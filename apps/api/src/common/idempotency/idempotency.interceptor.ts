import {
  Inject,
  Injectable,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { PATH_METADATA } from '@nestjs/common/constants.js';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';
import { from, lastValueFrom, type Observable } from 'rxjs';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../../common/errors/domain-error.js';
import { sqlStateOf } from '../../common/errors/sql-state.js';
import { deriveSuccessStatus } from '../../common/http/success-status.js';
import {
  IDEMPOTENCY_KEY_PATTERN,
  IDEMPOTENT_METHODS,
  IDEMPOTENCY_ROUTE_PATTERN,
  IDEMPOTENT_KEY,
  MAX_STORED_RESPONSE_BYTES,
  RESPONSE_ENC_COLUMN,
} from '../../common/idempotency/idempotency.constants.js';
import { fingerprintOf } from '../../common/idempotency/fingerprint.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits IdempotencyStore as the constructor param type for DI
import { IdempotencyStore, type IdempotencyScope } from '../../db/idempotency-store.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from '../../db/tenant-db.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PiiService as the constructor param type for DI
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
import { readAuthzContext } from '../../security/authz/access-scope.js';
import { canonicalRoutePath, normalizeRoutePaths } from '../../security/authz/route-scan.js';

/**
 * Idempotent mutating routes (ADR-010 L8/L9/L11, F1-06 T07).
 *
 * One transaction owns the whole request: claim (`INSERT … ON CONFLICT DO
 * NOTHING`), the handler (its repositories reuse the transaction), and the
 * `completed` row with the encrypted response. Therefore:
 *  - replay returns the stored status/body and runs nothing (`Idempotent-Replayed: true`);
 *  - a different payload on the same key is `422 IDEMPOTENCY_KEY_REUSED`;
 *  - a concurrent duplicate waits on the unique key: replayed if the first
 *    committed, `409 IDEMPOTENCY_IN_PROGRESS` (+ `Retry-After: 1`) when the
 *    lock wait (SQLSTATE 55P03) expires;
 *  - a handler error — business 4xx included — rolls everything back: no row,
 *    and a retry re-executes (only successful responses are stored);
 *  - the handler cap aborts the transaction (and `statement_timeout` stops the
 *    DB side); the JS handler itself is NOT cancellable, which is why a marked
 *    handler may only have effects inside the request transaction (no direct
 *    SMS/HTTP calls — an outbox enqueue in the same transaction is the pattern).
 *
 * The key is never logged. The fingerprint covers params + query + body only;
 * route and principal live in the scope key (owner CP4 change 4).
 */

interface IdempotentRequest extends Request {
  idempotencyReplay?: boolean;
}

const MAX_RESOLVE_ATTEMPTS = 3;

/**
 * Stored-body envelope (review LOW 8): `JSON.stringify(undefined)` is not a
 * string, so a void handler stored as `null` would replay `{data:null}` while
 * the original response was `{}`. A one-byte tag preserves the exact shape.
 */
const STORED_BODY_JSON = 'j';
const STORED_BODY_UNDEFINED = 'u';

@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly tenantContext: TenantContext,
    private readonly tenantDb: TenantDb,
    private readonly pii: PiiService,
    private readonly store: IdempotencyStore,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(IdempotencyInterceptor.name);
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const required = this.reflector.get<unknown>(IDEMPOTENT_KEY, context.getHandler()) === true;
    if (!required) {
      return next.handle();
    }
    return from(this.run(context, next));
  }

  private async run(context: ExecutionContext, next: CallHandler): Promise<unknown> {
    const request = context.switchToHttp().getRequest<IdempotentRequest>();
    const { principal } = readAuthzContext(request);
    const idemKey = idempotencyKeyOf(request);
    if (idemKey === null) {
      throw DomainError.idempotencyKeyRequired();
    }
    const method = typeof request.method === 'string' ? request.method.toUpperCase() : '';
    if (!(IDEMPOTENT_METHODS as readonly string[]).includes(method)) {
      // The boot scan rejects `@Idempotent()` on non-mutating routes; reaching
      // here is a programming bug, never something a client can trigger.
      throw DomainError.internal({ reason: 'idempotency_method' });
    }
    const routeKey = `${method} ${routeTemplateOf(context, request)}`;
    if (!IDEMPOTENCY_ROUTE_PATTERN.test(routeKey)) {
      throw DomainError.internal({ reason: 'idempotency_route_key' });
    }
    const scope: IdempotencyScope = {
      tenantId: principal.tenantId,
      userId: principal.userId,
      routeKey,
      idemKey,
    };
    const fingerprint = fingerprintOf({
      params: request.params,
      query: request.query,
      body: request.body,
    });
    const fullScope =
      principal.carrierId === undefined
        ? { tenantId: principal.tenantId }
        : { tenantId: principal.tenantId, carrierId: principal.carrierId };

    return this.tenantContext.run(fullScope, () =>
      this.tenantDb.run(async () => {
        await this.store.applyTimeouts(
          this.config.idempotency.lockTimeoutMs,
          this.config.idempotency.handlerTimeoutMs,
        );
        const claimId = uuidv7();
        let claimed: string | null;
        try {
          claimed = await this.store.claim(
            scope,
            claimId,
            fingerprint,
            this.config.idempotency.ttlHours,
          );
        } catch (error) {
          throw mapClaimError(error);
        }
        if (claimed !== null) {
          return this.execute(context, next, scope, claimId);
        }
        return this.resolveExisting(context, request, next, scope, fingerprint);
      }),
    );
  }

  /** The handler ran under the claim: store the successful response or roll back. */
  private async execute(
    context: ExecutionContext,
    next: CallHandler,
    scope: IdempotencyScope,
    claimId: string,
  ): Promise<unknown> {
    const result = await this.runWithCap(next, this.config.idempotency.handlerTimeoutMs);
    const serialized = serializeBody(result);
    if (serialized === null || Buffer.byteLength(serialized, 'utf8') > MAX_STORED_RESPONSE_BYTES) {
      // A programming error: the business change rolls back with the claim, so
      // a retry re-executes and fails the same way. Code-only log, no payload.
      this.logger.warn(
        { code: 'IDEMPOTENCY_RESPONSE_TOO_LARGE' },
        'idempotent response cannot be stored',
      );
      throw DomainError.internal({ reason: 'idempotency_response' });
    }
    const responseEnc = this.pii.encrypt(
      serialized,
      buildAad(scope.tenantId, RESPONSE_ENC_COLUMN, claimId),
    );
    try {
      await this.store.complete(scope, claimId, deriveSuccessStatus(context), responseEnc);
    } catch (error) {
      throw mapClaimError(error);
    }
    return result;
  }

  /**
   * The key already exists: replay, reject a different payload, or take over an
   * expired row exactly once. The conflicting INSERT already waited for the
   * other transaction, so a committed row is visible here.
   */
  private async resolveExisting(
    context: ExecutionContext,
    request: IdempotentRequest,
    next: CallHandler,
    scope: IdempotencyScope,
    fingerprint: Buffer,
  ): Promise<unknown> {
    for (let attempt = 0; attempt < MAX_RESOLVE_ATTEMPTS; attempt += 1) {
      let row;
      try {
        row = await this.store.find(scope);
      } catch (error) {
        throw mapClaimError(error);
      }
      if (row === null) {
        // The unique conflict named a row we cannot see: never answer success.
        throw DomainError.internal({ reason: 'idempotency_row_missing' });
      }
      if (row.expired) {
        let tookOver: boolean;
        try {
          tookOver = await this.store.takeOver(
            scope,
            row.id,
            fingerprint,
            this.config.idempotency.ttlHours,
          );
        } catch (error) {
          throw mapClaimError(error);
        }
        if (tookOver) {
          return this.execute(context, next, scope, row.id);
        }
        // Another request won the CAS; read the row again.
        continue;
      }
      if (!row.fingerprint.equals(fingerprint)) {
        throw DomainError.idempotencyKeyReused();
      }
      if (row.status !== 'completed' || row.responseEnc === null || row.responseStatus === null) {
        throw DomainError.idempotencyInProgress();
      }
      return this.replay(context, request, row, scope.tenantId);
    }
    throw DomainError.idempotencyInProgress();
  }

  private replay(
    context: ExecutionContext,
    request: IdempotentRequest,
    row: {
      readonly id: string;
      readonly responseStatus: number | null;
      readonly responseEnc: Buffer | null;
    },
    tenantId: string,
  ): unknown {
    if (row.responseEnc === null || row.responseStatus === null) {
      throw DomainError.internal({ reason: 'idempotency_replay_fields' });
    }
    let body: string;
    try {
      body = this.pii.decrypt(row.responseEnc, buildAad(tenantId, RESPONSE_ENC_COLUMN, row.id));
    } catch {
      throw DomainError.internal({ reason: 'idempotency_replay_decrypt' });
    }
    let parsed: unknown;
    try {
      parsed = deserializeBody(body);
    } catch {
      throw DomainError.internal({ reason: 'idempotency_replay_json' });
    }
    const response = context.switchToHttp().getResponse<Response>();
    response.status(row.responseStatus);
    response.setHeader('Idempotent-Replayed', 'true');
    // A replay is not a mutation: the sensitive-audit interceptor must not
    // write a second success row (ADR-010 L11).
    request.idempotencyReplay = true;
    return parsed;
  }

  /**
   * Runs the handler under the cap. `Promise.race` does not cancel the handler,
   * so the transaction (and `statement_timeout`) is the real bound; a marked
   * handler must keep its effects inside that transaction.
   */
  private async runWithCap(next: CallHandler, timeoutMs: number): Promise<unknown> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const capped = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(DomainError.idempotencyTimeout()), timeoutMs);
    });
    const handled = lastValueFrom(next.handle());
    // If the cap wins, the handler's own promise settles later; its rejection
    // must not become an unhandled rejection.
    handled.catch(() => undefined);
    try {
      return await Promise.race([handled, capped]);
    } catch (error) {
      // Aligned statement_timeout: a DB statement killed at the cap is the
      // same outcome as a JS timeout, never a raw 500.
      if (sqlStateOf(error) === '57014') {
        throw DomainError.idempotencyTimeout();
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

function idempotencyKeyOf(request: Request): string | null {
  const raw = request.headers['idempotency-key'];
  if (typeof raw !== 'string' || !IDEMPOTENCY_KEY_PATTERN.test(raw)) {
    return null;
  }
  return raw;
}

/**
 * `METHOD` + canonical route template from Nest metadata, never the raw URL.
 * A handler mounted on an array path registers several routes sharing this
 * handler; the request's own path picks the candidate, so `/b` can never
 * replay `/a`'s row (review LOW 10).
 */
function routeTemplateOf(context: ExecutionContext, request: Request): string {
  const controllerPaths = normalizeRoutePaths(
    Reflect.getMetadata(PATH_METADATA, context.getClass()),
  );
  const handlerPaths = normalizeRoutePaths(
    Reflect.getMetadata(PATH_METADATA, context.getHandler()),
  );
  const candidates = controllerPaths.flatMap((controllerPath) =>
    handlerPaths.map((handlerPath) => canonicalRoutePath(controllerPath, handlerPath)),
  );
  if (candidates.length === 0) {
    return '';
  }
  const actual = typeof request.path === 'string' ? request.path.replace(/\/+$/, '') || '/' : '';
  return candidates.find((candidate) => candidate === actual) ?? candidates[0] ?? '';
}

function serializeBody(value: unknown): string | null {
  if (value === undefined) {
    return STORED_BODY_UNDEFINED;
  }
  try {
    const json = JSON.stringify(value);
    return typeof json === 'string' ? `${STORED_BODY_JSON}${json}` : null;
  } catch {
    return null;
  }
}

function deserializeBody(stored: string): unknown {
  if (stored === STORED_BODY_UNDEFINED) {
    return undefined;
  }
  if (!stored.startsWith(STORED_BODY_JSON)) {
    throw new Error('IDEMPOTENCY_STORED_BODY_INVALID');
  }
  return JSON.parse(stored.slice(STORED_BODY_JSON.length)) as unknown;
}

/** 55P03 (lock_timeout) is a concurrent duplicate, not a server error. */
function mapClaimError(error: unknown): unknown {
  switch (sqlStateOf(error)) {
    case '55P03':
      return DomainError.idempotencyInProgress();
    case '57014':
      return DomainError.idempotencyTimeout();
    default:
      return error;
  }
}
