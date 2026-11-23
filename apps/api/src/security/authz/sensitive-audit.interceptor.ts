import {
  Inject,
  Injectable,
  type CallHandler,
  type ExecutionContext,
  type NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';
import { from, lastValueFrom, type Observable } from 'rxjs';

import { deriveSuccessStatus } from '../../common/http/success-status.js';
import { runWithAuditChanges } from '../../modules/audit/audit-context.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from '../../db/tenant-db.js';
import { readAuthzContext } from './access-scope.js';
import { AUDIT_HOOK, type AuditHook, type AuditRecord } from './audit-hook.js';
import { BODY_SCHEMA_KEY, REQUIRE_PERMISSION_KEY } from './decorators.js';
import { isSensitivePermission } from './permissions.js';

interface AuditedRequest extends Request {
  body: unknown;
  /**
   * Set by the idempotency interceptor when a stored response is replayed
   * (ADR-010 L11): a replay is not a second mutation, so it must not write a
   * second success audit row. Harmless when the idempotency interceptor is not
   * active or is outer to this one (then this code never sees a replay).
   */
  idempotencyReplay?: boolean;
}

interface SafeParseSchema {
  safeParse(value: unknown): { readonly success: boolean; readonly data?: unknown };
}

/**
 * Sensitive-action audit (ADR-008 Z10, ADR-009 L1b/L6, F1-05 T06, F1-06 T05).
 *
 * Runs around every route whose permission is catalog-sensitive and calls
 * AuditHook exactly once:
 *  - success: the handler executes INSIDE an outer tenant transaction; the
 *    persistent hook appends the audit row in that same transaction, so a
 *    committed sensitive change always has its audit row (fail-closed).
 *  - failure: after the transaction rolled back, the hook writes a best-effort
 *    `failure` row in a fresh transaction and the original error is rethrown
 *    (the response is unchanged).
 *
 * `auditChange()` calls made by the handler are collected and stored as the
 * before/after snapshots. The reason is parsed from the request body with the
 * exact schema recorded by `@ZodBody`; it is never taken from a header/query/
 * param and never logged here. Guard denials happen BEFORE interceptors and are
 * audited by the guard itself (L6).
 */

@Injectable()
export class SensitiveAuditInterceptor implements NestInterceptor {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(AUDIT_HOOK) private readonly hook: AuditHook,
    private readonly tenantContext: TenantContext,
    private readonly tenantDb: TenantDb,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(SensitiveAuditInterceptor.name);
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const handler = context.getHandler();
    const permission = this.reflector.get<unknown>(REQUIRE_PERMISSION_KEY, handler);
    if (typeof permission !== 'string' || !isSensitivePermission(permission)) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest<AuditedRequest>();
    return from(this.runAudited(context, request, permission, next));
  }

  private async runAudited(
    context: ExecutionContext,
    request: AuditedRequest,
    action: string,
    next: CallHandler,
  ): Promise<unknown> {
    const { principal } = readAuthzContext(request);
    const base: Omit<AuditRecord, 'outcome'> = {
      actor: {
        userId: principal.userId,
        tenantId: principal.tenantId,
        sessionId: principal.sessionId,
      },
      action,
      resource: {
        type: 'handler',
        id: `${context.getClass().name}.${context.getHandler().name}`,
      },
      reason: this.reasonFor(context.getHandler(), request.body),
      requestId: requestIdOf(request),
      ip: clientIp(request),
      ...(principal.carrierId === undefined ? {} : { carrierId: principal.carrierId }),
    };

    try {
      // The full scope, not just the tenant: a carrier-scoped handler's own
      // `TenantContext.run` must match this inner scope (F1-08).
      const scope =
        principal.carrierId === undefined
          ? { tenantId: principal.tenantId }
          : { tenantId: principal.tenantId, carrierId: principal.carrierId };
      return await this.tenantContext.run(scope, () =>
        this.tenantDb.run(async () => {
          const { result, changes } = await runWithAuditChanges(() => lastValueFrom(next.handle()));
          if (request.idempotencyReplay === true) {
            // The idempotency interceptor answered from its stored row and the
            // handler never ran; the original request already wrote the row.
            return result;
          }
          const record: AuditRecord = {
            ...base,
            outcome: 'success',
            httpStatus: deriveSuccessStatus(context),
            ...(changes.length > 0 ? { changes } : {}),
          };
          // Same transaction as the handler: if this insert fails, the change
          // does not commit either.
          await this.hook.record(record);
          return result;
        }),
      );
    } catch (error) {
      // The handler's transaction is already rolled back. Failure rows are
      // best-effort (ADR-009 C3); the hook swallows their errors and never
      // changes the response. A failure of the SUCCESS write lands here too:
      // the hook propagated it so this transaction rolled back (fail-closed).
      await this.hook.record({
        ...base,
        outcome: 'failure',
        httpStatus: failureStatus(error),
      });
      throw error;
    }
  }

  /**
   * Reuses the recorded `@ZodBody` schema instead of trusting the raw body.
   * `null` means the body never validated (e.g. the pipe rejected it) or the
   * schema is not the reviewed shape — the hook still records the outcome.
   */
  private reasonFor(handler: Parameters<Reflector['get']>[1], body: unknown): string | null {
    const schema: unknown = this.reflector.get<unknown>(BODY_SCHEMA_KEY, handler);
    if (!isSafeParseSchema(schema)) {
      return null;
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success || typeof parsed.data !== 'object' || parsed.data === null) {
      return null;
    }
    const reason = (parsed.data as { reason?: unknown }).reason;
    return typeof reason === 'string' ? reason : null;
  }
}

/**
 * The status Nest will actually send is derived by `deriveSuccessStatus`
 * (common/http), shared with the idempotency interceptor so a stored replay
 * carries the same status as the original.
 */

function failureStatus(error: unknown): number {
  if (typeof error === 'object' && error !== null) {
    const candidate = error as { statusCode?: unknown; status?: unknown };
    for (const value of [candidate.statusCode, candidate.status]) {
      if (typeof value === 'number' && value >= 400 && value <= 599) {
        return value;
      }
    }
  }
  return 500;
}

/** pino's request id is `string | number`; only a string column can hold it. */
function requestIdOf(request: Request): string | null {
  const id: unknown = request.id;
  if (typeof id === 'string' && id.length > 0) {
    return id;
  }
  return typeof id === 'number' ? String(id) : null;
}

/** Bounded raw client IP; anything longer than an address is dropped. */
function clientIp(request: Request): string | null {
  const ip = request.ip;
  return typeof ip === 'string' && ip.length > 0 && ip.length <= 64 ? ip : null;
}

function isSafeParseSchema(value: unknown): value is SafeParseSchema {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { safeParse?: unknown }).safeParse === 'function'
  );
}
