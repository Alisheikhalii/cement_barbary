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
import { catchError, concatMap, from, mergeMap, throwError, type Observable } from 'rxjs';

import { readAuthzContext } from './access-scope.js';
import { AUDIT_HOOK, type AuditHook, type AuditOutcome, type AuditRecord } from './audit-hook.js';
import { BODY_SCHEMA_KEY, REQUIRE_PERMISSION_KEY } from './decorators.js';
import { isSensitivePermission } from './permissions.js';

interface AuditedRequest extends Request {
  body: unknown;
}

interface SafeParseSchema {
  safeParse(value: unknown): { readonly success: boolean; readonly data?: unknown };
}

/**
 * Sensitive-action audit (ADR-008 Z10, CP1 SA-02/SA-03, F1-05 T06).
 *
 * Runs around every route whose permission is catalog-sensitive. After the
 * handler settles it calls AuditHook exactly once:
 *  - success: after the handler returned;
 *  - failure: after a pipe or handler error, before the original error is
 *    rethrown (the response is unchanged).
 *
 * The reason is parsed from the request body with the exact schema recorded by
 * `@ZodBody`; it is never taken from a header/query/param and never logged
 * here. Guard denials happen BEFORE interceptors and are handled by the guard's
 * reason-code log, not by this hook.
 */

@Injectable()
export class SensitiveAuditInterceptor implements NestInterceptor {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(AUDIT_HOOK) private readonly hook: AuditHook,
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
    // Exactly one record per request, even if a handler returns a stream that
    // emits more than once or emits before failing.
    let recorded = false;
    const recordOnce = async (outcome: AuditOutcome): Promise<void> => {
      if (recorded) {
        return;
      }
      recorded = true;
      await this.recordSafely(context, request, permission, outcome);
    };

    return next.handle().pipe(
      concatMap(async (value: unknown) => {
        await recordOnce('success');
        return value;
      }),
      catchError((error: unknown) =>
        from(recordOnce('failure')).pipe(mergeMap(() => throwError(() => error))),
      ),
    );
  }

  /**
   * The hook is observational: a failing hook must not change the HTTP result.
   * The catch logs only the request id, outcome and error class — never the
   * permission name, the actor or the reason text.
   */
  private async recordSafely(
    context: ExecutionContext,
    request: AuditedRequest,
    action: string,
    outcome: AuditOutcome,
  ): Promise<void> {
    try {
      const { principal } = readAuthzContext(request);
      const record: AuditRecord = {
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
        outcome,
      };
      await this.hook.record(record);
    } catch (error) {
      this.logger.warn(
        {
          reqId: request.id ?? null,
          outcome,
          errorName: error instanceof Error ? error.name : 'Unknown',
        },
        'audit hook failed',
      );
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

function isSafeParseSchema(value: unknown): value is SafeParseSchema {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { safeParse?: unknown }).safeParse === 'function'
  );
}
