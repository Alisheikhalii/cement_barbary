import type { ExecutionContext } from '@nestjs/common';

/**
 * The status Nest will actually send for a successful handler (ADR-009 L6).
 * At interceptor time Nest has not applied `@HttpCode`/the POST default yet,
 * so those are derived the same way the Express adapter does; a handler that
 * used `@Res()` already sent headers and its own status wins.
 *
 * Shared by the sensitive-audit and idempotency interceptors so both record the
 * same final status (and the stored replay status equals the original).
 */
export function deriveSuccessStatus(context: ExecutionContext): number {
  const response = context
    .switchToHttp()
    .getResponse<{ readonly headersSent?: boolean; readonly statusCode?: number }>();
  if (response.headersSent === true && typeof response.statusCode === 'number') {
    return response.statusCode;
  }
  const explicit: unknown = Reflect.getMetadata('__httpCode__', context.getHandler());
  if (typeof explicit === 'number') {
    return explicit;
  }
  const method = context.switchToHttp().getRequest<{ method?: string }>().method;
  return method === 'POST' ? 201 : 200;
}
