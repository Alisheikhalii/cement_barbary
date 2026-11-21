import { SetMetadata } from '@nestjs/common';

/**
 * Deny by default (T07): the global AuthGuard protects every route, and only
 * handlers explicitly marked @Public() are reachable without a bearer access
 * token. Public cookie endpoints still validate their own CSRF and credentials.
 *
 * ADR-008 Z3: access markers are handler-level only. The type intentionally
 * rejects class-level use; the boot scan and route-scan test reject it at
 * runtime as well.
 */
export const IS_PUBLIC_KEY = 'isPublic';

export const Public = (): MethodDecorator => SetMetadata(IS_PUBLIC_KEY, true);
