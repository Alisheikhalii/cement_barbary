import { SetMetadata } from '@nestjs/common';

/**
 * Deny by default (T07): the global AuthGuard protects every route, and only
 * handlers/controllers explicitly marked @Public() are reachable without a
 * bearer access token. Public cookie endpoints still validate their own CSRF
 * and credentials.
 */
export const IS_PUBLIC_KEY = 'isPublic';

export const Public = (): MethodDecorator & ClassDecorator => SetMetadata(IS_PUBLIC_KEY, true);
