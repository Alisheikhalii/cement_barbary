import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';

import { IS_PUBLIC_KEY } from '../../common/auth/public.decorator.js';
import { DomainError } from '../../common/errors/domain-error.js';
import { bearerToken } from './bearer.js';
import { TokenService, type AccessTokenClaims } from './token.service.js';

/** Express request after the guard ran on a protected route. */
export interface AuthedRequest extends Request {
  auth?: AccessTokenClaims;
}

/**
 * Global authentication guard (T07): deny by default, @Public() opts out.
 * Authentication only — permissions are F1-05. Any missing/invalid/expired/
 * wrong-audience token is the same generic 401.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(TokenService) private readonly tokens: TokenService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // ADR-008 Z3: access markers are handler-level only. `get` (not
    // getAllAndOverride) means a class-level @Public() cannot widen the
    // authentication surface; the authorization guard rejects it too.
    const isPublic = this.reflector.get<boolean>(IS_PUBLIC_KEY, context.getHandler());
    if (isPublic === true) {
      return true;
    }
    const request = context.switchToHttp().getRequest<AuthedRequest>();
    const token = bearerToken(request.headers.authorization);
    if (token === null) {
      throw DomainError.unauthorized();
    }
    try {
      request.auth = await this.tokens.verifyAccessToken(token);
      return true;
    } catch {
      throw DomainError.unauthorized();
    }
  }
}
