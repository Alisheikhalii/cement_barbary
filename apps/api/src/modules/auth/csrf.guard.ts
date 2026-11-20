import {
  ForbiddenException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';

/** Required on every cookie endpoint; a cross-origin page cannot set it without CORS approval. */
export const CSRF_HEADER = 'x-bitabar-csrf';
export const CSRF_HEADER_VALUE = '1';

/**
 * CSRF defence for the cookie endpoints (ADR-007 A12, GUIDELINES §6.3):
 *  1. a custom header (`X-Bitabar-CSRF: 1`) must be present — forms and
 *     cross-origin fetches cannot add it without a preflighted CORS grant;
 *  2. when the browser sends Origin, it must be in the configured allowlist;
 *  3. with no Origin, a present Sec-Fetch-Site must be `same-origin`.
 * The guard runs BEFORE the handler, so with and without a valid cookie the
 * answer is the same 403 — a rejected request never becomes a cookie oracle.
 * Rejections use 403 (never 401) and set no cookie.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    if (request.headers[CSRF_HEADER] !== CSRF_HEADER_VALUE) {
      throw new ForbiddenException();
    }
    const origin = request.headers.origin;
    if (origin !== undefined) {
      if (!this.config.corsOrigins.includes(origin)) {
        throw new ForbiddenException();
      }
    } else {
      const site = request.headers['sec-fetch-site'];
      if (site !== undefined && site !== 'same-origin') {
        throw new ForbiddenException();
      }
    }
    return true;
  }
}
