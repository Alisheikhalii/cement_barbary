import { Body, Controller, Get, HttpCode, Inject, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { Public } from '../../common/auth/public.decorator.js';
import { DomainError } from '../../common/errors/domain-error.js';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import {
  changePasswordInputSchema,
  loginInputSchema,
  type ChangePasswordInput,
  type LoginInput,
} from './auth.dto.js';
import type { AuthedRequest } from './auth.guard.js';
import { AuthService, type MeResult, type SessionTokens } from './auth.service.js';
import {
  clearRefreshCookie,
  parseRefreshCookie,
  refreshCookieMaxAgeSeconds,
  serializeRefreshCookie,
} from './cookie.js';
import { CsrfGuard } from './csrf.guard.js';
import type { SessionClientMeta } from './session.service.js';

/**
 * Auth endpoints (ADR-007 A15, T07): login, refresh, logout, password change
 * and me. Access tokens travel in the JSON body; the refresh token exists ONLY
 * in the HttpOnly cookie. Login/logout/refresh/password-change are public to
 * the global guard because they authenticate themselves (password, cookie +
 * CSRF, or a change token); /auth/me is guarded. No RBAC yet (F1-05).
 */
@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AuthService) private readonly auth: AuthService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Log in with username@tenant-code or a phone number' })
  async login(
    @Body(new ZodValidationPipe(loginInputSchema)) body: LoginInput,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionTokens | { changeToken: string; expiresIn: number }> {
    // Login-CSRF guard: a cross-site HTML form can only post urlencoded/multipart
    // bodies, while JSON from another origin needs a preflighted CORS grant.
    // Requiring JSON therefore blocks form-based login CSRF (review LOW 3).
    if (!request.is('application/json')) {
      throw DomainError.badInput();
    }
    const result = await this.auth.login(body, this.meta(request));
    if (result.kind === 'change') {
      // A19: no session and no cookie until the password is changed.
      return { changeToken: result.changeToken, expiresIn: result.expiresIn };
    }
    this.setRefreshCookie(response, result.refreshToken, result.refreshExpiresAt);
    return result.tokens;
  }

  @Public()
  @UseGuards(CsrfGuard)
  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: 'Rotate the refresh cookie and issue a new access token' })
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionTokens> {
    const result = await this.auth.refresh(
      parseRefreshCookie(request.headers.cookie),
      this.meta(request),
    );
    this.setRefreshCookie(response, result.refreshToken, result.refreshExpiresAt);
    return result.tokens;
  }

  @Public()
  @UseGuards(CsrfGuard)
  @Post('logout')
  @HttpCode(200)
  @ApiOperation({ summary: 'Revoke the session and clear the refresh cookie' })
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<{ loggedOut: true }> {
    await this.auth.logout(parseRefreshCookie(request.headers.cookie));
    response.setHeader('Set-Cookie', clearRefreshCookie({ secure: this.secureCookies() }));
    return { loggedOut: true };
  }

  @Public()
  @Post('password/change')
  @HttpCode(200)
  @ApiOperation({ summary: 'Change the password with a change token or an access token' })
  async changePassword(
    @Body(new ZodValidationPipe(changePasswordInputSchema)) body: ChangePasswordInput,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<SessionTokens> {
    const result = await this.auth.changePassword(
      body,
      request.headers.authorization,
      this.meta(request),
    );
    this.setRefreshCookie(response, result.refreshToken, result.refreshExpiresAt);
    return result.tokens;
  }

  @Get('me')
  @ApiOperation({ summary: 'The authenticated identity from the access token' })
  me(@Req() request: AuthedRequest): MeResult {
    if (request.auth === undefined) {
      // The global guard runs before this handler; this is defense in depth.
      throw DomainError.unauthorized();
    }
    return this.auth.me(request.auth);
  }

  private meta(request: Request): SessionClientMeta {
    const userAgent = request.headers['user-agent'];
    return {
      ip: request.ip ?? null,
      // AGENT.md §7: the column is varchar(512); truncate at the HTTP boundary.
      userAgent:
        typeof userAgent === 'string' && userAgent.length > 0 ? userAgent.slice(0, 512) : null,
    };
  }

  private secureCookies(): boolean {
    // A8: Secure everywhere except local development over plain http.
    return this.config.nodeEnv === 'production';
  }

  private setRefreshCookie(response: Response, token: string, expiresAt: Date): void {
    response.setHeader(
      'Set-Cookie',
      serializeRefreshCookie(token, {
        secure: this.secureCookies(),
        // A8: remaining lifetime, never a fresh 30 days on rotation.
        maxAgeSeconds: refreshCookieMaxAgeSeconds(expiresAt),
      }),
    );
  }
}
