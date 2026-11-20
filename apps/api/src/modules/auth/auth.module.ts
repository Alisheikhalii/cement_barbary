import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

import { PiiModule } from '../../security/pii/pii.module.js';
import { AuthController } from './auth.controller.js';
import { AuthGuard } from './auth.guard.js';
import { AuthRepository } from './auth.repository.js';
import { AuthService } from './auth.service.js';
import { CsrfGuard } from './csrf.guard.js';
import { DbRateLimiter } from './db-rate-limiter.js';
import { PasswordMethod } from './password-method.js';
import { PasswordService } from './password.service.js';
import { RATE_LIMITER } from './rate-limiter.js';
import { SessionRepository } from './session.repository.js';
import { SessionService } from './session.service.js';
import { TenantDirectory } from './tenant-directory.js';
import { TokenService } from './token.service.js';

/**
 * F1-04 auth module (T06/T07). The global AuthGuard makes authentication deny
 * by default; @Public() declares the exceptions. No RBAC (F1-05), no audit
 * (F1-06), no OTP (§J). DatabaseModule (TenantDb/TenantContext/AuthLookup) and
 * ConfigModule are global; PiiModule supplies the blind-index HMAC.
 */
@Module({
  imports: [PiiModule],
  controllers: [AuthController],
  providers: [
    PasswordService,
    TokenService,
    SessionRepository,
    SessionService,
    AuthRepository,
    TenantDirectory,
    PasswordMethod,
    AuthService,
    CsrfGuard,
    { provide: RATE_LIMITER, useClass: DbRateLimiter },
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
  exports: [AuthService, TokenService],
})
export class AuthModule {}
