import { randomUUID } from 'node:crypto';

import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { LoggerModule } from 'nestjs-pino';

import { GlobalExceptionFilter } from './common/filters/http-exception.filter.js';
import { IdempotencyModule } from './common/idempotency/idempotency.module.js';
import { TransformInterceptor } from './common/interceptors/transform.interceptor.js';
import { ConfigModule } from './config/config.module.js';
import { DatabaseModule } from './db/database.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { BaseDataModule } from './modules/base-data/base-data.module.js';
import { HealthModule } from './modules/health/health.module.js';
import { OutboxModule } from './modules/outbox/outbox.module.js';
import { UsersModule } from './modules/users/users.module.js';
import { PiiModule } from './security/pii/pii.module.js';
import { redactPiiLogObject } from './security/pii/log-redact.js';
import { AuthzModule } from './security/authz/authz.module.js';

@Module({
  imports: [
    ConfigModule,
    DatabaseModule,
    // Structured JSON logs with a request id per request (GUIDELINES §10).
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.NODE_ENV === 'test' ? 'silent' : 'info',
        genReqId: () => randomUUID(),
        // Never log credentials (GUIDELINES §6.3) or personal data (ADR-006 U11:
        // the formatter hides phone / national id / *_enc / *_hash at any depth).
        redact: {
          // `reason` is also handled structurally by redactPiiLogObject; these
          // paths cover child-logger bindings, which bypass formatters.log.
          // The idempotency key is an opaque replay credential (ADR-010 L9):
          // it must never reach an access log (F1-06 T07 review HIGH).
          paths: [
            'req.headers.authorization',
            'req.headers.cookie',
            'req.headers["idempotency-key"]',
            'reason',
            '*.reason',
          ],
          censor: '[redacted]',
        },
        formatters: { log: redactPiiLogObject },
      },
    }),
    HealthModule,
    PiiModule,
    UsersModule,
    AuthModule,
    // Must stay AFTER AuthModule: AuthGuard answers 401 before AuthorizationGuard
    // decides 403 (ADR-008 Z4). The order is locked by a test.
    AuthzModule,
    // AFTER AuthzModule: its transaction is outer to (or flagged through) the
    // sensitive audit so a failed handler still gets its best-effort row.
    IdempotencyModule,
    // Producer for every external side effect; the poller/mock are flag-gated
    // and refused in production.
    OutboxModule,
    // F1-07 base data: first real business endpoints (guarded, audited). Kept
    // after the security modules so the discovery order matches the matrix
    // script's controller list (Health → Auth → Destinations → Halls).
    BaseDataModule,
  ],
  providers: [
    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
    { provide: APP_INTERCEPTOR, useClass: TransformInterceptor },
  ],
})
export class AppModule {}
