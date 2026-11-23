import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';

import { IdempotencyStore } from '../../db/idempotency-store.js';
import { PiiModule } from '../../security/pii/pii.module.js';
import { IdempotencyInterceptor } from './idempotency.interceptor.js';

/**
 * Global idempotency interceptor (ADR-010 L8–L11, F1-06 T07).
 *
 * Imported AFTER AuthzModule so the sensitive-audit interceptor is outer: a
 * handler failure still rolls the claim back before the best-effort failure
 * audit row is written in a fresh transaction, and a replay is flagged so the
 * audit interceptor writes no second row. No controller of its own.
 */
@Module({
  imports: [PiiModule],
  providers: [
    IdempotencyStore,
    IdempotencyInterceptor,
    { provide: APP_INTERCEPTOR, useExisting: IdempotencyInterceptor },
  ],
  exports: [IdempotencyStore, IdempotencyInterceptor],
})
export class IdempotencyModule {}
