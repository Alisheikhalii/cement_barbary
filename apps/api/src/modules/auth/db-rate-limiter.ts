import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';

import { RateLimitStore } from '../../db/rate-limit-store.js';
import { type RateLimiter, type RateLimitVerdict } from './rate-limiter.js';

/** How often expired windows are swept (A11: lazy expiry + hourly cleanup). */
export const RATE_LIMIT_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Postgres implementation of RateLimiter (ADR-007 A11, owner Q2). A Redis
 * implementation can replace it without changing callers. The sweep timer is
 * unref'd so it never keeps the process alive, and a failed sweep is ignored
 * (the table self-heals lazily on the next hit).
 */
@Injectable()
export class DbRateLimiter implements RateLimiter, OnModuleInit, OnModuleDestroy {
  private timer: NodeJS.Timeout | undefined;

  constructor(@Inject(RateLimitStore) private readonly store: RateLimitStore) {}

  async hit(key: string, limit: number, windowSeconds: number): Promise<RateLimitVerdict> {
    const hit = await this.store.hit(key, windowSeconds);
    if (hit.count <= limit) {
      return { allowed: true };
    }
    const remainingMs = hit.expiresAt.getTime() - Date.now();
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)) };
  }

  onModuleInit(): void {
    this.timer = setInterval(() => {
      void this.store.sweep().catch(() => undefined);
    }, RATE_LIMIT_SWEEP_INTERVAL_MS);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
    }
  }

  /** Exposed for the test that proves expired buckets are removed. */
  sweep(): Promise<number> {
    return this.store.sweep();
  }
}
