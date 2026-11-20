/**
 * Rate limiting behind an interface (ADR-007 A11, owner Q2). The Postgres
 * `auth_rate_limits` implementation lands in T06; a Redis implementation can
 * replace it later without touching callers. The per-account progressive
 * delay (A2) is NOT here — it lives on `user_credentials` (T03/T06).
 */

export interface RateLimitVerdict {
  readonly allowed: boolean;
  /** Seconds until the current window closes; set when denied (for Retry-After). */
  readonly retryAfterSeconds?: number;
}

export interface RateLimiter {
  /**
   * Atomically increment `key` inside a fixed window of `windowSeconds` and
   * judge it against `limit`. Implementations must be atomic under
   * concurrency (the Postgres impl uses a single upsert). Keys are namespaced
   * by the caller via `rateLimitKeys` so shapes cannot drift.
   */
  hit(key: string, limit: number, windowSeconds: number): Promise<RateLimitVerdict>;
}

/** Window length behind the `AUTH_RL_LOGIN_*_PER_MIN` config numbers. */
export const LOGIN_WINDOW_SECONDS = 60;

/** Single place for key shapes — callers never hand-roll keys. */
export const rateLimitKeys = {
  loginIp: (ip: string): string => `login:ip:${ip}`,
  loginTenant: (tenantCode: string): string => `login:tenant:${tenantCode}`,
} as const;
