import { createHmac } from 'node:crypto';

/**
 * Rate limiting behind an interface (ADR-007 A11). The Postgres
 * `auth_rate_limits` implementation lives in db-rate-limiter.ts; a Redis
 * implementation can replace it later without touching callers. The
 * per-account progressive delay (A2) is NOT here — it lives on
 * `user_credentials`.
 *
 * Key hygiene (owner T06): keys never embed a raw phone number, username or
 * tenant code. Identifiers are HMAC-SHA256'd with a domain-separated input of
 * PII_HMAC_KEY first, so the persisted row cannot be used to re-identify an
 * account. The only raw value is the client IP (a counter dimension, not an
 * account identifier).
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
   * by the caller via `rateLimitKeys()` so shapes cannot drift.
   */
  hit(key: string, limit: number, windowSeconds: number): Promise<RateLimitVerdict>;
}

/** Injection token for the RateLimiter implementation. */
export const RATE_LIMITER = Symbol('RATE_LIMITER');

/** Window length behind the `AUTH_RL_LOGIN_*_PER_MIN` config numbers. */
export const LOGIN_WINDOW_SECONDS = 60;

/** Every key this module can produce, for the shape test. */
export const RATE_LIMIT_KEY_PATTERNS = {
  loginIp: /^login:ip:[0-9a-fA-F.:]+$/,
  loginAccount: /^login:acct:[A-Za-z0-9_-]{43}$/,
  loginTenant: /^login:tenant:[A-Za-z0-9_-]{43}$/,
} as const;

/**
 * HMAC of an identifier with domain separation (`ratelimit:v1:`). The HMAC key
 * is the existing PII_HMAC_KEY — a separate per-purpose key is a future option,
 * but domain-separated use keeps one secret from being useful across purposes.
 */
export function hashRateLimitIdentifier(secret: Buffer, value: string): string {
  return createHmac('sha256', secret).update(`ratelimit:v1:${value}`).digest('base64url');
}

/**
 * Single place for key shapes — callers never hand-roll keys. Account and
 * tenant values are hashed here, so a caller cannot accidentally put raw
 * identifiers in a key.
 */
export function rateLimitKeys(secret: Buffer) {
  return {
    /** Per client IP. Not an account identifier. */
    loginIp: (ip: string): string => `login:ip:${ip}`,
    /** Per login identifier: `staff:<tenant-code>:<username>` or `driver:<phone>`. */
    loginAccount: (identity: string): string =>
      `login:acct:${hashRateLimitIdentifier(secret, identity)}`,
    /** Per tenant code (staff logins only). */
    loginTenant: (tenantCode: string): string =>
      `login:tenant:${hashRateLimitIdentifier(secret, `tenant:${tenantCode}`)}`,
  };
}

export type RateLimitKeys = ReturnType<typeof rateLimitKeys>;
