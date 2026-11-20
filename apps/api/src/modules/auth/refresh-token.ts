import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Opaque refresh tokens (ADR-007 A8): 32 random bytes, base64url — 43 chars,
 * cookie-safe. Only the SHA-256 hash is ever stored; the token itself is never
 * persisted or logged. 256 bits of entropy needs no HMAC pepper.
 */

export const REFRESH_TOKEN_BYTES = 32;

/** base64url of 32 bytes, unpadded — always exactly 43 characters. */
const REFRESH_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function generateRefreshToken(): string {
  return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
}

/** Shape check before hashing or any DB work — malformed input costs nothing. */
export function isRefreshTokenShape(token: string): boolean {
  return REFRESH_TOKEN_PATTERN.test(token);
}

/** The at-rest value: SHA-256 of the token's UTF-8 text, 32 bytes. */
export function hashRefreshToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/**
 * Constant-time equality for stored hashes (A8/A9). Length is compared first
 * because timingSafeEqual throws on mismatched lengths; lengths of SHA-256
 * digests are public anyway.
 */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  // An empty "hash" can never be a valid digest; treating two empty buffers
  // as equal would make a missing value match another missing value.
  return a.length !== 0 && a.length === b.length && timingSafeEqual(a, b);
}
