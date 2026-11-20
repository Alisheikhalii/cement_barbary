import { API_PREFIX } from '@bitabar/shared';

import { isRefreshTokenShape } from './refresh-token.js';

/**
 * Refresh-cookie helpers (ADR-007 A8/A12, GUIDELINES §6.1). The value is an
 * opaque base64url token; the cookie is never readable by JavaScript and is
 * scoped to the auth endpoints. `SameSite=Lax` is deliberate (owner condition
 * 5): it already withholds the cookie from cross-site POSTs, and the cookie
 * endpoints are POST-only; Strict is re-evaluated when the SPA ships.
 */

export const REFRESH_COOKIE_NAME = 'bitabar_refresh';
/**
 * Scoped to the auth endpoints under the global API prefix (only /health is
 * outside it). A path that does not match the mounted routes would make the
 * browser withhold the cookie from refresh/logout.
 */
export const REFRESH_COOKIE_PATH = `${API_PREFIX}/auth`;
/** A8: the refresh token (and its session) lives 30 days. */
export const REFRESH_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

export interface RefreshCookieOptions {
  /**
   * True everywhere except local development over plain http (A8). Passed
   * explicitly by the caller so this module never reads env or NODE_ENV.
   */
  readonly secure: boolean;
  readonly maxAgeSeconds?: number;
}

/**
 * `Set-Cookie` value that plants the refresh token. Rejects anything that is
 * not a well-formed token: the value is interpolated into a header, so a `;`
 * or CRLF could otherwise inject attributes.
 */
export function serializeRefreshCookie(token: string, options: RefreshCookieOptions): string {
  if (!isRefreshTokenShape(token)) {
    throw new Error('refusing to serialize a malformed refresh token');
  }
  const maxAge = options.maxAgeSeconds ?? REFRESH_COOKIE_MAX_AGE_SECONDS;
  return cookieString(token, maxAge, options.secure);
}

/**
 * Cookie Max-Age from a session's absolute expiry (A8). T06 must use this on
 * rotation: the session does not slide, so a fixed 30-day Max-Age late in a
 * session would leave the cookie alive after the server-side record expires.
 */
export function refreshCookieMaxAgeSeconds(expiresAt: Date, now: Date = new Date()): number {
  const seconds = Math.floor((expiresAt.getTime() - now.getTime()) / 1000);
  return Number.isFinite(seconds) ? Math.max(0, seconds) : 0;
}

/** `Set-Cookie` value that clears the refresh cookie (logout, revocation). */
export function clearRefreshCookie(options: { readonly secure: boolean }): string {
  return cookieString('', 0, options.secure);
}

function cookieString(value: string, maxAgeSeconds: number, secure: boolean): string {
  const parts = [
    `${REFRESH_COOKIE_NAME}=${value}`,
    `Max-Age=${maxAgeSeconds}`,
    `Path=${REFRESH_COOKIE_PATH}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * Extracts the refresh token from a Cookie header. Returns null for absent,
 * malformed, duplicated or non-token-shaped values — duplicates are rejected
 * because accepting one of several same-named cookies enables cookie tossing.
 */
export function parseRefreshCookie(header: string | undefined): string | null {
  if (header === undefined || header.length === 0) {
    return null;
  }
  let value: string | null = null;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) {
      continue;
    }
    if (part.slice(0, separator).trim() !== REFRESH_COOKIE_NAME) {
      continue;
    }
    if (value !== null) {
      return null; // duplicate name — ambiguous, fail closed
    }
    value = part.slice(separator + 1).trim();
  }
  if (value === null) {
    return null;
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  return isRefreshTokenShape(decoded) ? decoded : null;
}
