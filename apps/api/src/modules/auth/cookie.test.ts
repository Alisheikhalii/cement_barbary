import { describe, expect, it } from 'vitest';

import {
  clearRefreshCookie,
  parseRefreshCookie,
  REFRESH_COOKIE_MAX_AGE_SECONDS,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  refreshCookieMaxAgeSeconds,
  serializeRefreshCookie,
} from './cookie.js';
import { generateRefreshToken } from './refresh-token.js';

/** Cookie attribute strings (ADR-007 A8/A12, GUIDELINES §6.1). */
describe('refresh cookie', () => {
  const token = generateRefreshToken();

  it('serializes with HttpOnly, Lax, the mounted auth path and Max-Age', () => {
    expect(REFRESH_COOKIE_PATH).toBe('/api/v1/auth');
    expect(serializeRefreshCookie(token, { secure: true })).toBe(
      `bitabar_refresh=${token}; Max-Age=2592000; Path=/api/v1/auth; HttpOnly; SameSite=Lax; Secure`,
    );
  });

  it('refuses to serialize a malformed value (header-injection guard)', () => {
    for (const bad of ['', 'short', `${token}; Domain=evil.example`, `${token}\r\nX: y`]) {
      expect(() => serializeRefreshCookie(bad, { secure: true })).toThrow(/malformed/);
    }
  });

  it('derives the remaining cookie lifetime from the session expiry', () => {
    const now = new Date('2026-11-20T00:00:00Z');
    expect(refreshCookieMaxAgeSeconds(new Date('2026-11-20T00:10:00Z'), now)).toBe(600);
    expect(refreshCookieMaxAgeSeconds(new Date('2026-11-19T00:00:00Z'), now)).toBe(0);
    // A programming-error Date must not serialize `Max-Age=NaN`.
    expect(refreshCookieMaxAgeSeconds(new Date('not-a-date'), now)).toBe(0);
    expect(REFRESH_COOKIE_MAX_AGE_SECONDS).toBe(30 * 24 * 60 * 60);
  });

  it('omits Secure only when explicitly told (local http dev)', () => {
    const value = serializeRefreshCookie(token, { secure: false });
    expect(value).not.toContain('Secure');
    expect(value).toContain('HttpOnly');
    expect(value).toContain('SameSite=Lax');
  });

  it('never sets a Domain attribute', () => {
    expect(serializeRefreshCookie(token, { secure: true })).not.toMatch(/Domain=/i);
  });

  it('honours a custom Max-Age', () => {
    expect(serializeRefreshCookie(token, { secure: true, maxAgeSeconds: 60 })).toContain(
      'Max-Age=60',
    );
  });

  it('clears with an empty value and Max-Age=0, keeping the same scope and flags', () => {
    expect(clearRefreshCookie({ secure: true })).toBe(
      'bitabar_refresh=; Max-Age=0; Path=/api/v1/auth; HttpOnly; SameSite=Lax; Secure',
    );
    expect(clearRefreshCookie({ secure: false })).toBe(
      'bitabar_refresh=; Max-Age=0; Path=/api/v1/auth; HttpOnly; SameSite=Lax',
    );
  });
});

describe('parseRefreshCookie', () => {
  const token = generateRefreshToken();

  it('extracts the token from a Cookie header', () => {
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=${token}`)).toBe(token);
  });

  it('finds it among other cookies and tolerates spaces', () => {
    expect(parseRefreshCookie(`theme=dark; ${REFRESH_COOKIE_NAME}=${token}; lang=fa`)).toBe(token);
    expect(parseRefreshCookie(`theme=dark;${REFRESH_COOKIE_NAME}= ${token} `)).toBe(token);
  });

  it('decodes percent-encoded values', () => {
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=${encodeURIComponent(token)}`)).toBe(token);
  });

  it('returns null for absent, empty, malformed or non-token values', () => {
    expect(parseRefreshCookie(undefined)).toBeNull();
    expect(parseRefreshCookie('')).toBeNull();
    expect(parseRefreshCookie('theme=dark')).toBeNull();
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=`)).toBeNull();
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=short`)).toBeNull();
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=${'a'.repeat(42)}`)).toBeNull();
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=${'a'.repeat(44)}`)).toBeNull();
    expect(parseRefreshCookie(`${REFRESH_COOKIE_NAME}=%E0%A4%A`)).toBeNull();
  });

  it('rejects duplicated cookie names (cookie-tossing safety)', () => {
    expect(
      parseRefreshCookie(`${REFRESH_COOKIE_NAME}=${token}; ${REFRESH_COOKIE_NAME}=${token}`),
    ).toBeNull();
  });
});
