import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  LOGIN_WINDOW_SECONDS,
  RATE_LIMIT_KEY_PATTERNS,
  rateLimitKeys,
} from '../../src/modules/auth/rate-limiter.js';

/**
 * ATTACK tests for the rate-limit key shapes (F1-04 T02/T06, ADR-007 A11) and
 * the owner's key-shape rule: account and tenant dimensions are HMAC'd, so the
 * persisted row never contains a raw phone, username or tenant code.
 */

const secret = randomBytes(32);
const keys = rateLimitKeys(secret);

describe('rateLimitKeys — hashed identifier keys', () => {
  it('keeps only the client IP in the IP bucket', () => {
    expect(keys.loginIp('203.0.113.7')).toBe('login:ip:203.0.113.7');
    expect(keys.loginIp('::ffff:127.0.0.1')).toBe('login:ip:::ffff:127.0.0.1');
  });

  it('hashes account and tenant identifiers — no raw PII in the key', () => {
    const phone = '09120000001';
    const username = 'operator';
    const tenantCode = 'dev-factory';
    const generated = [
      keys.loginAccount(`driver:${phone}`),
      keys.loginAccount(`staff:${tenantCode}:${username}`),
      keys.loginTenant(tenantCode),
    ];
    for (const key of generated) {
      expect(key).not.toContain(phone);
      expect(key).not.toContain(username);
      expect(key).not.toContain(tenantCode);
      expect(key).toMatch(/^login:(acct|tenant):[A-Za-z0-9_-]{43}$/);
    }
  });

  it('the exported patterns pin the exact key shapes', () => {
    expect(RATE_LIMIT_KEY_PATTERNS.loginIp.test(keys.loginIp('127.0.0.1'))).toBe(true);
    expect(RATE_LIMIT_KEY_PATTERNS.loginAccount.test(keys.loginAccount('driver:09120000001'))).toBe(
      true,
    );
    expect(RATE_LIMIT_KEY_PATTERNS.loginTenant.test(keys.loginTenant('dev-factory'))).toBe(true);
    expect(RATE_LIMIT_KEY_PATTERNS.loginIp.test('login:acct:abc')).toBe(false);
    expect(RATE_LIMIT_KEY_PATTERNS.loginAccount.test('login:acct:short')).toBe(false);
  });

  it('is deterministic for the same secret and identifier, and distinct otherwise', () => {
    expect(keys.loginAccount('staff:a:u1')).toBe(keys.loginAccount('staff:a:u1'));
    expect(keys.loginAccount('staff:a:u1')).not.toBe(keys.loginAccount('staff:b:u1'));
    expect(keys.loginTenant('a')).toBe(rateLimitKeys(secret).loginTenant('a'));
    expect(keys.loginTenant('a')).not.toBe(rateLimitKeys(randomBytes(32)).loginTenant('a'));
  });

  it('never lets crafted values collide across namespaces', () => {
    const crafted = ['x', 'tenant:x', 'ip:x', 'tenant:', 'ip:', ':', '', 'a:b:c'];
    for (const a of crafted) {
      for (const b of crafted) {
        expect(keys.loginIp(a)).not.toBe(keys.loginTenant(b));
        expect(keys.loginAccount(a)).not.toBe(keys.loginTenant(b));
      }
    }
  });

  it('uses a 60-second window behind the per-minute config numbers', () => {
    expect(LOGIN_WINDOW_SECONDS).toBe(60);
  });
});
