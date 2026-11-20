import { describe, expect, it } from 'vitest';

import { LOGIN_WINDOW_SECONDS, rateLimitKeys } from '../../src/modules/auth/rate-limiter.js';

/**
 * ATTACK tests for the rate-limit key shapes (F1-04 T02, ADR-007 A11): keys
 * must stay namespaced so crafted IPs / tenant codes can never collide across
 * buckets and share a counter.
 */

describe('rateLimitKeys', () => {
  it('builds the documented key shapes', () => {
    expect(rateLimitKeys.loginIp('203.0.113.7')).toBe('login:ip:203.0.113.7');
    expect(rateLimitKeys.loginTenant('acme')).toBe('login:tenant:acme');
  });

  it('uses a 60-second window behind the per-minute config numbers', () => {
    expect(LOGIN_WINDOW_SECONDS).toBe(60);
  });

  it('never lets crafted values collide across namespaces', () => {
    const crafted = ['x', 'tenant:x', 'ip:x', 'tenant:', 'ip:', ':', '', 'a:b:c'];
    for (const ip of crafted) {
      for (const tenant of crafted) {
        expect(rateLimitKeys.loginIp(ip)).not.toBe(rateLimitKeys.loginTenant(tenant));
      }
    }
  });
});
