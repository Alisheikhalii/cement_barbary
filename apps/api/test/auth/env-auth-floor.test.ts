import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { parseEnv } from '../../src/config/env.js';

/**
 * ATTACK tests for the F1-04 auth env floor (ADR-007 A1 condition 7, A2, A11,
 * A7, A19): startup must refuse Argon2 parameters weaker than the OWASP
 * minimum and any inconsistent lockout / rate-limit / TTL numbers, while
 * accepting the floor itself and anything stronger.
 */

function baseEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    DATABASE_URL: 'postgresql://bitabar_app:x@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
    ...overrides,
  };
}

describe('auth env — defaults equal the OWASP minimum (A1 condition 7)', () => {
  it('parses with floor defaults when no AUTH_* vars are set', () => {
    const config = parseEnv(baseEnv());
    expect(config.auth.argon2).toEqual({ memoryKiB: 19456, time: 2, parallelism: 1 });
    expect(config.auth.loginDelay).toEqual({ baseSeconds: 1, maxSeconds: 300 });
    expect(config.auth.rateLimit).toEqual({
      loginIpPerMinute: 20,
      loginAccountPerMinute: 10,
      loginTenantPerMinute: 60,
    });
    expect(config.auth.accessTokenTtlSeconds).toBe(600);
    expect(config.auth.tempPasswordTtlHours).toBe(24);
  });
});

describe('auth env — Argon2 floor rejects anything weaker', () => {
  const memoryAttacks: [string, string][] = [
    ['one KiB below the floor', '19455'],
    ['zero', '0'],
    ['negative', '-100'],
    ['above the hard cap', '1048577'],
    ['non-numeric garbage', 'lots-of-memory'],
    ['float', '19456.5'],
    ['hex text just below the floor', '0x4bff'],
    ['infinity', 'Infinity'],
    ['empty string', ''],
  ];
  it.each(memoryAttacks)('rejects AUTH_ARGON2_MEMORY_KIB — %s', (_label, value) => {
    expect(() => parseEnv(baseEnv({ AUTH_ARGON2_MEMORY_KIB: value }))).toThrow(
      /AUTH_ARGON2_MEMORY_KIB/,
    );
  });

  const timeAttacks: [string, string][] = [
    ['one below the floor', '1'],
    ['zero', '0'],
    ['non-numeric', 'twice'],
    ['above the hard cap', '11'],
  ];
  it.each(timeAttacks)('rejects AUTH_ARGON2_TIME — %s', (_label, value) => {
    expect(() => parseEnv(baseEnv({ AUTH_ARGON2_TIME: value }))).toThrow(/AUTH_ARGON2_TIME/);
  });

  const parallelismAttacks: [string, string][] = [
    ['zero (below the floor)', '0'],
    ['negative', '-1'],
    ['non-numeric', 'many'],
    ['above the hard cap', '9'],
  ];
  it.each(parallelismAttacks)('rejects AUTH_ARGON2_PARALLELISM — %s', (_label, value) => {
    expect(() => parseEnv(baseEnv({ AUTH_ARGON2_PARALLELISM: value }))).toThrow(
      /AUTH_ARGON2_PARALLELISM/,
    );
  });
});

describe('auth env — the floor itself and stronger values are accepted', () => {
  it('accepts exactly the OWASP floor', () => {
    const config = parseEnv(
      baseEnv({
        AUTH_ARGON2_MEMORY_KIB: '19456',
        AUTH_ARGON2_TIME: '2',
        AUTH_ARGON2_PARALLELISM: '1',
      }),
    );
    expect(config.auth.argon2).toEqual({ memoryKiB: 19456, time: 2, parallelism: 1 });
  });

  it('accepts stronger-than-floor parameters and exposes them typed', () => {
    const config = parseEnv(
      baseEnv({
        AUTH_ARGON2_MEMORY_KIB: '65536',
        AUTH_ARGON2_TIME: '4',
        AUTH_ARGON2_PARALLELISM: '4',
      }),
    );
    expect(config.auth.argon2).toEqual({ memoryKiB: 65536, time: 4, parallelism: 4 });
  });
});

describe('auth env — lockout consistency (A2)', () => {
  it('rejects AUTH_LOCK_BASE_SECONDS greater than AUTH_LOCK_MAX_SECONDS', () => {
    expect(() =>
      parseEnv(baseEnv({ AUTH_LOCK_BASE_SECONDS: '60', AUTH_LOCK_MAX_SECONDS: '10' })),
    ).toThrow(/AUTH_LOCK_BASE_SECONDS: must not exceed AUTH_LOCK_MAX_SECONDS/);
  });

  it('accepts base == max (boundary is not greater)', () => {
    const config = parseEnv(baseEnv({ AUTH_LOCK_BASE_SECONDS: '10', AUTH_LOCK_MAX_SECONDS: '10' }));
    expect(config.auth.loginDelay).toEqual({ baseSeconds: 10, maxSeconds: 10 });
  });

  const lockAttacks: [string, Record<string, string>][] = [
    ['base above its hard cap', { AUTH_LOCK_BASE_SECONDS: '61' }],
    ['base zero', { AUTH_LOCK_BASE_SECONDS: '0' }],
    ['base non-numeric', { AUTH_LOCK_BASE_SECONDS: 'soon' }],
    ['max below its floor', { AUTH_LOCK_MAX_SECONDS: '9' }],
    ['max non-numeric', { AUTH_LOCK_MAX_SECONDS: 'forever' }],
  ];
  it.each(lockAttacks)('rejects %s', (_label, overrides) => {
    expect(() => parseEnv(baseEnv(overrides))).toThrow(/AUTH_LOCK_/);
  });
});

describe('auth env — rate-limit and TTL floors (A11 / A7 / A19)', () => {
  const attacks: [Record<string, string>, RegExp][] = [
    [{ AUTH_RL_LOGIN_IP_PER_MIN: '0' }, /AUTH_RL_LOGIN_IP_PER_MIN/],
    [{ AUTH_RL_LOGIN_IP_PER_MIN: 'many' }, /AUTH_RL_LOGIN_IP_PER_MIN/],
    [{ AUTH_RL_LOGIN_TENANT_PER_MIN: '0' }, /AUTH_RL_LOGIN_TENANT_PER_MIN/],
    [{ AUTH_ACCESS_TOKEN_TTL_SECONDS: '59' }, /AUTH_ACCESS_TOKEN_TTL_SECONDS/],
    [{ AUTH_ACCESS_TOKEN_TTL_SECONDS: '3601' }, /AUTH_ACCESS_TOKEN_TTL_SECONDS/],
    [{ AUTH_TEMP_PASSWORD_TTL_HOURS: '0' }, /AUTH_TEMP_PASSWORD_TTL_HOURS/],
    [{ AUTH_TEMP_PASSWORD_TTL_HOURS: '169' }, /AUTH_TEMP_PASSWORD_TTL_HOURS/],
  ];
  it.each(attacks)('rejects %j', (overrides, pattern) => {
    expect(() => parseEnv(baseEnv(overrides))).toThrow(pattern);
  });
});
