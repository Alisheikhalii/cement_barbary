import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { parseEnv } from './env.js';

// Random per run (ADR-006 U17) — test-only placeholders, never real secrets.
const PII_ENC = randomBytes(32).toString('base64');
const PII_HMAC = randomBytes(32).toString('base64');
const TOKEN_SECRET = randomBytes(32).toString('base64');

/** Minimal valid environment; individual tests override one variable. */
const BASE_ENV = {
  DATABASE_URL: 'postgresql://bitabar_app:secret-pw@localhost:5432/bitabar',
  PII_ENC_KEY: PII_ENC,
  PII_HMAC_KEY: PII_HMAC,
  AUTH_TOKEN_SECRET: TOKEN_SECRET,
};

describe('parseEnv', () => {
  it('applies defaults when only the required variables are set', () => {
    const config = parseEnv({ ...BASE_ENV });
    expect(config.nodeEnv).toBe('development');
    expect(config.port).toBe(4000);
    expect(config.publicUrl).toBe('http://localhost:4000');
    expect(config.corsOrigins).toEqual(['http://localhost:3000']);
  });

  it('parses a fully specified environment', () => {
    const config = parseEnv({
      ...BASE_ENV,
      NODE_ENV: 'production',
      API_PORT: '8080',
      API_PUBLIC_URL: 'https://api.example.ir',
      CORS_ALLOWED_ORIGINS: 'https://panel.example.ir, https://driver.example.ir',
      DATABASE_POOL_MAX: '25',
      DATABASE_STATEMENT_TIMEOUT_MS: '10000',
    });
    expect(config.nodeEnv).toBe('production');
    expect(config.port).toBe(8080);
    expect(config.publicUrl).toBe('https://api.example.ir');
    expect(config.corsOrigins).toEqual(['https://panel.example.ir', 'https://driver.example.ir']);
    expect(config.database).toEqual({
      url: BASE_ENV.DATABASE_URL,
      poolMax: 25,
      statementTimeoutMs: 10000,
    });
  });

  it('fails fast on an invalid port', () => {
    expect(() => parseEnv({ ...BASE_ENV, API_PORT: 'not-a-number' })).toThrow(
      /Invalid environment/,
    );
  });

  it('fails fast on an invalid NODE_ENV', () => {
    expect(() => parseEnv({ ...BASE_ENV, NODE_ENV: 'staging-ish' })).toThrow(/Invalid environment/);
  });

  it('fails fast on an invalid public URL', () => {
    expect(() => parseEnv({ ...BASE_ENV, API_PUBLIC_URL: 'not a url' })).toThrow(
      /Invalid environment/,
    );
  });

  it('fails fast when DATABASE_URL is missing', () => {
    expect(() => parseEnv({})).toThrow(/DATABASE_URL/);
  });

  it('fails fast on a non-postgres DATABASE_URL', () => {
    expect(() => parseEnv({ DATABASE_URL: 'mysql://localhost/db' })).toThrow(
      /must be a postgres URL/,
    );
  });

  it('defaults the pool size to 10 and the statement timeout to 5000', () => {
    const config = parseEnv({ ...BASE_ENV });
    expect(config.database.poolMax).toBe(10);
    expect(config.database.statementTimeoutMs).toBe(5000);
  });

  it('fails fast when DATABASE_POOL_MAX is 0', () => {
    expect(() => parseEnv({ ...BASE_ENV, DATABASE_POOL_MAX: '0' })).toThrow(/Invalid environment/);
  });

  it('never leaks the password into validation error messages', () => {
    let message = '';
    try {
      parseEnv({ DATABASE_URL: 'mysql://user:sup3r-secret-pw@localhost/db' });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toContain('sup3r-secret-pw');
    expect(message).toContain('DATABASE_URL');
  });
});

describe('parseEnv PII keys (ADR-006 U10)', () => {
  it('parses valid keys into 32-byte buffers with key id default 1', () => {
    const config = parseEnv({ ...BASE_ENV });
    expect(config.pii.encKey.length).toBe(32);
    expect(config.pii.hmacKey.length).toBe(32);
    expect(config.pii.encKey.equals(config.pii.hmacKey)).toBe(false);
    expect(config.pii.keyId).toBe(1);
  });

  it('fails fast when PII_ENC_KEY is missing', () => {
    const env: Record<string, string> = { ...BASE_ENV };
    delete env.PII_ENC_KEY;
    expect(() => parseEnv(env)).toThrow(/PII_ENC_KEY/);
  });

  it('fails fast when PII_HMAC_KEY is missing', () => {
    const env: Record<string, string> = { ...BASE_ENV };
    delete env.PII_HMAC_KEY;
    expect(() => parseEnv(env)).toThrow(/PII_HMAC_KEY/);
  });

  it('fails fast when a key does not decode to exactly 32 bytes', () => {
    const short16 = randomBytes(16).toString('base64');
    const long48 = randomBytes(48).toString('base64');
    expect(() => parseEnv({ ...BASE_ENV, PII_ENC_KEY: short16 })).toThrow(/PII_ENC_KEY/);
    expect(() => parseEnv({ ...BASE_ENV, PII_HMAC_KEY: long48 })).toThrow(/PII_HMAC_KEY/);
    expect(() => parseEnv({ ...BASE_ENV, PII_ENC_KEY: 'not!base64!' })).toThrow(/PII_ENC_KEY/);
  });

  it('fails fast when the encryption and HMAC keys are identical', () => {
    expect(() => parseEnv({ ...BASE_ENV, PII_HMAC_KEY: PII_ENC })).toThrow(
      /must differ from PII_ENC_KEY/,
    );
  });

  it('fails fast on an out-of-range PII_KEY_ID and accepts 1..255', () => {
    expect(() => parseEnv({ ...BASE_ENV, PII_KEY_ID: '0' })).toThrow(/PII_KEY_ID/);
    expect(() => parseEnv({ ...BASE_ENV, PII_KEY_ID: '256' })).toThrow(/PII_KEY_ID/);
    expect(parseEnv({ ...BASE_ENV, PII_KEY_ID: '255' }).pii.keyId).toBe(255);
  });

  it('never leaks key material into validation error messages', () => {
    const secretKey = randomBytes(32).toString('base64');
    let message = '';
    try {
      parseEnv({
        DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
        PII_ENC_KEY: secretKey,
        PII_HMAC_KEY: secretKey,
        AUTH_TOKEN_SECRET: TOKEN_SECRET,
      });
      expect.unreachable();
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toContain(secretKey);
    expect(message).toMatch(/must differ from PII_ENC_KEY/);
  });
});

describe('parseEnv auth config (ADR-007, F1-04)', () => {
  it('defaults every auth number — Argon2 defaults equal the OWASP floor (A1)', () => {
    const config = parseEnv({ ...BASE_ENV });
    expect(config.auth.argon2).toEqual({ memoryKiB: 19456, time: 2, parallelism: 1 });
    expect(config.auth.loginDelay).toEqual({ baseSeconds: 1, maxSeconds: 300 });
    expect(config.auth.rateLimit).toEqual({ loginIpPerMinute: 20, loginTenantPerMinute: 60 });
    expect(config.auth.accessTokenTtlSeconds).toBe(600);
    expect(config.auth.tempPasswordTtlHours).toBe(24);
  });

  it('rejects Argon2 parameters weaker than the OWASP floor (condition 7)', () => {
    expect(() => parseEnv({ ...BASE_ENV, AUTH_ARGON2_MEMORY_KIB: '19455' })).toThrow(
      /AUTH_ARGON2_MEMORY_KIB/,
    );
    expect(() => parseEnv({ ...BASE_ENV, AUTH_ARGON2_TIME: '1' })).toThrow(/AUTH_ARGON2_TIME/);
    expect(() => parseEnv({ ...BASE_ENV, AUTH_ARGON2_PARALLELISM: '0' })).toThrow(
      /AUTH_ARGON2_PARALLELISM/,
    );
  });

  it('accepts stronger-than-floor Argon2 parameters', () => {
    const config = parseEnv({
      ...BASE_ENV,
      AUTH_ARGON2_MEMORY_KIB: '65536',
      AUTH_ARGON2_TIME: '4',
      AUTH_ARGON2_PARALLELISM: '2',
    });
    expect(config.auth.argon2).toEqual({ memoryKiB: 65536, time: 4, parallelism: 2 });
  });

  it('rejects a delay base above the delay cap', () => {
    expect(() =>
      parseEnv({ ...BASE_ENV, AUTH_LOCK_BASE_SECONDS: '60', AUTH_LOCK_MAX_SECONDS: '10' }),
    ).toThrow(/must not exceed AUTH_LOCK_MAX_SECONDS/);
  });

  it('bounds the access-token TTL and the temp-password TTL', () => {
    expect(() => parseEnv({ ...BASE_ENV, AUTH_ACCESS_TOKEN_TTL_SECONDS: '30' })).toThrow(
      /AUTH_ACCESS_TOKEN_TTL_SECONDS/,
    );
    // Owner T05 rule: access tokens stay short — 15 minutes is the ceiling.
    expect(() => parseEnv({ ...BASE_ENV, AUTH_ACCESS_TOKEN_TTL_SECONDS: '901' })).toThrow(
      /AUTH_ACCESS_TOKEN_TTL_SECONDS/,
    );
    expect(
      parseEnv({ ...BASE_ENV, AUTH_ACCESS_TOKEN_TTL_SECONDS: '900' }).auth.accessTokenTtlSeconds,
    ).toBe(900);
    expect(() => parseEnv({ ...BASE_ENV, AUTH_TEMP_PASSWORD_TTL_HOURS: '0' })).toThrow(
      /AUTH_TEMP_PASSWORD_TTL_HOURS/,
    );
  });
});

describe('parseEnv AUTH_TOKEN_SECRET (ADR-007 A7/A13)', () => {
  it('decodes 32–64 random bytes from base64', () => {
    const config = parseEnv({ ...BASE_ENV });
    expect(config.auth.tokenSecret).toHaveLength(32);
    const longer = parseEnv({
      ...BASE_ENV,
      AUTH_TOKEN_SECRET: randomBytes(48).toString('base64'),
    });
    expect(longer.auth.tokenSecret).toHaveLength(48);
  });

  it('is required — a missing secret fails startup', () => {
    const withoutSecret: Record<string, string | undefined> = { ...BASE_ENV };
    delete withoutSecret.AUTH_TOKEN_SECRET;
    expect(() => parseEnv(withoutSecret)).toThrow(/AUTH_TOKEN_SECRET/);
  });

  it('rejects a short key (16 bytes) and a non-base64 value', () => {
    expect(() =>
      parseEnv({ ...BASE_ENV, AUTH_TOKEN_SECRET: randomBytes(16).toString('base64') }),
    ).toThrow(/AUTH_TOKEN_SECRET/);
    expect(() => parseEnv({ ...BASE_ENV, AUTH_TOKEN_SECRET: 'not+base64===' })).toThrow(
      /AUTH_TOKEN_SECRET/,
    );
  });

  it('never leaks the secret into a validation error message', () => {
    const shortKey = randomBytes(16).toString('base64');
    let message = '';
    try {
      parseEnv({ ...BASE_ENV, AUTH_TOKEN_SECRET: shortKey });
      expect.unreachable();
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/AUTH_TOKEN_SECRET/);
    expect(message).not.toContain(shortKey);
  });

  it('rejects a secret equal to either PII key (A13: one leak, one purpose)', () => {
    expect(() => parseEnv({ ...BASE_ENV, AUTH_TOKEN_SECRET: PII_ENC })).toThrow(
      /AUTH_TOKEN_SECRET: must differ from PII_ENC_KEY/,
    );
    expect(() => parseEnv({ ...BASE_ENV, AUTH_TOKEN_SECRET: PII_HMAC })).toThrow(
      /AUTH_TOKEN_SECRET: must differ from PII_HMAC_KEY/,
    );
  });
});
