import { describe, expect, it } from 'vitest';

import { parseEnv } from './env.js';

/** Minimal valid environment; individual tests override one variable. */
const BASE_ENV = {
  DATABASE_URL: 'postgresql://bitabar_app:secret-pw@localhost:5432/bitabar',
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
