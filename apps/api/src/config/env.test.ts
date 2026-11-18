import { describe, expect, it } from 'vitest';

import { parseEnv } from './env.js';

describe('parseEnv', () => {
  it('applies defaults when no variables are set', () => {
    const config = parseEnv({});
    expect(config.nodeEnv).toBe('development');
    expect(config.port).toBe(4000);
    expect(config.publicUrl).toBe('http://localhost:4000');
    expect(config.corsOrigins).toEqual(['http://localhost:3000']);
  });

  it('parses a fully specified environment', () => {
    const config = parseEnv({
      NODE_ENV: 'production',
      API_PORT: '8080',
      API_PUBLIC_URL: 'https://api.example.ir',
      CORS_ALLOWED_ORIGINS: 'https://panel.example.ir, https://driver.example.ir',
    });
    expect(config.nodeEnv).toBe('production');
    expect(config.port).toBe(8080);
    expect(config.corsOrigins).toEqual(['https://panel.example.ir', 'https://driver.example.ir']);
  });

  it('fails fast on an invalid port', () => {
    expect(() => parseEnv({ API_PORT: 'not-a-number' })).toThrow(/Invalid environment/);
  });

  it('fails fast on an invalid NODE_ENV', () => {
    expect(() => parseEnv({ NODE_ENV: 'staging-ish' })).toThrow(/Invalid environment/);
  });

  it('fails fast on an invalid public URL', () => {
    expect(() => parseEnv({ API_PUBLIC_URL: 'not a url' })).toThrow(/Invalid environment/);
  });
});
