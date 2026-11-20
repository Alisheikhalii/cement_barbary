import { randomBytes } from 'node:crypto';

import type { ExecutionContext } from '@nestjs/common';
import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import { parseEnv, type AppConfig } from '../../config/env.js';
import { CSRF_HEADER, CSRF_HEADER_VALUE, CsrfGuard } from './csrf.guard.js';

/**
 * CSRF policy (ADR-007 A12, GUIDELINES §6.3): custom header required; Origin,
 * when present, must be in the allowlist; otherwise Sec-Fetch-Site must be
 * same-origin. Failures are 403 and carry no cookie.
 */

function config(): AppConfig {
  return parseEnv({
    DATABASE_URL: 'postgresql://bitabar_app:x@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
    CORS_ALLOWED_ORIGINS: 'https://panel.example.ir,https://driver.example.ir',
  });
}

function contextWith(headers: Record<string, string | undefined>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
  } as unknown as ExecutionContext;
}

const guard = new CsrfGuard(config());
const ok = { [CSRF_HEADER]: CSRF_HEADER_VALUE };

describe('CsrfGuard', () => {
  it('accepts the custom header from an allowed origin', () => {
    expect(guard.canActivate(contextWith({ ...ok, origin: 'https://panel.example.ir' }))).toBe(
      true,
    );
  });

  it('accepts a non-browser client with only the custom header', () => {
    expect(guard.canActivate(contextWith(ok))).toBe(true);
  });

  it('rejects a missing / wrong custom header', () => {
    for (const value of [undefined, '', '0', 'true', 'yes']) {
      expect(() =>
        guard.canActivate(
          contextWith({
            ...(value === undefined ? {} : { [CSRF_HEADER]: value }),
          }),
        ),
      ).toThrow(ForbiddenException);
    }
  });

  it('rejects a cross-origin or unlisted Origin', () => {
    for (const origin of [
      'https://evil.example',
      'https://panel.example.ir.evil.example',
      'https://evil-panel.example.ir',
      'null',
      'https://PANEL.EXAMPLE.IR',
      'https://panel.example.ir/',
      'https://panel.example.ir:444',
    ]) {
      expect(() => guard.canActivate(contextWith({ ...ok, origin }))).toThrow(ForbiddenException);
    }
  });

  it('rejects a cross-site Sec-Fetch-Site when Origin is absent', () => {
    for (const site of ['cross-site', 'same-site', 'none']) {
      expect(() => guard.canActivate(contextWith({ ...ok, 'sec-fetch-site': site }))).toThrow(
        ForbiddenException,
      );
    }
    expect(guard.canActivate(contextWith({ ...ok, 'sec-fetch-site': 'same-origin' }))).toBe(true);
  });

  it('checks the header before looking at any cookie — no cookie oracle', () => {
    // Both a "valid-looking" and an absent cookie hit the same first check.
    expect(() => guard.canActivate(contextWith({ cookie: 'bitabar_refresh=abc' }))).toThrow(
      ForbiddenException,
    );
    expect(() => guard.canActivate(contextWith({}))).toThrow(ForbiddenException);
  });
});
