import { Writable } from 'node:stream';

import pino from 'pino';
import { describe, expect, it } from 'vitest';

import { PII_REDACTED, redactPii, redactPiiLogObject } from '../../src/security/pii/log-redact.js';

/**
 * ATTACK tests for auth-secret log redaction (F1-04 T02, ADR-007 A14).
 * Focus: key-case tricks, deep nesting, secrets inside arrays, camelCase
 * carrier keys, and the keys that MUST stay visible (errorCode, statusCode,
 * codeName, tenantId, userId) — plus proof the input object is never mutated.
 */

const PW = 's3cr3t-marker-pw';
const OTP = '482916-marker-otp';
const TOK = 'tok-marker-abcdef';

describe('redactPii — auth secret keys (lowercase/snake/camel forms)', () => {
  it.each([
    'password',
    'newPassword',
    'passphrase',
    'pin',
    'user_pin',
    'driverPin',
    'loginPin',
    'pin_code',
    'token',
    'accessToken',
    'refresh_token',
    'refreshTokenHash',
    'idToken',
    'secret',
    'clientSecret',
    'otp',
    'otpCode',
    'otp_code',
    'code',
    'sms_code',
    'verification_code',
    'authorization',
    'cookie',
    'set-cookie',
    'credential',
    'credentials',
    'userCredential',
  ])('redacts key %s', (key) => {
    expect(redactPii({ [key]: PW })[key]).toBe(PII_REDACTED);
  });
});

describe('redactPii — case tricks', () => {
  it.each([
    'Password',
    'PASSWORD',
    'pAsSwOrD',
    'OTP',
    'Otp',
    'Code',
    'CODE',
    'Token',
    'TOKEN',
    'Secret',
    'SECRET',
    'Authorization',
    'AUTHORIZATION',
    'Cookie',
    'COOKIE',
    'Credentials',
    'PIN',
    'Pin',
    'Passphrase',
  ])('redacts key %s', (key) => {
    expect(redactPii({ [key]: PW })[key]).toBe(PII_REDACTED);
  });
});

describe('redactPii — camelCase carrier keys (A14 attack surface)', () => {
  // Contract (A14): keys *containing* pin must be redacted. camelCase
  // `pinXxx` is how a TS codebase would actually name a PIN carrier.
  it.each(['pinCode', 'pinNumber', 'pinAttempts'])('redacts pin-carrier key %s', (key) => {
    expect(redactPii({ [key]: OTP })[key]).toBe(PII_REDACTED);
  });

  // The `*_code` rule only fires on snake_case; camelCase code-carriers are
  // the same OTP secret under a JS-idiomatic name.
  it.each(['smsCode', 'verificationCode'])('redacts code-carrier key %s', (key) => {
    expect(redactPii({ [key]: OTP })[key]).toBe(PII_REDACTED);
  });
});

describe('redactPii — structure attacks', () => {
  it('redacts at depth 7', () => {
    const input = { l1: { l2: { l3: { l4: { l5: { l6: { password: PW } } } } } } };
    const out = redactPii(input);
    expect(JSON.stringify(out)).not.toContain(PW);
    expect(out.l1.l2.l3.l4.l5.l6.password).toBe(PII_REDACTED);
  });

  it('redacts keys inside arrays and nested arrays', () => {
    const input = {
      attempts: [{ password: PW }, [{ otp: OTP }], { meta: { refreshToken: TOK } }],
    };
    const out = redactPii(input);
    const text = JSON.stringify(out);
    expect(text).not.toContain(PW);
    expect(text).not.toContain(OTP);
    expect(text).not.toContain(TOK);
  });

  it('redacts a sensitive-keyed subtree wholesale (over-redaction is by design)', () => {
    const out = redactPii({ credentials: { password: PW, userId: 'u-1' } });
    expect(out.credentials).toBe(PII_REDACTED);
  });

  it('does not mutate the input object', () => {
    const input = { password: PW, nested: { otp: OTP } };
    redactPii(input);
    expect(input.password).toBe(PW);
    expect(input.nested.otp).toBe(OTP);
  });

  it('redacts a realistic HTTP-shaped log object', () => {
    const out = redactPii({
      req: {
        headers: { authorization: `Bearer ${TOK}`, cookie: `session=${TOK}` },
        body: { username: 'op.one', password: PW },
      },
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(PW);
    expect(text).not.toContain(TOK);
    expect(out.req.body.username).toBe('op.one');
  });
});

describe('redactPii — keys that MUST stay visible', () => {
  it.each(['errorCode', 'statusCode', 'codeName', 'tenantId', 'userId', 'shipping'])(
    'does not redact key %s',
    (key) => {
      expect(redactPii({ [key]: 'visible-value' })[key]).toBe('visible-value');
    },
  );

  it('redacts DomainError-shaped { code } (accepted trade-off) but keeps errorCode/statusCode', () => {
    const out = redactPii({
      err: { code: 'LOGIN_THROTTLED', message: 'ورودی نامعتبر است' },
      errorCode: 'LOGIN_THROTTLED',
      statusCode: 423,
    });
    expect(out.err.code).toBe(PII_REDACTED);
    expect(out.errorCode).toBe('LOGIN_THROTTLED');
    expect(out.statusCode).toBe(423);
  });
});

describe('pino wiring — a real log call never writes the secret', () => {
  it('redacts password/otp/code/token keys in a real log line', () => {
    const chunks: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(String(chunk));
        callback();
      },
    });
    const logger = pino({ level: 'info', formatters: { log: redactPiiLogObject } }, stream);

    logger.info(
      {
        password: PW,
        otp: OTP,
        code: OTP,
        accessToken: TOK,
        headers: { authorization: `Bearer ${TOK}`, cookie: `sid=${TOK}` },
        errorCode: 'LOGIN_FAILED',
        userId: 'u-42',
      },
      'auth redaction probe',
    );

    const output = chunks.join('');
    expect(output).not.toContain(PW);
    expect(output).not.toContain(OTP);
    expect(output).not.toContain(TOK);
    expect(output).toContain(PII_REDACTED);
    expect(output).toContain('LOGIN_FAILED');
    expect(output).toContain('u-42');
    expect(output).toContain('auth redaction probe');
  });
});
