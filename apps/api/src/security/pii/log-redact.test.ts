import { Writable } from 'node:stream';

import pino from 'pino';
import { describe, expect, it } from 'vitest';

import { randomNationalId } from '../../../test/setup/national-id.js';
import { PII_CIRCULAR, PII_REDACTED, redactPii, redactPiiLogObject } from './log-redact.js';

const PHONE = '09120000001'; // gitleaks-allowlisted synthetic number

describe('redactPii', () => {
  it('redacts PII keys at any depth, including inside arrays', () => {
    const nationalId = randomNationalId();
    const input = {
      phone: PHONE,
      nested: { deep: { national_id: nationalId, keep: 'visible' } },
      list: [{ phone_hash: 'abc', nationalId }, { note: 'ok' }],
      phone_enc: Buffer.from([1, 2, 3]),
    };
    const out = redactPii(input);
    const text = JSON.stringify(out);
    expect(text).not.toContain(PHONE);
    expect(text).not.toContain(nationalId);
    expect(text).not.toContain('abc');
    expect(out.nested.deep.keep).toBe('visible');
    expect(out.list[1]?.note).toBe('ok');
    expect(out.phone).toBe(PII_REDACTED);
    expect(out.phone_enc).toBe(PII_REDACTED);
  });

  it('redacts every *_enc / *_hash key regardless of prefix', () => {
    const out = redactPii({ future_field_enc: 'x', another_hash: 'y' });
    expect(out.future_field_enc).toBe(PII_REDACTED);
    expect(out.another_hash).toBe(PII_REDACTED);
  });

  it('redacts compound and camelCase PII keys', () => {
    const nationalId = randomNationalId();
    const out = redactPii({
      driverPhone: PHONE,
      phone_number: PHONE,
      mobile_number: PHONE,
      nationalCode: nationalId,
      national_code: nationalId,
      phoneEnc: 'x',
      phoneHash: 'y',
      msisdn: PHONE,
      keepThis: 'visible',
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(PHONE);
    expect(text).not.toContain(nationalId);
    expect(out.phoneEnc).toBe(PII_REDACTED);
    expect(out.phoneHash).toBe(PII_REDACTED);
    expect(out.keepThis).toBe('visible');
  });

  it('redacts at any depth', () => {
    let deep: Record<string, unknown> = { phone: PHONE };
    for (let i = 0; i < 12; i += 1) {
      deep = { next: deep };
    }
    expect(JSON.stringify(redactPii(deep))).not.toContain(PHONE);
  });

  it('redacts a shared (non-cyclic) reference under every key', () => {
    // Regression: a global "seen" set would return the original object on the
    // second visit and leak the raw phone under key b.
    const shared = { phone: PHONE, name: 'visible' };
    const out = redactPii({ a: shared, b: shared });
    expect(out.a.phone).toBe(PII_REDACTED);
    expect(out.b.phone).toBe(PII_REDACTED);
    expect(out.b.name).toBe('visible');
    expect(JSON.stringify(out)).not.toContain(PHONE);
  });

  it('cuts a real cycle that contains a phone (no throw, no leak)', () => {
    const cyclic: Record<string, unknown> = { phone: PHONE };
    cyclic.self = cyclic;
    const out = redactPii(cyclic);
    expect(out.phone).toBe(PII_REDACTED);
    expect(out.self).toBe(PII_CIRCULAR);
    expect(JSON.stringify(out)).not.toContain(PHONE);
  });

  it('passes through primitives and null', () => {
    expect(redactPii(null)).toBeNull();
    expect(redactPii('plain')).toBe('plain');
    expect(redactPii(42)).toBe(42);
  });
});

describe('redactPii — auth secrets (ADR-007 A14)', () => {
  it('redacts password, PIN, token, secret, OTP and header keys at any depth', () => {
    const input = {
      password: 'secret-1',
      nested: { newPassword: 'secret-2', pin: '12345678', driverPin: '87654321' },
      accessToken: 'tok-1',
      refresh_token_hash: 'tok-2',
      tokenSecret: 'tok-3',
      otp: '123456',
      otpCode: '654321',
      code: '999999', // future OTP shape — redacted (accepted trade-off, see log-redact.ts)
      sms_code: '111111',
      authorization: 'Bearer x',
      cookieHeader: 'bitabar_refresh=…',
      credentials: { password: 'secret-3' },
      list: [{ passphrase: 'secret-4' }],
      headers: { 'idempotency-key': 'key-secret-5', 'Idempotency-Key': 'key-secret-6' },
      idempotencyReplay: true,
    };
    const out = redactPii(input);
    const text = JSON.stringify(out);
    for (const value of [
      'secret-1',
      'secret-2',
      'secret-3',
      'secret-4',
      '12345678',
      '87654321',
      'tok-1',
      'tok-2',
      'tok-3',
      '123456',
      '654321',
      '999999',
      '111111',
      'Bearer x',
      'bitabar_refresh=…',
      'key-secret-5',
      'key-secret-6',
    ]) {
      expect(text).not.toContain(value);
    }
    expect(out.password).toBe(PII_REDACTED);
    expect(out.code).toBe(PII_REDACTED);
    // The boolean replay marker is operational, not a credential.
    expect(out.idempotencyReplay).toBe(true);
  });

  it('keeps non-secret operational keys visible', () => {
    const out = redactPii({
      errorCode: 'INVALID_CREDENTIALS', // error codes stay observable (filter logs errorCode)
      statusCode: 401,
      codeName: 'named-shape',
      tenantCode: 'dev-factory', // part of the public login identifier — needed for spray detection
      tenantId: '00000000-0000-7000-8000-000000000001',
      userId: '00000000-0000-7000-8000-000000000002',
    });
    expect(out.errorCode).toBe('INVALID_CREDENTIALS');
    expect(out.statusCode).toBe(401);
    expect(out.codeName).toBe('named-shape');
    expect(out.tenantCode).toBe('dev-factory');
    expect(out.tenantId).toBe('00000000-0000-7000-8000-000000000001');
    expect(out.userId).toBe('00000000-0000-7000-8000-000000000002');
  });

  it('redacts api-key carrier keys (future adapters)', () => {
    const out = redactPii({ apiKey: 'k-1', api_key: 'k-2', 'x-api-key': 'k-3' });
    expect(out.apiKey).toBe(PII_REDACTED);
    expect(out.api_key).toBe(PII_REDACTED);
    expect(out['x-api-key']).toBe(PII_REDACTED);
  });

  it('redacts free-text reason at any depth but keeps the denial reasonCode visible', () => {
    const reason = 'دلیل محرمانه تست';
    const out = redactPii({
      reason,
      reasonText: reason,
      reason_text: reason,
      nested: { reason },
      list: [{ reason }, { keep: 'visible' }],
      req: { headers: { reason, 'x-reason': reason, 'x-reason-text': reason } },
      reasonCode: 'AUTHZ_PERMISSION_DENIED',
      reason_code: 'AUTHZ_PERMISSION_DENIED',
    });

    const text = JSON.stringify(out);
    expect(text).not.toContain(reason);
    expect(out.reason).toBe(PII_REDACTED);
    expect(out.reasonText).toBe(PII_REDACTED);
    expect(out.reason_text).toBe(PII_REDACTED);
    expect(out.nested.reason).toBe(PII_REDACTED);
    expect(out.list[0]?.reason).toBe(PII_REDACTED);
    expect(out.req.headers.reason).toBe(PII_REDACTED);
    expect(out.req.headers['x-reason']).toBe(PII_REDACTED);
    expect(out.req.headers['x-reason-text']).toBe(PII_REDACTED);
    expect(out.list[1]?.keep).toBe('visible');
    expect(out.reasonCode).toBe('AUTHZ_PERMISSION_DENIED');
    expect(out.reason_code).toBe('AUTHZ_PERMISSION_DENIED');
  });

  it('a real log call redacts reason in nested objects, arrays and headers', () => {
    const reason = 'دلیل محرمانه تست';
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
        reason,
        reasonText: reason,
        nested: { reason },
        list: [{ reason }],
        req: { headers: { 'x-reason': reason } },
        reasonCode: 'AUTHZ_PERMISSION_DENIED',
        reason_code: 'AUTHZ_PERMISSION_DENIED',
      },
      'reason redaction probe',
    );

    const output = chunks.join('');
    expect(output).not.toContain(reason);
    expect(output).toContain(PII_REDACTED);
    expect(output).toContain('AUTHZ_PERMISSION_DENIED');
    expect(output).toContain('reason redaction probe');
  });

  it('a child logger binding carrying reason is redacted too', () => {
    const reason = 'دلیل محرمانه تست';
    const chunks: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(String(chunk));
        callback();
      },
    });
    const logger = pino(
      {
        level: 'info',
        redact: {
          paths: ['reason', '*.reason'],
          censor: '[redacted]',
        },
        formatters: { log: redactPiiLogObject },
      },
      stream,
    );

    logger.child({ reason }).info('child reason probe');

    const output = chunks.join('');
    expect(output).not.toContain(reason);
    expect(output).toContain('child reason probe');
  });

  it('a real log call with a password/token/cookie header and otp/code keys writes [Redacted]', () => {
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
        password: 'hunter2-hunter2',
        token: 'access-token-value',
        cookie: 'bitabar_refresh=refresh-token-value',
        otp: '481516',
        code: '234267',
      },
      'auth redaction probe',
    );

    const output = chunks.join('');
    for (const value of [
      'hunter2-hunter2',
      'access-token-value',
      'refresh-token-value',
      '481516',
      '234267',
    ]) {
      expect(output).not.toContain(value);
    }
    expect(output).toContain(PII_REDACTED);
    expect(output).toContain('auth redaction probe');
  });
});

describe('pino wiring (formatters.log)', () => {
  it('hides phone and nationalId in a real log call', () => {
    const nationalId = randomNationalId();
    const chunks: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(String(chunk));
        callback();
      },
    });
    const logger = pino({ level: 'info', formatters: { log: redactPiiLogObject } }, stream);

    logger.info(
      { phone: PHONE, nationalId, user: { national_id: nationalId }, action: 'test' },
      'pii redaction probe',
    );

    const output = chunks.join('');
    expect(output).not.toContain(PHONE);
    expect(output).not.toContain(nationalId);
    expect(output).toContain(PII_REDACTED);
    expect(output).toContain('pii redaction probe');
    expect(output).toContain('test');
  });
});
