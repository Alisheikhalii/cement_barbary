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
