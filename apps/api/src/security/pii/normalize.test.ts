import { describe, expect, it } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import { normalizeNationalId, normalizePhone, toAsciiDigits } from './normalize.js';

/** Builds a valid national ID from 9 digits by computing the official checksum. */
function withCheckDigit(nineDigits: string): string {
  let sum = 0;
  for (let i = 0; i < 9; i += 1) {
    sum += Number(nineDigits[i]) * (10 - i);
  }
  const r = sum % 11;
  return nineDigits + String(r < 2 ? r : 11 - r);
}

describe('toAsciiDigits', () => {
  it('converts Persian digits', () => {
    expect(toAsciiDigits('۰۱۲۳۴۵۶۷۸۹')).toBe('0123456789');
  });

  it('converts Arabic-Indic digits', () => {
    expect(toAsciiDigits('٠١٢٣٤٥٦٧٨٩')).toBe('0123456789');
  });

  it('leaves ASCII and other characters untouched', () => {
    expect(toAsciiDigits('a09 ب')).toBe('a09 ب');
  });
});

describe('normalizePhone', () => {
  it('accepts the canonical form unchanged', () => {
    expect(normalizePhone('09120000001')).toBe('09120000001');
  });

  it('normalizes the +98, 0098, 98 and 9 prefixes', () => {
    expect(normalizePhone('+989120000001')).toBe('09120000001');
    expect(normalizePhone('00989120000001')).toBe('09120000001');
    expect(normalizePhone('989120000001')).toBe('09120000001');
    expect(normalizePhone('9120000001')).toBe('09120000001');
  });

  it('ignores spaces, dashes and parentheses', () => {
    expect(normalizePhone('0912 000 00 01')).toBe('09120000001');
    expect(normalizePhone('+98 (912) 000-0001')).toBe('09120000001');
  });

  it('normalizes Persian and Arabic digits', () => {
    expect(normalizePhone('۰۹۱۲۰۰۰۰۰۰۱')).toBe('09120000001');
    expect(normalizePhone('٠٩١٢٠٠٠٠٠٠١')).toBe('09120000001');
  });

  it('rejects invalid numbers with BAD_INPUT', () => {
    for (const bad of [
      '08123456789',
      '0912345678', // too short
      '091200000012', // too long
      '+98912000000', // too short after prefix
      'phone',
      '',
      null,
      undefined,
      9123456789,
    ]) {
      try {
        normalizePhone(bad);
        expect.unreachable(`expected rejection for ${String(bad)}`);
      } catch (error) {
        expect(error).toBeInstanceOf(DomainError);
        expect((error as DomainError).code).toBe('BAD_INPUT');
      }
    }
  });

  it('never echoes the rejected input in the error', () => {
    try {
      normalizePhone('+98 (912) 345-000'); // 10 digits after normalization — invalid
      expect.unreachable();
    } catch (error) {
      const text = JSON.stringify(error);
      expect(text).not.toContain('912');
      expect(text).not.toContain('+98');
    }
  });
});

describe('normalizeNationalId', () => {
  it('accepts a valid ID with a correct checksum', () => {
    const id = withCheckDigit('004958424');
    expect(normalizeNationalId(id)).toBe(id);
  });

  it('accepts a valid ID written with Persian digits and spaces', () => {
    const id = withCheckDigit('004958424');
    const persian = toAsciiDigits(id).replace(/\d/g, (d) =>
      String.fromCodePoint(0x06f0 + Number(d)),
    );
    expect(normalizeNationalId(persian)).toBe(id);
  });

  it('rejects a wrong checksum', () => {
    const id = withCheckDigit('004958424');
    // Flipping the check digit always invalidates the ID: the correct check
    // digit for the same 9 digits is unique.
    const corrupted = `${id.slice(0, 9)}${(Number(id[9]) + 1) % 10}`;
    expect(corrupted).not.toBe(id);
    expect(() => normalizeNationalId(corrupted)).toThrowError(DomainError);
  });

  it('rejects all-identical digits, wrong lengths and non-strings', () => {
    for (const bad of ['1111111111', '0000000000', '123456789', '12345678901', 'abcd', null, 42]) {
      expect(() => normalizeNationalId(bad)).toThrowError(DomainError);
    }
  });

  it('never echoes the rejected input in the error', () => {
    const id = withCheckDigit('004958424');
    const corrupted = `${id.slice(0, 9)}${(Number(id[9]) + 1) % 10}`;
    try {
      normalizeNationalId(corrupted);
      expect.unreachable();
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(corrupted);
    }
  });
});
