import { describe, expect, it } from 'vitest';

import { nameInputSchema, NAME_MAX_LENGTH, normalizeNameKey } from './name-key.js';

describe('normalizeNameKey', () => {
  it('maps Persian and Arabic-Indic digits to ASCII', () => {
    expect(normalizeNameKey('مقصد ۱۲۳')).toBe('مقصد 123');
    expect(normalizeNameKey('مقصد ١٢٣')).toBe('مقصد 123');
    expect(normalizeNameKey('مقصد 123')).toBe('مقصد 123');
    expect(normalizeNameKey('۱۲۳٤٥٦')).toBe('123456');
  });

  it('treats ZWNJ as a space and collapses whitespace', () => {
    const expected = 'سالن ها';
    expect(normalizeNameKey('سالن‌ها')).toBe(expected);
    expect(normalizeNameKey('  سالن \t\n ها  ')).toBe(expected);
    expect(normalizeNameKey('سالن‌ها')).toBe(normalizeNameKey('سالن ها'));
  });

  it('folds Arabic yeh/kaf into the Persian forms', () => {
    expect(normalizeNameKey('كريمان')).toBe('کریمان');
    expect(normalizeNameKey('كرمان')).toBe(normalizeNameKey('کرمان'));
  });

  it('normalizes Unicode composition (NFC)', () => {
    expect(normalizeNameKey('Café')).toBe('café');
    expect(normalizeNameKey('Café')).toBe('café');
  });

  it('is case-insensitive for Latin text', () => {
    expect(normalizeNameKey('  DePoT  ')).toBe('depot');
    expect(normalizeNameKey('ABC')).toBe(normalizeNameKey('abc'));
  });

  it('returns an empty key when nothing visible remains', () => {
    expect(normalizeNameKey('   ')).toBe('');
    expect(normalizeNameKey('‌')).toBe('');
    expect(normalizeNameKey('‌ ‌')).toBe('');
  });

  it('caps the raw name before normalizing and the key at the column cap', () => {
    const long = `${'x'.repeat(100)}`;
    expect(normalizeNameKey(long)).toHaveLength(NAME_MAX_LENGTH);

    // Lowercasing U+0130 expands to two code points per character; the key
    // must still fit `name_key varchar(64)`.
    const expanding = 'İ'.repeat(NAME_MAX_LENGTH);
    expect(Array.from(normalizeNameKey(expanding)).length).toBeLessThanOrEqual(NAME_MAX_LENGTH);
  });
});

describe('nameInputSchema', () => {
  it.each(['مقصد اصلی', 'ab', '  ab  '])('accepts %j', (value) => {
    expect(nameInputSchema.safeParse(value).success).toBe(true);
  });

  it.each([
    ['too short', 'a'],
    ['too long', 'x'.repeat(NAME_MAX_LENGTH + 1)],
    ['whitespace only', '   '],
    ['ZWNJ only', '‌‌'],
  ])('rejects %s', (_label, value) => {
    expect(nameInputSchema.safeParse(value).success).toBe(false);
  });

  it('rejects a non-string (mass-assignment shape)', () => {
    expect(nameInputSchema.safeParse({ name: 'x' }).success).toBe(false);
  });
});
