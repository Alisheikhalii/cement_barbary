import { describe, expect, it } from 'vitest';

import { EXPECTED_VERSION_MAX, expectedVersionSchema } from './expected-version.js';

describe('expectedVersionSchema', () => {
  it.each([3, '3', 0, '0', EXPECTED_VERSION_MAX, String(EXPECTED_VERSION_MAX)])(
    'accepts the canonical value %j',
    (value) => {
      expect(expectedVersionSchema.safeParse(value).success).toBe(true);
    },
  );

  it('returns the parsed number for a canonical string', () => {
    expect(expectedVersionSchema.parse('3')).toBe(3);
    expect(expectedVersionSchema.parse(3)).toBe(3);
  });

  it.each([
    ['leading zero', '03'],
    ['all zeros', '00'],
    ['padded', '0003'],
    ['negative string', '-1'],
    ['negative number', -1],
    ['fractional number', 1.5],
    ['fractional string', '1.5'],
    ['trailing space', '3 '],
    ['leading space', ' 3'],
    ['explicit plus', '+3'],
    ['Persian digit', '۳'],
    ['Arabic-Indic digit', '٣'],
    ['empty', ''],
    ['exponent', '1e3'],
    ['hex', '0x10'],
    ['above int4', '2147483648'],
    ['above int4 as number', 2147483648],
    ['unsafe integer string', '9007199254740993'],
    ['unsafe integer number', 2 ** 53],
    ['null', null],
    ['undefined', undefined],
    ['boolean', true],
  ])('rejects %s', (_label, value) => {
    expect(expectedVersionSchema.safeParse(value).success).toBe(false);
  });
});
