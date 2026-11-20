import { describe, expect, it } from 'vitest';

import { bearerToken } from './bearer.js';

describe('bearerToken', () => {
  it('extracts the token from a well-formed header, scheme case-insensitively', () => {
    expect(bearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi');
    expect(bearerToken('bearer  abc.def.ghi')).toBe('abc.def.ghi');
    // OWS between scheme and credentials is legal (RFC 6750).
    expect(bearerToken('Bearer\tabc')).toBe('abc');
  });

  it('returns null for every malformed shape', () => {
    for (const header of [
      undefined,
      '',
      'Bearer',
      'Bearer ',
      'Basic abc',
      'Token abc',
      'Bearer a b',
      'Bearerabc',
    ]) {
      expect(bearerToken(header), `header ${JSON.stringify(header)}`).toBeNull();
    }
  });

  it('trims surrounding whitespace only', () => {
    expect(bearerToken('  Bearer abc  ')).toBe('abc');
  });
});
