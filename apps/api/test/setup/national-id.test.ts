import { describe, expect, it } from 'vitest';

import { normalizeNationalId } from '../../src/security/pii/normalize.js';
import { randomNationalId } from './national-id.js';

describe('randomNationalId (test helper)', () => {
  it('generates values that pass the real validation', () => {
    for (let i = 0; i < 50; i += 1) {
      const id = randomNationalId();
      expect(normalizeNationalId(id)).toBe(id);
    }
  });

  it('does not return all-identical digits', () => {
    for (let i = 0; i < 50; i += 1) {
      expect(/^(\d)\1{9}$/.test(randomNationalId())).toBe(false);
    }
  });
});
