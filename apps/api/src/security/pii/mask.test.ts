import { describe, expect, it } from 'vitest';

import { maskNationalId, maskPhone } from './mask.js';

describe('maskPhone', () => {
  it('masks a canonical phone to 0912***6789 shape', () => {
    expect(maskPhone('09120000001')).toBe('0912***0001');
  });

  it('fully hides non-canonical input', () => {
    expect(maskPhone('not-a-phone')).toBe('***********');
    expect(maskPhone('')).toBe('***********');
  });
});

describe('maskNationalId', () => {
  it('keeps only the last 4 digits', () => {
    expect(maskNationalId('0049584243')).toBe('******4243');
  });

  it('fully hides short input', () => {
    expect(maskNationalId('123')).toBe('**********');
  });
});
