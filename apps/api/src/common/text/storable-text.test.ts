import { describe, expect, it } from 'vitest';

import { isStorableText } from './storable-text.js';

describe('isStorableText', () => {
  it('accepts ordinary text, Persian, emoji pairs and empty strings', () => {
    expect(isStorableText('')).toBe(true);
    expect(isStorableText('Destinations')).toBe(true);
    expect(isStorableText('مقصد اصلی')).toBe(true);
    expect(isStorableText('😀 pair')).toBe(true);
  });

  it('rejects NUL, which PostgreSQL cannot store in text', () => {
    expect(isStorableText('ab\u0000cd')).toBe(false);
    expect(isStorableText('\u0000')).toBe(false);
  });

  it('rejects unpaired surrogates but accepts a complete pair', () => {
    expect(isStorableText('ab\uD800cd')).toBe(false);
    expect(isStorableText('ab\uDC00cd')).toBe(false);
    expect(isStorableText('ab😀cd')).toBe(true);
  });
});
