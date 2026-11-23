import { describe, expect, it } from 'vitest';

import { escapeLike, likeContains } from './like.js';

describe('escapeLike', () => {
  it('escapes percent, underscore and backslash', () => {
    expect(escapeLike('100%')).toBe('100\\%');
    expect(escapeLike('a_b')).toBe('a\\_b');
    expect(escapeLike('c:\\temp')).toBe('c:\\\\temp');
    expect(escapeLike('%_\\')).toBe('\\%\\_\\\\');
    expect(escapeLike('a%b_c\\d')).toBe('a\\%b\\_c\\\\d');
  });

  it('leaves ordinary Persian and Latin text unchanged', () => {
    expect(escapeLike('مقصد اصلی')).toBe('مقصد اصلی');
    expect(escapeLike('destination 1')).toBe('destination 1');
  });
});

describe('likeContains', () => {
  it('wraps the escaped term in contains wildcards', () => {
    expect(likeContains('50%')).toBe('%50\\%%');
    expect(likeContains('سالن')).toBe('%سالن%');
  });

  it('cannot smuggle an unescaped wildcard', () => {
    expect(likeContains('%')).toBe('%\\%%');
    expect(likeContains('_')).toBe('%\\_%');
  });
});
