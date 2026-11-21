import { describe, expect, it } from 'vitest';

import { hasForbiddenReasonCharacter, sensitiveReasonSchema } from './sensitive-reason.js';

/**
 * The sensitive-action reason contract (ADR-008 Z10, CP1 SA-02):
 * required, trimmed, 10–500 characters, no C0/C1 controls, zero-width or
 * bidi controls. Persian text and emoji are normal content and must pass.
 */
const PERSIAN = 'دلیل تست شماره یک';

function parse(value: unknown) {
  return sensitiveReasonSchema.safeParse(value);
}

function withCharacter(character: string): string {
  return `${'a'.repeat(5)}${character}${'b'.repeat(5)}`;
}

describe('sensitiveReasonSchema', () => {
  it('accepts Persian text and trims surrounding whitespace', () => {
    const result = parse(`  ${PERSIAN}  `);
    expect(result.success).toBe(true);
    expect(result.success ? result.data : null).toBe(PERSIAN);
  });

  it('accepts emoji and mixed Persian/emoji content within the bounds', () => {
    expect(parse('😀'.repeat(10)).success).toBe(true);
    expect(parse(`${PERSIAN} 😀`).success).toBe(true);
  });

  it('enforces 10–500 characters after trim', () => {
    expect(parse('a'.repeat(9)).success).toBe(false);
    expect(parse('a'.repeat(10)).success).toBe(true);
    expect(parse('a'.repeat(500)).success).toBe(true);
    expect(parse('a'.repeat(501)).success).toBe(false);
    expect(parse(`  ${'a'.repeat(9)}  `).success).toBe(false);
    expect(parse('   ').success).toBe(false);
    expect(parse(undefined).success).toBe(false);
    expect(parse(null).success).toBe(false);
    expect(parse(123).success).toBe(false);
    expect(parse(['a'.repeat(10)]).success).toBe(false);
  });

  it('rejects C0 and C1 control characters anywhere in the text', () => {
    for (const character of [
      '\u0000',
      '\u0008',
      '\u000A',
      '\u001F',
      '\u007F',
      '\u0085',
      '\u009F',
    ]) {
      expect(parse(withCharacter(character)).success, `U+${character.codePointAt(0)}`).toBe(false);
    }
  });

  it('rejects zero-width and bidi control characters (SA-02)', () => {
    const codePoints = [
      0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066,
      0x2067, 0x2068, 0x2069,
    ];
    for (const codePoint of codePoints) {
      const character = String.fromCodePoint(codePoint);
      expect(parse(withCharacter(character)).success, `U+${codePoint.toString(16)}`).toBe(false);
      expect(hasForbiddenReasonCharacter(character)).toBe(true);
    }
  });

  it('rejects a lone surrogate code unit', () => {
    const candidate = `${'a'.repeat(5)}${String.fromCodePoint(0xd800)}${'b'.repeat(5)}`;
    expect(parse(candidate).success).toBe(false);
    expect(hasForbiddenReasonCharacter(String.fromCodePoint(0xd800))).toBe(true);
  });

  it('accepts a normal space-separated Persian sentence', () => {
    expect(parse('دلیل تست شماره یک').success).toBe(true);
  });
});
