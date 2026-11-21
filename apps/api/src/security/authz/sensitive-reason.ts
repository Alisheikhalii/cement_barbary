import { z } from 'zod';

/**
 * The `reason` contract for sensitive actions (ADR-008 Z10, CP1 SA-02).
 * Guards run before pipes, so the route scan cannot rely on the pipe alone:
 * it inspects the body schema's `reason` field and proves this exact contract
 * (required, trimmed, 10–500 characters, no C0/C1 controls, zero-width
 * characters or bidi controls).
 *
 * F1-08 sensitive endpoints reuse this schema inside their strict body schema.
 */

/**
 * C0/C1, zero-width, bidi-control and lone-surrogate ranges. Exported so the
 * boot scan can sample the complete set instead of a few representatives.
 */
export const FORBIDDEN_REASON_RANGES: readonly (readonly [number, number])[] = Object.freeze([
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2066, 0x2069],
  [0xd800, 0xdfff],
]);

/** True when the text contains any forbidden control/zero-width/bidi point. */
export function hasForbiddenReasonCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) {
      continue;
    }
    if (FORBIDDEN_REASON_RANGES.some(([start, end]) => codePoint >= start && codePoint <= end)) {
      return true;
    }
  }
  return false;
}

export const sensitiveReasonSchema = z
  .string()
  .trim()
  .min(10)
  .max(500)
  .refine((value) => !hasForbiddenReasonCharacter(value), {
    message: 'must not contain control, zero-width or bidi characters',
  });
