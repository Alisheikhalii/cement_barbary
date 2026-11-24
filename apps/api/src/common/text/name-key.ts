import { z } from 'zod';

import { isStorableText } from './storable-text.js';

/**
 * B4 name normalization for the operator-managed base data (destinations,
 * halls, terminals, loader-type groups and loader types).
 *
 * `name` is what the operator typed; `name_key` is the server-only comparison
 * key behind the per-tenant partial UNIQUE index. The key is never displayed
 * and never accepted from a client (`.strict()` schemas exclude it).
 *
 * Steps, in this order:
 *   1. cap the RAW value at 64 code points (B2: `name` is 2–64);
 *   2. NFC (a decomposed `e` + U+0301 and the precomposed `é` are one name);
 *   3. ZWNJ → space, then collapse all whitespace runs and trim;
 *   4. Arabic yeh/kaf (ي/ك) → Persian ی/ک;
 *   5. Persian (۰–۹) and Arabic-Indic (٠–٩) digits → ASCII digits;
 *   6. lowercase.
 *
 * The result is capped again at 64 code points: lowercasing can expand a few
 * characters (`İ` → `i` + U+0307), and the `name_key varchar(64)` column counts
 * characters, not UTF-16 units. Cap-before-normalize means a caller that skips
 * the input schema cannot make the inserted key longer than the column.
 */
export const NAME_MIN_LENGTH = 2;
export const NAME_MAX_LENGTH = 64;

const ZWNJ = '‌';
const ARABIC_YEH = 'ي';
const ARABIC_KAF = 'ك';
const PERSIAN_YEH = 'ی';
const PERSIAN_KAF = 'ک';

function capped(value: string): string {
  return Array.from(value).slice(0, NAME_MAX_LENGTH).join('');
}

export function normalizeNameKey(raw: string): string {
  const normalized = capped(raw)
    .normalize('NFC')
    .replaceAll(ZWNJ, ' ')
    .replaceAll(ARABIC_YEH, PERSIAN_YEH)
    .replaceAll(ARABIC_KAF, PERSIAN_KAF)
    .replace(/[۰-۹]/g, (digit) => String(digit.charCodeAt(0) - 0x06f0))
    .replace(/[٠-٩]/g, (digit) => String(digit.charCodeAt(0) - 0x0660))
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
  return capped(normalized);
}

/**
 * The shared `name` field schema (B2). The length cap applies to the RAW name
 * before normalization; the refinement rejects a name that only consists of
 * whitespace/ZWNJ, which would otherwise produce `name_key = ''` and hit the
 * DB CHECK as a 500 instead of a 400.
 */
export const nameInputSchema = z
  .string()
  .min(NAME_MIN_LENGTH)
  .max(NAME_MAX_LENGTH)
  .refine(isStorableText, {
    message: 'name contains characters that cannot be stored',
  })
  .refine((value) => normalizeNameKey(value) !== '', {
    message: 'name must contain at least one visible character',
  });

export type NameInput = z.infer<typeof nameInputSchema>;

/**
 * The shared `q` search contract (B3/T04): raw length 1–64, storable text, and
 * at least one visible character after normalization. The caller normalizes
 * and LIKE-escapes before querying `name_key`.
 */
export const nameSearchSchema = z
  .string()
  .min(1)
  .max(NAME_MAX_LENGTH)
  .refine(isStorableText, { message: 'q contains unstorable characters' })
  .refine((value) => normalizeNameKey(value) !== '', {
    message: 'q must contain at least one visible character',
  });
