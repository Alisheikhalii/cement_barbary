import { z } from 'zod';

/**
 * B6/R5 optimistic-concurrency input. `expectedVersion` is the version the
 * operator loaded; it travels in a PATCH body or a DELETE query string.
 *
 * Only a canonical spelling is accepted:
 *   - a JSON number that is an integer, or a decimal string with no sign,
 *     no leading zeros, no whitespace and no exponent (`'3'`, not `'03'`,
 *     `'+3'`, `'3 '` or `'1e3'`);
 *   - `0 ≤ value ≤ 2 147 483 647` (the column is PostgreSQL `int4`).
 *
 * Canonicality matters because the DELETE query is part of the idempotency
 * fingerprint (R5): `'3'` and `'03'` must never be two different keys for the
 * same intent. A non-canonical value is a 400, not a silent rewrite.
 */
export const EXPECTED_VERSION_MAX = 2_147_483_647;

const CANONICAL_INTEGER = /^(0|[1-9]\d*)$/;

export const expectedVersionSchema = z.preprocess(
  (value) => (typeof value === 'string' && CANONICAL_INTEGER.test(value) ? Number(value) : value),
  z.number().int().min(0).max(EXPECTED_VERSION_MAX),
);

export type ExpectedVersion = z.infer<typeof expectedVersionSchema>;
