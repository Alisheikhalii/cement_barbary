import { z } from 'zod';

/**
 * B3 sort contract. The client sends a comma-separated allowlist selection,
 * each field optionally prefixed with `-` for descending:
 *
 *   `?sort=displayOrder,-name`
 *
 * Unknown fields, duplicate fields, empty segments, `+`, a doubled `-`, and
 * anything over the length cap are rejected — never silently ignored. The
 * per-resource allowlist and the default order are supplied by the caller, so
 * a resource can never be sorted by a column it did not opt into (for example
 * `tenantId`, `nameKey` or `version`). `id` as the final tiebreak is added by
 * the repository, not accepted from the client.
 */
export const SORT_PARAM_MAX_LENGTH = 200;

export type SortDirection = 'asc' | 'desc';

export interface SortField<TField extends string> {
  readonly field: TField;
  readonly direction: SortDirection;
}

export interface SortOptions<TField extends string> {
  readonly allowed: readonly TField[];
  /** Applied when `sort` is absent. Returned as copies, never shared. */
  readonly default: readonly SortField<TField>[];
}

export class InvalidSortError extends Error {
  constructor(readonly reason: 'length' | 'field' | 'duplicate') {
    super(`INVALID_SORT_${reason.toUpperCase()}`);
    this.name = 'InvalidSortError';
  }
}

export function parseSort<TField extends string>(
  raw: string | undefined,
  options: SortOptions<TField>,
): SortField<TField>[] {
  if (raw === undefined) {
    return options.default.map((field) => ({ ...field }));
  }
  if (raw.length === 0 || raw.length > SORT_PARAM_MAX_LENGTH) {
    throw new InvalidSortError('length');
  }
  const allowed = new Set<string>(options.allowed);
  const seen = new Set<string>();
  return raw.split(',').map((segment) => {
    const direction: SortDirection = segment.startsWith('-') ? 'desc' : 'asc';
    const field = direction === 'desc' ? segment.slice(1) : segment;
    if (!allowed.has(field)) {
      throw new InvalidSortError('field');
    }
    if (seen.has(field)) {
      throw new InvalidSortError('duplicate');
    }
    seen.add(field);
    return { field: field as TField, direction };
  });
}

/**
 * Zod wrapper for `@ZodQuery`: an invalid sort is a 400 with a generic issue,
 * and an absent `sort` yields the caller's default. The raw string is only
 * accepted as a string (a repeated query key arrives as an array and fails).
 */
export function sortQuerySchema<TField extends string>(
  options: SortOptions<TField>,
): z.ZodType<SortField<TField>[]> {
  return z
    .string()
    .max(SORT_PARAM_MAX_LENGTH)
    .optional()
    .transform((raw, ctx) => {
      try {
        return parseSort(raw, options);
      } catch (error) {
        // Only an invalid client string is a 400. A future parser bug must
        // surface as an error, not be laundered into a validation issue.
        if (!(error instanceof InvalidSortError)) {
          throw error;
        }
        ctx.addIssue({ code: 'custom', message: 'invalid sort parameter' });
        return z.NEVER;
      }
    });
}
