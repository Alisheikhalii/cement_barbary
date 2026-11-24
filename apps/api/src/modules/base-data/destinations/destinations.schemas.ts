import { z } from 'zod';

import { paginationQuerySchema } from '../../../common/pagination/pagination.js';
import { sortQuerySchema, type SortOptions } from '../../../common/pagination/sort.js';
import { nameInputSchema, normalizeNameKey } from '../../../common/text/name-key.js';
import { isStorableText } from '../../../common/text/storable-text.js';
import { expectedVersionSchema } from '../../../common/validation/expected-version.js';
import type { DestinationDto } from './destinations.types.js';

/**
 * HTTP contracts for `/api/v1/base/destinations` (ADR-011 B2/B3/B6, T04).
 *
 * Every object is strict at every level; `@ZodBody`/`@ZodQuery`/`@ZodParams`
 * record them for the mass-assignment scan. Server-only columns (`id`,
 * `tenantId`, `nameKey`, `version`, timestamps, `deletedAt`) are not in any
 * shape, so they are rejected as unknown keys.
 */

export const DESTINATION_SORT_FIELDS = ['displayOrder', 'name', 'createdAt'] as const;

export type DestinationSortField = (typeof DESTINATION_SORT_FIELDS)[number];

/** B3: default order is displayOrder then name; `id` is the repository tiebreak. */
export const destinationSortOptions: SortOptions<DestinationSortField> = {
  allowed: DESTINATION_SORT_FIELDS,
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

/** Optional province display name; the same storable-text rule as `name`. */
const provinceNameSchema = z
  .string()
  .max(64)
  .refine(isStorableText, { message: 'provinceName contains unstorable characters' });

/** `q` is normalized before the LIKE; a name that normalizes to '' cannot match anything. */
const searchSchema = z
  .string()
  .min(1)
  .max(64)
  .refine(isStorableText, { message: 'q contains unstorable characters' })
  .refine((value) => normalizeNameKey(value) !== '', {
    message: 'q must contain at least one visible character',
  });

export const destinationListQuerySchema = paginationQuerySchema.extend({
  isActive: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  q: searchSchema.optional(),
  sort: sortQuerySchema(destinationSortOptions),
});

export type DestinationListQuery = z.infer<typeof destinationListQuerySchema>;

export const destinationIdParamsSchema = z.strictObject({ id: z.uuid() });

/** Routes that take no query string: an unknown key is a 400, not silently ignored. */
export const emptyQuerySchema = z.strictObject({});

export const createDestinationSchema = z.strictObject({
  name: nameInputSchema,
  provinceName: provinceNameSchema.optional(),
  isActive: z.boolean().default(true),
  displayOrder: z.number().int().min(0).max(9999).default(0),
});

export type CreateDestinationInput = z.infer<typeof createDestinationSchema>;

export const updateDestinationSchema = z
  .strictObject({
    name: nameInputSchema.optional(),
    provinceName: provinceNameSchema.optional(),
    isActive: z.boolean().optional(),
    displayOrder: z.number().int().min(0).max(9999).optional(),
    expectedVersion: expectedVersionSchema,
  })
  .refine(
    (body) =>
      body.name !== undefined ||
      body.provinceName !== undefined ||
      body.isActive !== undefined ||
      body.displayOrder !== undefined,
    { message: 'at least one mutable field is required' },
  );

export type UpdateDestinationInput = z.infer<typeof updateDestinationSchema>;

/** B6/R5: DELETE carries only the canonical expected version in the query string. */
export const deleteDestinationQuerySchema = z.strictObject({
  expectedVersion: expectedVersionSchema,
});

export type DeleteDestinationQuery = z.infer<typeof deleteDestinationQuerySchema>;

export interface DestinationListResult {
  readonly data: DestinationDto[];
  readonly meta: { readonly page: number; readonly pageSize: number; readonly total: number };
}
