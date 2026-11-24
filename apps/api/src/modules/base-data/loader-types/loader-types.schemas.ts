import { z } from 'zod';

import { paginationQuerySchema } from '../../../common/pagination/pagination.js';
import { sortQuerySchema, type SortOptions } from '../../../common/pagination/sort.js';
import { nameInputSchema, nameSearchSchema } from '../../../common/text/name-key.js';
import { expectedVersionSchema } from '../../../common/validation/expected-version.js';
import type { LoaderTypeDto, LoaderTypeGroupDto } from './loader-types.types.js';

export { emptyQuerySchema } from '../../../common/validation/empty-query.js';

/**
 * HTTP contracts for `/api/v1/base/loader-type-groups` and
 * `/api/v1/base/loader-types` (ADR-011 B2/B3/B6, T06). Every object is strict
 * at every level.
 *
 * A loader type's `groupId` is a real, mutable business field — unlike a
 * terminal's hall, it is accepted in the body and can be changed by PATCH
 * (a move). The service resolves it against the live tenant scope, so a
 * missing, deleted or other-tenant group is the same generic 404 as a missing
 * type; only the shape (UUID) is a 400.
 */

export const LOADER_TYPE_GROUP_SORT_FIELDS = ['displayOrder', 'name', 'createdAt'] as const;
export type LoaderTypeGroupSortField = (typeof LOADER_TYPE_GROUP_SORT_FIELDS)[number];

export const loaderTypeGroupSortOptions: SortOptions<LoaderTypeGroupSortField> = {
  allowed: LOADER_TYPE_GROUP_SORT_FIELDS,
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

export const LOADER_TYPE_SORT_FIELDS = ['displayOrder', 'name', 'createdAt'] as const;
export type LoaderTypeSortField = (typeof LOADER_TYPE_SORT_FIELDS)[number];

export const loaderTypeSortOptions: SortOptions<LoaderTypeSortField> = {
  allowed: LOADER_TYPE_SORT_FIELDS,
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

export const loaderTypeGroupListQuerySchema = paginationQuerySchema.extend({
  isActive: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  q: nameSearchSchema.optional(),
  sort: sortQuerySchema(loaderTypeGroupSortOptions),
});

export const loaderTypeListQuerySchema = paginationQuerySchema.extend({
  /** Optional parent filter; the service 404s a missing/deleted/foreign group. */
  groupId: z.uuid().optional(),
  isActive: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  q: nameSearchSchema.optional(),
  sort: sortQuerySchema(loaderTypeSortOptions),
});

export type LoaderTypeGroupListQuery = z.infer<typeof loaderTypeGroupListQuerySchema>;
export type LoaderTypeListQuery = z.infer<typeof loaderTypeListQuerySchema>;

/** `/base/loader-type-groups/:id` and `/base/loader-types/:id` routes. */
export const loaderTypeGroupParamsSchema = z.strictObject({ id: z.uuid() });
export const loaderTypeParamsSchema = z.strictObject({ id: z.uuid() });

export const createLoaderTypeGroupSchema = z.strictObject({
  name: nameInputSchema,
  isActive: z.boolean().default(true),
  displayOrder: z.number().int().min(0).max(9999).default(0),
});

export const updateLoaderTypeGroupSchema = z
  .strictObject({
    name: nameInputSchema.optional(),
    isActive: z.boolean().optional(),
    displayOrder: z.number().int().min(0).max(9999).optional(),
    expectedVersion: expectedVersionSchema,
  })
  .refine(
    (body) =>
      body.name !== undefined || body.isActive !== undefined || body.displayOrder !== undefined,
    { message: 'at least one mutable field is required' },
  );

export const createLoaderTypeSchema = z.strictObject({
  groupId: z.uuid(),
  name: nameInputSchema,
  isActive: z.boolean().default(true),
  displayOrder: z.number().int().min(0).max(9999).default(0),
});

export const updateLoaderTypeSchema = z
  .strictObject({
    /** A move: the service locks the target group FOR UPDATE (AT-11). */
    groupId: z.uuid().optional(),
    name: nameInputSchema.optional(),
    isActive: z.boolean().optional(),
    displayOrder: z.number().int().min(0).max(9999).optional(),
    expectedVersion: expectedVersionSchema,
  })
  .refine(
    (body) =>
      body.groupId !== undefined ||
      body.name !== undefined ||
      body.isActive !== undefined ||
      body.displayOrder !== undefined,
    { message: 'at least one mutable field is required' },
  );

export const deleteQuerySchema = z.strictObject({ expectedVersion: expectedVersionSchema });

export type CreateLoaderTypeGroupInput = z.infer<typeof createLoaderTypeGroupSchema>;
export type UpdateLoaderTypeGroupInput = z.infer<typeof updateLoaderTypeGroupSchema>;
export type CreateLoaderTypeInput = z.infer<typeof createLoaderTypeSchema>;
export type UpdateLoaderTypeInput = z.infer<typeof updateLoaderTypeSchema>;
export type DeleteQuery = z.infer<typeof deleteQuerySchema>;

export interface LoaderTypeGroupListResult {
  readonly data: LoaderTypeGroupDto[];
  readonly meta: { readonly page: number; readonly pageSize: number; readonly total: number };
}

export interface LoaderTypeListResult {
  readonly data: LoaderTypeDto[];
  readonly meta: { readonly page: number; readonly pageSize: number; readonly total: number };
}
