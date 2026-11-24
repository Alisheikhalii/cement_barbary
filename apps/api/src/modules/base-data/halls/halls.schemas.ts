import { z } from 'zod';

import { paginationQuerySchema } from '../../../common/pagination/pagination.js';
import { sortQuerySchema, type SortOptions } from '../../../common/pagination/sort.js';
import { nameInputSchema, nameSearchSchema } from '../../../common/text/name-key.js';
import { expectedVersionSchema } from '../../../common/validation/expected-version.js';
import type { HallDto, TerminalDto } from './halls.types.js';

export { emptyQuerySchema } from '../../../common/validation/empty-query.js';

/**
 * HTTP contracts for `/api/v1/base/halls` and the nested terminals (ADR-011
 * B2/B3/B6, T05). Every object is strict at every level. A terminal's hall
 * exists ONLY in the path: `hallId` is not accepted in any body.
 */

export const HALL_SORT_FIELDS = ['displayOrder', 'name', 'createdAt'] as const;
export type HallSortField = (typeof HALL_SORT_FIELDS)[number];

export const hallSortOptions: SortOptions<HallSortField> = {
  allowed: HALL_SORT_FIELDS,
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

export const TERMINAL_SORT_FIELDS = ['displayOrder', 'name', 'createdAt'] as const;
export type TerminalSortField = (typeof TERMINAL_SORT_FIELDS)[number];

export const terminalSortOptions: SortOptions<TerminalSortField> = {
  allowed: TERMINAL_SORT_FIELDS,
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

export const hallListQuerySchema = paginationQuerySchema.extend({
  isActive: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  q: nameSearchSchema.optional(),
  sort: sortQuerySchema(hallSortOptions),
});

export const terminalListQuerySchema = paginationQuerySchema.extend({
  isActive: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  q: nameSearchSchema.optional(),
  sort: sortQuerySchema(terminalSortOptions),
});

export type HallListQuery = z.infer<typeof hallListQuerySchema>;
export type TerminalListQuery = z.infer<typeof terminalListQuerySchema>;

/** `/base/halls/:id` routes. */
export const hallParamsSchema = z.strictObject({ id: z.uuid() });
/** `/base/halls/:hallId/terminals...` routes. */
export const hallIdParamsSchema = z.strictObject({ hallId: z.uuid() });
export const terminalParamsSchema = z.strictObject({ hallId: z.uuid(), id: z.uuid() });

export const createHallSchema = z.strictObject({
  name: nameInputSchema,
  isActive: z.boolean().default(true),
  displayOrder: z.number().int().min(0).max(9999).default(0),
});

export const updateHallSchema = z
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

export const createTerminalSchema = z.strictObject({
  name: nameInputSchema,
  isActive: z.boolean().default(true),
  displayOrder: z.number().int().min(0).max(9999).default(0),
});

export const updateTerminalSchema = z
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

export const deleteQuerySchema = z.strictObject({ expectedVersion: expectedVersionSchema });

export type CreateHallInput = z.infer<typeof createHallSchema>;
export type UpdateHallInput = z.infer<typeof updateHallSchema>;
export type CreateTerminalInput = z.infer<typeof createTerminalSchema>;
export type UpdateTerminalInput = z.infer<typeof updateTerminalSchema>;
export type DeleteQuery = z.infer<typeof deleteQuerySchema>;

export interface HallListResult {
  readonly data: HallDto[];
  readonly meta: { readonly page: number; readonly pageSize: number; readonly total: number };
}

export interface TerminalListResult {
  readonly data: TerminalDto[];
  readonly meta: { readonly page: number; readonly pageSize: number; readonly total: number };
}
