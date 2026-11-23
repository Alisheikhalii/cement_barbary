import { DEFAULT_PAGE_SIZE } from '@bitabar/shared';
import { z } from 'zod';

/**
 * B3 pagination contract for every base-data list endpoint.
 *
 * The schema is strict: an unknown query key is a 400 (AT-04 query level).
 * Resource schemas extend it with their own filters (`isActive`, `q`, `sort`,
 * `groupId`); `extend()` keeps the strictness, so the combined schema still
 * rejects server-only keys such as `tenantId`, `nameKey` or `version`.
 *
 * `pageSize` is capped at 100 so one request cannot force the API to build an
 * unbounded response.
 */
export const PAGE_SIZE_MAX = 100;

export const paginationQuerySchema = z.strictObject({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(PAGE_SIZE_MAX).default(DEFAULT_PAGE_SIZE),
});

export type PaginationQuery = z.infer<typeof paginationQuerySchema>;

export interface PaginationMeta {
  readonly page: number;
  readonly pageSize: number;
  readonly total: number;
}

/** SQL OFFSET for the request; always a non-negative safe integer. */
export function paginationOffset(query: PaginationQuery): number {
  return (query.page - 1) * query.pageSize;
}

/** The `meta` object accepted by the response envelope `{data, meta}`. */
export function paginationMeta(query: PaginationQuery, total: number): PaginationMeta {
  return { page: query.page, pageSize: query.pageSize, total };
}
