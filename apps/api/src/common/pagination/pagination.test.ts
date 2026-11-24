import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  PAGE_MAX,
  PAGE_SIZE_MAX,
  paginationMeta,
  paginationOffset,
  paginationQuerySchema,
} from './pagination.js';

describe('paginationQuerySchema', () => {
  it('defaults to page 1 and pageSize 50', () => {
    expect(paginationQuerySchema.parse({})).toEqual({ page: 1, pageSize: 50 });
  });

  it('coerces query strings and accepts the 1–100 bounds', () => {
    expect(paginationQuerySchema.parse({ page: '2', pageSize: '1' })).toEqual({
      page: 2,
      pageSize: 1,
    });
    expect(paginationQuerySchema.parse({ pageSize: String(PAGE_SIZE_MAX) }).pageSize).toBe(
      PAGE_SIZE_MAX,
    );
  });

  it.each([
    ['page 0', { page: '0' }],
    ['negative page', { page: '-1' }],
    ['fractional page', { page: '1.5' }],
    ['non-numeric page', { page: 'abc' }],
    ['page beyond the safe OFFSET bound', { page: String(PAGE_MAX + 1) }],
    ['pageSize 0', { pageSize: '0' }],
    ['pageSize 101', { pageSize: String(PAGE_SIZE_MAX + 1) }],
    ['fractional pageSize', { pageSize: '10.5' }],
    ['repeated page', { page: ['1', '2'] }],
  ])('rejects %s', (_label, query) => {
    expect(paginationQuerySchema.safeParse(query).success).toBe(false);
  });

  it('rejects an unknown query key and keeps that rejection after extend()', () => {
    expect(paginationQuerySchema.safeParse({ tenantId: 'x' }).success).toBe(false);
    const extended = paginationQuerySchema.extend({ q: z.string().optional() });
    expect(extended.safeParse({ q: 'x' }).success).toBe(true);
    expect(extended.safeParse({ tenantId: 'x' }).success).toBe(false);
    expect(extended.safeParse({ nameKey: 'x' }).success).toBe(false);
  });
});

describe('paginationMeta / paginationOffset', () => {
  it('builds the envelope meta', () => {
    expect(paginationMeta({ page: 2, pageSize: 50 }, 120)).toEqual({
      page: 2,
      pageSize: 50,
      total: 120,
    });
  });

  it('computes the SQL offset', () => {
    expect(paginationOffset({ page: 1, pageSize: 50 })).toBe(0);
    expect(paginationOffset({ page: 3, pageSize: 20 })).toBe(40);
  });
});
