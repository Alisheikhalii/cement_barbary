import { describe, expect, it } from 'vitest';

import {
  InvalidSortError,
  parseSort,
  SORT_PARAM_MAX_LENGTH,
  sortQuerySchema,
  type SortOptions,
} from './sort.js';

type Field = 'displayOrder' | 'name' | 'createdAt';

const OPTIONS: SortOptions<Field> = {
  allowed: ['displayOrder', 'name', 'createdAt'],
  default: [
    { field: 'displayOrder', direction: 'asc' },
    { field: 'name', direction: 'asc' },
  ],
};

describe('parseSort', () => {
  it('returns the caller default (as copies) when sort is absent', () => {
    const parsed = parseSort(undefined, OPTIONS);
    expect(parsed).toEqual([
      { field: 'displayOrder', direction: 'asc' },
      { field: 'name', direction: 'asc' },
    ]);
    expect(parsed).not.toBe(OPTIONS.default);
    expect(parsed[0]).not.toBe(OPTIONS.default[0]);
  });

  it('parses ascending, descending and mixed multi-field sorts', () => {
    expect(parseSort('name', OPTIONS)).toEqual([{ field: 'name', direction: 'asc' }]);
    expect(parseSort('-createdAt', OPTIONS)).toEqual([{ field: 'createdAt', direction: 'desc' }]);
    expect(parseSort('displayOrder,-name', OPTIONS)).toEqual([
      { field: 'displayOrder', direction: 'asc' },
      { field: 'name', direction: 'desc' },
    ]);
  });

  it.each([
    ['empty string', ''],
    ['not allowlisted', 'id'],
    ['server-only column', 'tenantId'],
    ['nameKey', 'nameKey'],
    ['version', 'version'],
    ['trailing comma', 'name,'],
    ['leading comma', ',name'],
    ['empty middle segment', 'name,,createdAt'],
    ['doubled minus', '--name'],
    ['explicit plus', '+name'],
    ['duplicate field', 'name,name'],
    ['same field twice', 'name,-name'],
    ['wrong case', 'NAME'],
    ['injection attempt', 'name;drop table users'],
    ['over the length cap', 'x'.repeat(SORT_PARAM_MAX_LENGTH + 1)],
  ])('rejects %s', (_label, raw) => {
    expect(() => parseSort(raw, OPTIONS)).toThrow(InvalidSortError);
  });
});

describe('sortQuerySchema', () => {
  const schema = sortQuerySchema(OPTIONS);

  it('applies the default when the parameter is absent', () => {
    expect(schema.parse(undefined)).toEqual(OPTIONS.default);
  });

  it('parses a valid selection', () => {
    expect(schema.parse('-name')).toEqual([{ field: 'name', direction: 'desc' }]);
  });

  it.each(['id', 'name,', 'name;drop', 'x'.repeat(SORT_PARAM_MAX_LENGTH + 1)])(
    'rejects %j as a 400-able issue',
    (raw) => {
      expect(schema.safeParse(raw).success).toBe(false);
    },
  );

  it('rejects a repeated query key (array) and a non-string', () => {
    expect(schema.safeParse(['name', 'createdAt']).success).toBe(false);
    expect(schema.safeParse(3).success).toBe(false);
  });
});
