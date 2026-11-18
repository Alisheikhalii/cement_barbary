import { pgTable } from 'drizzle-orm/pg-core';
import { validate, version } from 'uuid';
import { describe, expect, it } from 'vitest';

import { id } from './columns.js';

const probe = pgTable('probe', { id: id() });

function defaultId(): string {
  const fn = probe.id.defaultFn;
  if (!fn) throw new Error('id column has no default function');
  const value: unknown = fn();
  if (typeof value !== 'string') throw new Error('id default is not a string');
  return value;
}

describe('schema column helpers', () => {
  it('generates UUID version 7 primary keys by default', () => {
    const value = defaultId();
    expect(validate(value)).toBe(true);
    expect(version(value)).toBe(7);
  });

  it('generates ids that sort in creation order', async () => {
    const first = defaultId();
    // v7 is time-ordered per millisecond; wait so the timestamps differ.
    await new Promise((resolve) => setTimeout(resolve, 10));
    const second = defaultId();
    expect(first < second).toBe(true);
  });
});
