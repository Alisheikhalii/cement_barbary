import { sql } from 'drizzle-orm';
import { check, pgTable, uniqueIndex, uuid, varchar } from 'drizzle-orm/pg-core';

import { createdBy, deletedAt, id, timestamps } from './columns.js';

/**
 * A tenant is one factory using the platform. The row IS the tenant, so it has
 * no tenant_id column; RLS on this table (T04) compares `id` to the context.
 */
export const tenants = pgTable(
  'tenants',
  {
    id: id(),
    /** Short slug chosen by the platform admin, e.g. `cement-1` (Assumption A1). */
    code: varchar('code', { length: 32 }).notNull(),
    name: varchar('name', { length: 200 }).notNull(),
    status: varchar('status', { length: 16 }).notNull().default('active'),
    ...timestamps,
    createdBy: createdBy(),
    deletedAt: deletedAt(),
  },
  (t) => [
    uniqueIndex('tenants_code_uq')
      .on(t.code)
      .where(sql`${t.deletedAt} is null`),
    check('tenants_code_format', sql`${t.code} ~ '^[a-z0-9-]{2,32}$'`),
    check('tenants_status_valid', sql`${t.status} in ('active', 'suspended')`),
  ],
);

/**
 * Standard tenant column for every tenant-owned table (ADR-005 D9):
 * `tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT`.
 */
export const tenantId = () =>
  uuid('tenant_id')
    .notNull()
    .references(() => tenants.id, { onDelete: 'restrict' });
