import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  index,
  integer,
  pgTable,
  unique,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/pg-core';

import { deletedAt, id, timestamps } from './columns.js';
import { tenantId } from './tenants.js';

/**
 * A hall inside a tenant; terminals are its live children (B5).
 *
 * The soft-delete guard (AT-11) is application code: the service locks this row
 * FOR UPDATE before checking for live terminals, and a child create/move locks
 * the same row first. The composite FK on `hall_terminals` only enforces
 * existence and tenant match — its KEY SHARE lock does not conflict with a
 * soft-delete UPDATE.
 */
export const halls = pgTable(
  'halls',
  {
    id: id(),
    tenantId: tenantId(),
    name: varchar('name', { length: 64 }).notNull(),
    nameKey: varchar('name_key', { length: 64 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    displayOrder: integer('display_order').notNull().default(0),
    version: integer('version').notNull().default(1),
    ...timestamps,
    deletedAt: deletedAt(),
  },
  (t) => [
    check('halls_name_length', sql`char_length(${t.name}) between 2 and 64`),
    check('halls_name_key_present', sql`${t.nameKey} <> ''`),
    check('halls_display_order_range', sql`${t.displayOrder} between 0 and 9999`),
    check('halls_version_positive', sql`${t.version} >= 1`),
    unique('halls_tenant_id_uq').on(t.tenantId, t.id),
    uniqueIndex('halls_tenant_name_key_uq')
      .on(t.tenantId, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('halls_tenant_list_idx')
      .on(t.tenantId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
  ],
);
