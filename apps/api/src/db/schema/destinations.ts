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
 * One destination = one queue location (PRD §3, BR-01).
 *
 * `name_key` is the server-only B4 comparison key; it is unique per tenant
 * among LIVE rows (partial index). Soft delete only: the runtime role has no
 * DELETE/TRUNCATE (0018). `version` is bumped by the repository CAS, never by
 * a trigger.
 */
export const destinations = pgTable(
  'destinations',
  {
    id: id(),
    tenantId: tenantId(),
    name: varchar('name', { length: 64 }).notNull(),
    nameKey: varchar('name_key', { length: 64 }).notNull(),
    provinceName: varchar('province_name', { length: 64 }),
    isActive: boolean('is_active').notNull().default(true),
    displayOrder: integer('display_order').notNull().default(0),
    version: integer('version').notNull().default(1),
    ...timestamps,
    deletedAt: deletedAt(),
  },
  (t) => [
    check('destinations_name_length', sql`char_length(${t.name}) between 2 and 64`),
    check('destinations_name_key_present', sql`${t.nameKey} <> ''`),
    check('destinations_display_order_range', sql`${t.displayOrder} between 0 and 9999`),
    check('destinations_version_positive', sql`${t.version} >= 1`),
    unique('destinations_tenant_id_uq').on(t.tenantId, t.id),
    uniqueIndex('destinations_tenant_name_key_uq')
      .on(t.tenantId, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('destinations_tenant_list_idx')
      .on(t.tenantId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
  ],
);
