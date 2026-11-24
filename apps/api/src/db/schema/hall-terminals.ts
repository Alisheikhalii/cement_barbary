import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { deletedAt, id, timestamps } from './columns.js';
import { halls } from './halls.js';
import { tenantId } from './tenants.js';

/**
 * A terminal belongs to one hall. The composite FK (tenant_id, hall_id) makes
 * a cross-tenant parent impossible at the DB even if the application scope
 * filter were bypassed (B7). A child create/move locks the live parent row
 * FOR UPDATE in the service transaction before inserting (AT-11) — the FK's
 * KEY SHARE lock alone does not block a parent soft delete.
 */
export const hallTerminals = pgTable(
  'hall_terminals',
  {
    id: id(),
    tenantId: tenantId(),
    hallId: uuid('hall_id').notNull(),
    name: varchar('name', { length: 64 }).notNull(),
    nameKey: varchar('name_key', { length: 64 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    displayOrder: integer('display_order').notNull().default(0),
    version: integer('version').notNull().default(1),
    ...timestamps,
    deletedAt: deletedAt(),
  },
  (t) => [
    check('hall_terminals_name_length', sql`char_length(${t.name}) between 2 and 64`),
    check('hall_terminals_name_key_present', sql`${t.nameKey} <> ''`),
    check('hall_terminals_display_order_range', sql`${t.displayOrder} between 0 and 9999`),
    check('hall_terminals_version_positive', sql`${t.version} >= 1`),
    unique('hall_terminals_tenant_id_uq').on(t.tenantId, t.id),
    foreignKey({
      columns: [t.tenantId, t.hallId],
      foreignColumns: [halls.tenantId, halls.id],
      name: 'hall_terminals_hall_fk',
    }).onDelete('restrict'),
    uniqueIndex('hall_terminals_tenant_hall_name_key_uq')
      .on(t.tenantId, t.hallId, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('hall_terminals_tenant_hall_list_idx')
      .on(t.tenantId, t.hallId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
  ],
);
