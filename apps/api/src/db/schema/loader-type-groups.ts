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
 * A loader-type group (BR-06); loader types reference it. Soft delete is
 * guarded in application code exactly like halls (AT-11): the service locks
 * this row FOR UPDATE before checking for live types, and a type create/move
 * locks the same row first.
 */
export const loaderTypeGroups = pgTable(
  'loader_type_groups',
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
    check('loader_type_groups_name_length', sql`char_length(${t.name}) between 2 and 64`),
    check('loader_type_groups_name_key_present', sql`${t.nameKey} <> ''`),
    check('loader_type_groups_display_order_range', sql`${t.displayOrder} between 0 and 9999`),
    check('loader_type_groups_version_positive', sql`${t.version} >= 1`),
    unique('loader_type_groups_tenant_id_uq').on(t.tenantId, t.id),
    uniqueIndex('loader_type_groups_tenant_name_key_uq')
      .on(t.tenantId, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('loader_type_groups_tenant_list_idx')
      .on(t.tenantId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
  ],
);
