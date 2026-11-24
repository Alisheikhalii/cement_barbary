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
import { loaderTypeGroups } from './loader-type-groups.js';
import { tenantId } from './tenants.js';

/**
 * Loader types are data, not an enum (BR-06). The name is unique per tenant
 * (not per group): a type name means one vehicle class. The composite FK pins
 * the group to the same tenant (B7); a create/move locks the live group row
 * FOR UPDATE in the service transaction before writing (AT-11).
 */
export const loaderTypes = pgTable(
  'loader_types',
  {
    id: id(),
    tenantId: tenantId(),
    groupId: uuid('group_id').notNull(),
    name: varchar('name', { length: 64 }).notNull(),
    nameKey: varchar('name_key', { length: 64 }).notNull(),
    isActive: boolean('is_active').notNull().default(true),
    displayOrder: integer('display_order').notNull().default(0),
    version: integer('version').notNull().default(1),
    ...timestamps,
    deletedAt: deletedAt(),
  },
  (t) => [
    check('loader_types_name_length', sql`char_length(${t.name}) between 2 and 64`),
    check('loader_types_name_key_present', sql`${t.nameKey} <> ''`),
    check('loader_types_display_order_range', sql`${t.displayOrder} between 0 and 9999`),
    check('loader_types_version_positive', sql`${t.version} >= 1`),
    unique('loader_types_tenant_id_uq').on(t.tenantId, t.id),
    foreignKey({
      columns: [t.tenantId, t.groupId],
      foreignColumns: [loaderTypeGroups.tenantId, loaderTypeGroups.id],
      name: 'loader_types_group_fk',
    }).onDelete('restrict'),
    uniqueIndex('loader_types_tenant_name_key_uq')
      .on(t.tenantId, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('loader_types_tenant_list_idx')
      .on(t.tenantId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
    index('loader_types_tenant_group_list_idx')
      .on(t.tenantId, t.groupId, t.displayOrder, t.nameKey)
      .where(sql`${t.deletedAt} is null`),
  ],
);
