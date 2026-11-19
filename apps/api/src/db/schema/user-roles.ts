import { sql } from 'drizzle-orm';
import { check, foreignKey, pgTable, primaryKey, uuid, varchar } from 'drizzle-orm/pg-core';

import { roles } from './roles.js';
import { tenantId } from './tenants.js';
import { users } from './users.js';

/**
 * Which roles a user holds (ADR-006 U5). Tenant-owned, RLS in T04. Hard delete
 * is allowed (revoking a role, U13).
 *
 * U4 without a trigger: role_scope carries a copy of roles.scope bound by the
 * composite FK (role_code, role_scope) -> roles(code, scope), so the scope can
 * never be forged; the CHECK then keeps every platform-scoped role out.
 * The composite FK (tenant_id, user_id) -> users(tenant_id, id) makes a link
 * to another tenant's user impossible, even for the migration owner.
 */
export const userRoles = pgTable(
  'user_roles',
  {
    tenantId: tenantId(),
    userId: uuid('user_id').notNull(),
    roleCode: varchar('role_code', { length: 32 }).notNull(),
    roleScope: varchar('role_scope', { length: 16 }).notNull(),
  },
  (t) => [
    // U5: one row per (tenant, user, role); leads with tenant_id.
    primaryKey({ columns: [t.tenantId, t.userId, t.roleCode], name: 'user_roles_pk' }),
    foreignKey({
      columns: [t.tenantId, t.userId],
      foreignColumns: [users.tenantId, users.id],
      name: 'user_roles_user_fk',
    }),
    foreignKey({
      columns: [t.roleCode, t.roleScope],
      foreignColumns: [roles.code, roles.scope],
      name: 'user_roles_role_fk',
    }),
    check('user_roles_no_platform', sql`${t.roleScope} <> 'platform'`),
  ],
);
