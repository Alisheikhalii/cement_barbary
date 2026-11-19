import { sql } from 'drizzle-orm';
import { check, pgTable, unique, varchar } from 'drizzle-orm/pg-core';

/**
 * Global role catalog (ADR-006 U1): exactly 6 rows, inserted by a migration
 * (every environment needs them), never by the seed. No tenant_id — this is a
 * platform-owned read-only catalog; the runtime role gets SELECT only (T04).
 *
 * The (code, scope) unique index exists so user_roles can carry a copy of the
 * scope with a composite FK — the mechanism that enforces U4 without a trigger.
 */
export const roles = pgTable(
  'roles',
  {
    code: varchar('code', { length: 32 }).primaryKey(),
    nameFa: varchar('name_fa', { length: 100 }).notNull(),
    scope: varchar('scope', { length: 16 }).notNull(),
    description: varchar('description', { length: 500 }),
  },
  (t) => [
    check('roles_scope_valid', sql`${t.scope} in ('platform', 'tenant', 'carrier', 'driver')`),
    // FK target for user_roles (role_code, role_scope); a PK on code alone is
    // not a valid target for a composite FK, so this pair must be declared.
    // A UNIQUE CONSTRAINT (not a unique index) so it exists inside CREATE
    // TABLE, before the ALTER TABLE statements that add the FKs.
    unique('roles_code_scope_uq').on(t.code, t.scope),
  ],
);
