# Row-Level Security (RLS) — tenant isolation at the database

Status: active since F1-02 | Decisions: ADR-005 (`docs/adr/005-database-drizzle-rls.md`)

The database is the second isolation layer (the app layer is `TenantDb`). If
application code ever forgets a `WHERE tenant_id = ...`, PostgreSQL still hides
other tenants' rows. The app connects only as `bitabar_app`: `NOSUPERUSER`,
`NOBYPASSRLS`, not a table owner, DML grants only. RLS does not apply to
superusers or table owners, which is exactly why the app must never be one.

## Policy template (apply to EVERY tenant-owned table)

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
CREATE POLICY <t>_tenant_isolation ON <t> FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
```

The subselect wrapping makes the planner evaluate the context function once per
query. `app.current_tenant_id()` reads the transaction-local setting
`app.tenant_id` and returns NULL when it is missing — so with no context,
policies match zero rows and `WITH CHECK` rejects writes (fail closed,
ADR-005 D6). Both context functions are pinned to
`SET search_path = pg_catalog, pg_temp` so their bodies cannot be hijacked by
objects in other schemas.

`FORCE ROW LEVEL SECURITY` is intentionally not used: the schema owner exists
only to run migrations, and the app never connects as owner.

## How to add RLS to a new table

1. Define the table in `apps/api/src/db/schema/` using the standard helpers
   (`id()`, `tenantId()`, `timestamps`, …) and an index leading with `tenant_id`.
2. Run `pnpm --filter @bitabar/api db:generate` for the table DDL.
3. Run `pnpm --filter @bitabar/api db:generate --custom --name=rls_<table>` and
   fill the file with the template above (replace `<t>`).
4. Add a probe of the table's isolation to `apps/api/test/rls.int.test.ts`.

Grants for new tables come from `ALTER DEFAULT PRIVILEGES` (set in migration
`0001_rls_foundation`), so no extra `GRANT` statements are needed as long as
migrations run as the schema owner.

## Table inventory and the U14 allowlist

Global tables (no `tenant_id`, each with a written reason — ADR-006 U14):

- `tenants` — platform-owned tenant registry; the row IS the tenant, RLS
  compares `id` to the context (F1-02).
- `roles` — global read-only role catalog; `bitabar_app` has SELECT only
  (INSERT/UPDATE/DELETE revoked in `0003_users_roles_rls`).

Tenant-owned (template above): `users`, `user_roles`.

Special write rules:

- `users` is **soft-delete only** (ADR-006 U13): DELETE is revoked from
  `bitabar_app`; the app sets `deleted_at`. `user_roles` keeps DELETE (role
  revocation).

Any new table must either carry `tenant_id` + this template or be added to the
allowlist above with a reason — otherwise the guard test fails.

> **Table recreation warning:** REVOKEs, RLS and policies do NOT survive a
> drop/recreate — `ALTER DEFAULT PRIVILEGES` would silently re-grant full DML
> (including DELETE on `users`). Any migration that recreates `users`,
> `user_roles` or `roles` must re-apply 0003's REVOKE/ENABLE/policy statements.
> The privilege-matrix test and the U14 guard fail CI if this is forgotten.
