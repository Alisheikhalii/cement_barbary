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
- `roles` — global read-only role catalog (3 roles; trimmed from 6 in
  `0004_role_catalog_trim`, T05b); `bitabar_app` has SELECT only
  (INSERT/UPDATE/DELETE revoked in `0003_users_roles_rls`).
- `auth_rate_limits` — global fixed-window security counters (ADR-007 A11/A16):
  the bucket lives inside the key (`login:ip:…`, `login:tenant:…`), so the
  table has no `tenant_id` and cannot be tenant-owned. It holds **no account
  PII**; the only network-derived value is the IP bucket key itself, a
  transient counter swept at TTL. DELETE stays granted for the sweep.
  **Key hygiene:** a bucket key must never embed a raw phone number or raw
  username — any future account-dimension key is built from a hashed
  identifier (the tenant blind index for phones, a SHA-256 of the
  `tenant:username` pair), because the row outlives the TTL sweep target and
  the key text is not covered by pino redaction. `rateLimitKeys` is the only
  place key shapes are defined; the shape test lands with the first
  account-dimension key (T07, recorded in the T05 report).

Tenant-owned (template above): `users`, `user_roles`, `user_credentials`,
`auth_sessions`.

Special write rules:

- `users` is **soft-delete only** (ADR-006 U13): DELETE is revoked from
  `bitabar_app`; the app sets `deleted_at`. `user_roles` keeps DELETE (role
  revocation).
- `user_credentials` is **update-only**: credentials follow the user's
  soft-delete and are never hard-deleted; DELETE revoked (`0006_auth_rls`).
- `auth_sessions` is **soft-revoke only** (ADR-007 A9): sessions die via
  `revoked_at`, never DELETE (revoked in `0006_auth_rls`); a future purge of
  expired rows runs as the migration owner (recorded debt).

Any new table must either carry `tenant_id` + this template or be added to the
allowlist above with a reason — otherwise the guard test fails.

## The single RLS crossing: auth lookup functions (ADR-007 A17)

Pre-auth login has no tenant context, so the SECURITY DEFINER functions in
migration `0007_auth_lookup_functions` are the **only** way to read across RLS
without a context: `app.list_tenants()`, `app.auth_lookup_username(...)`,
`app.auth_lookup_phone(pairs jsonb)` and — added for the opaque-refresh design
of A8, flagged to the owner at the T03+T04 checkpoint —
`app.auth_lookup_session(refresh_hash hex)`, which resolves the refresh cookie
to its session (and flags rotated-token reuse). Rules that any future crossing
must also follow:

- owned by the migration owner; `SET search_path = pg_catalog, pg_temp`; every
  table reference schema-qualified (`public.…`) so a temp-table shadow cannot
  hijack it;
- static SQL only — no dynamic SQL;
- minimal result columns (no PII, no ciphertext beyond `password_hash`, which
  is the lookup's purpose);
- `EXECUTE` revoked from PUBLIC, granted to `bitabar_app` only;
- unknown tenant / user / phone all return the **identical empty result** —
  enforced by `test/auth-lookup.int.test.ts` (owner condition 4).

> **Table recreation warning:** REVOKEs, RLS and policies do NOT survive a
> drop/recreate — `ALTER DEFAULT PRIVILEGES` would silently re-grant full DML
> (including DELETE on `users`). Any migration that recreates `users`,
> `user_roles` or `roles` must re-apply 0003's REVOKE/ENABLE/policy statements.
> The privilege-matrix test and the U14 guard fail CI if this is forgotten.
