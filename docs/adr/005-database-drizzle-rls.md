# ADR-005: Database stack, migrations and tenant isolation (Drizzle + PostgreSQL RLS)

2026-11-18 | Accepted

**Context:** F1-02 adds the database layer. BitaBar is multi-tenant: one deployment serves several factories (`tenants`), and a forgotten `WHERE tenant_id = ...` in application code must never leak one tenant's data to another (GUIDELINES §4, §6.2 IDOR). The ORM is already decided by the owner: **Drizzle** (AGENT.md §3, PRD §8 allows Prisma or Drizzle). Two decisions were owner-approved on 2026-11-18: two layers of tenant isolation (app filter + RLS), and forward-only migrations with a pre-deploy backup. Everything else here is an architect decision recorded for the record.

**Decision (D1–D13):**

- **D1 — Two layers of tenant isolation.** (1) App layer: tenant data is reachable only through `TenantDb.run()`, which requires a tenant context. (2) DB layer: Row-Level Security (RLS) on every tenant-owned table, with a policy that compares the row's tenant to `app.current_tenant_id()`. A forgotten `WHERE` must not leak data.
- **D2 — Forward-only migrations.** Mistakes are fixed with a new migration. A DB backup runs before every production migration (F8 runbook). Migrations are never applied automatically on app start; they run through an explicit command or deploy step. (Drizzle has no down migrations; hand-written down scripts break silently over time.)
- **D3 — Driver and migration tooling.** `pg` (node-postgres) + `drizzle-orm/node-postgres`. Migrations: `drizzle-kit generate` (SQL committed to Git) + the `drizzle-orm` migrator. Most mature driver; works with Testcontainers.
- **D4 — Two DB roles.** The _migration owner_ (`DATABASE_MIGRATION_URL`; in dev the compose `POSTGRES_USER`) owns the schema. The _runtime role_ `bitabar_app` (`DATABASE_URL`) is `NOSUPERUSER NOBYPASSRLS NOCREATEROLE`, is not a table owner, and has DML grants only. A migration creates `bitabar_app` as `NOLOGIN` with no password; each environment enables login with a password that never goes into Git (dev script, test harness, F8 runbook). **The application never connects as the owner or a superuser: RLS does not apply to superusers or table owners, so connecting as one would silently disable the entire second isolation layer.**
- **D5 — Tenant GUC.** `app.tenant_id` (and `app.carrier_id`, reserved for F1-08), set **only** through `select set_config('app.tenant_id', $1, true)` — a parameterized, transaction-local call. Never `SET LOCAL ... '${value}'` (SQL injection risk). The value resets automatically at commit or rollback, so pooled connections never leak a tenant.
- **D6 — Fail closed.** `app.current_tenant_id()` returns `NULL` when the setting is missing. Policies then match zero rows, and `WITH CHECK` rejects inserts. In the app, `TenantDb.run()` without a context throws `TENANT_CONTEXT_MISSING` (HTTP 500, a programming error). A missing context never means "all tenants".
- **D7 — IDs.** UUID v7, generated in the app with the `uuid` package (`v7()`); column type `uuid`. PostgreSQL 17 has no native `uuidv7()`; time-ordered IDs keep indexes efficient (GUIDELINES §4).
- **D8 — Standard columns.** `id`, `tenant_id` (tenant-owned tables), `created_at`, `updated_at` (`timestamptz`, default `now()`, `updated_at` refreshed on update), `created_by uuid NULL` (FK to `users` added in F1-03), and `deleted_at timestamptz NULL` (operational tables only).
- **D9 — Tenant-owned table rules.** Every tenant-owned table gets: `tenant_id uuid NOT NULL REFERENCES tenants(id)`, an index whose leading column is `tenant_id`, `ENABLE ROW LEVEL SECURITY`, and the policy template below. Unique constraints are **per tenant** (`(tenant_id, code)`), partial on `deleted_at IS NULL` where soft delete applies.
- **D10 — `TenantDb.run(fn, opts?)`.** Opens **one transaction** per call (default READ COMMITTED; `opts.isolationLevel` can override). A nested `run()` inside an active run **reuses** the outer transaction. Service code receives `tx` and never opens its own connection.
- **D11 — DB access boundary.** Raw DB access (`pg`, `drizzle-orm/node-postgres`, the root `DB` token) is allowed only under `apps/api/src/db/**`. ESLint `no-restricted-imports` enforces this, so nobody can bypass `TenantDb` by accident.
- **D12 — Integration tests.** `@testcontainers/postgresql` (`postgres:17-alpine`), files named `*.int.test.ts`, separate Vitest config, `pnpm test:int`; CI runs them in the `quality` job. Unit tests (`pnpm test`) stay Docker-free (GUIDELINES §8).
- **D13 — No cross-tenant operations in F1-02.** Platform-level work (for example `PLATFORM_ADMIN` creating a tenant) is not built in F1-02. `tenants` rows are inserted only by the migration owner (tests, and the future seed). This avoids adding an RLS bypass before RBAC exists (open question Q1 in `docs/plan/F1-02.md`).

**RLS policy template** (from F1-02 T04; copied verbatim into `docs/security/rls.md` and applied to every future tenant-owned table):

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
CREATE POLICY <t>_tenant_isolation ON <t> FOR ALL TO bitabar_app
  USING (tenant_id = app.current_tenant_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
```

`FORCE ROW LEVEL SECURITY` is intentionally **not** used: the owner role is for migrations only, and the app never connects as owner (D4).

**Alternatives considered:**

- App-layer filtering only (no RLS) — rejected: one missed `WHERE` leaks data (GUIDELINES §4 requires defense in depth).
- RLS only, no `TenantDb` — rejected: the app layer is still needed for clear transaction boundaries and fail-closed errors (D6, D10).
- `FORCE ROW LEVEL SECURITY` on tables — rejected for now: the migration owner must keep working without per-table exemptions; the guarantee comes from D4 instead (the app never holds the owner role).
- Prisma instead of Drizzle — rejected by owner decision (AGENT.md §3).
- Separate schema or database per tenant — rejected: operationally too heavy for a handful of tenants on one Iranian VPS (PRD §7).
- Down migrations — rejected (D2): Drizzle does not generate them; forward-only plus pre-deploy backup is safer.

**Consequences:**

- Every new tenant-owned table must follow D8/D9 and apply the template above; `docs/security/rls.md` and `apps/api/src/db/README.md` describe the steps, and the T09 isolation suite proves the template on a probe table.
- The app cannot run migrations (no owner credentials in app config) and cannot bypass RLS (D4); enabling the runtime login is a deliberate, per-environment step.
- `TenantDb` is the only path to tenant data; bypassing it is a lint error (D11).
- Tenant creation and any cross-tenant administration are deferred to a later decision (Q1); nothing in F1-02 blocks either answer.
