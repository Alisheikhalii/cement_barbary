# src/db — the only folder that talks to PostgreSQL (ADR-005, D10/D11)

Everything outside this folder reaches tenant data exclusively through
`TenantDb.run()` inside a `TenantContext.run()` scope; ESLint blocks raw
`pg`/`drizzle-orm` imports elsewhere. Adding a tenant-owned table:

1. Define it in `schema/` with the helpers (`id()`, `tenantId()`, `timestamps`).
2. `pnpm --filter @bitabar/api db:generate` and review the table DDL.
3. `pnpm --filter @bitabar/api db:generate --custom --name=rls_<table>` and
   fill it with the RLS template from `docs/security/rls.md` (subselect form).
4. Grants reach `bitabar_app` via `ALTER DEFAULT PRIVILEGES` (migration 0001);
   never write `GRANT` by hand, never connect the app as the owner.
5. Add an isolation scenario for the new table in `test/rls.int.test.ts`.
