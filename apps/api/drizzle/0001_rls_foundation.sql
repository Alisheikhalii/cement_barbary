-- F1-02 T04: RLS foundation (ADR-005).
-- Creates the restricted runtime role, the tenant-context functions, the DML
-- grants, and row-level security on `tenants`. Contains no passwords; each
-- environment enables LOGIN separately (dev script / test harness / F8 runbook).

-- Runtime role: no login here (password set per environment, never in Git).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bitabar_app') THEN
    CREATE ROLE bitabar_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END $$;
--> statement-breakpoint
CREATE SCHEMA IF NOT EXISTS app;
--> statement-breakpoint
REVOKE ALL ON SCHEMA app FROM PUBLIC;
--> statement-breakpoint
-- Fail closed: NULL when unset/empty → policies match nothing.
-- search_path pinned to pg_catalog so the function body cannot be hijacked by
-- objects in other schemas.
CREATE OR REPLACE FUNCTION app.current_tenant_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.current_carrier_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog, pg_temp
  AS $$ SELECT NULLIF(current_setting('app.carrier_id', true), '')::uuid $$;
--> statement-breakpoint
GRANT USAGE ON SCHEMA app TO bitabar_app;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.current_tenant_id(), app.current_carrier_id() TO bitabar_app;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO bitabar_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bitabar_app;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bitabar_app;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO bitabar_app;
--> statement-breakpoint
-- Drizzle's migration journal must not be touched by the app.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'drizzle') THEN
    EXECUTE 'REVOKE ALL ON SCHEMA drizzle FROM bitabar_app';
  END IF;
END $$;
--> statement-breakpoint
-- tenants: the app may only see/modify its own tenant row; no insert/delete from the app in F1-02.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
-- Subselect wrapping makes the planner evaluate the context function once per query.
CREATE POLICY tenants_isolation ON tenants FOR SELECT TO bitabar_app USING (id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
CREATE POLICY tenants_update ON tenants FOR UPDATE TO bitabar_app
  USING (id = (SELECT app.current_tenant_id())) WITH CHECK (id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE INSERT, DELETE ON tenants FROM bitabar_app;
