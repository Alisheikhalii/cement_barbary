-- 0012 — audit_logs isolation, append-only and occurred_at immutability
-- (ADR-009 L3, owner CP1 A3). Runs as the migration owner; contains no secrets.
--
-- Three independent controls:
--   1. the verbatim RLS template from docs/security/rls.md;
--   2. REVOKE UPDATE/DELETE/TRUNCATE (and TRIGGER/REFERENCES, so no later
--      trigger can be added) from the runtime role, with a fail-closed
--      post-condition (the 0010 pattern) so a non-owner run cannot silently
--      leave the invariant absent;
--   3. BEFORE triggers that reject UPDATE/DELETE/TRUNCATE for EVERY role
--      (including the owner) and force occurred_at to the server clock on
--      INSERT, so a row can never be backdated by the application.
-- Both trigger functions are SECURITY INVOKER with a pinned search_path; the
-- DEFINER catalog therefore stays at exactly six functions.
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY audit_logs_tenant_isolation ON public.audit_logs FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON public.audit_logs FROM bitabar_app;
--> statement-breakpoint
DO $$
BEGIN
  IF has_table_privilege('bitabar_app', 'public.audit_logs', 'UPDATE')
     OR has_table_privilege('bitabar_app', 'public.audit_logs', 'DELETE')
     OR has_table_privilege('bitabar_app', 'public.audit_logs', 'TRUNCATE')
     OR has_table_privilege('bitabar_app', 'public.audit_logs', 'TRIGGER')
     OR has_table_privilege('bitabar_app', 'public.audit_logs', 'REFERENCES')
     OR has_any_column_privilege('bitabar_app', 'public.audit_logs', 'UPDATE') THEN
    RAISE EXCEPTION 'AUDIT_REVOKE_INCOMPLETE'
      USING ERRCODE = '42501',
            HINT = 'run 0012 as the audit_logs owner/grantor';
  END IF;
END $$;
--> statement-breakpoint

-- Raises for UPDATE, DELETE and TRUNCATE. One function serves the row and the
-- statement trigger: it never inspects the row and always raises.
CREATE OR REPLACE FUNCTION app.audit_logs_block_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'AUDIT_APPEND_ONLY' USING ERRCODE = '42501';
END;
$$;
--> statement-breakpoint

-- A3: the server clock wins. A client-supplied (or app-supplied) occurred_at is
-- overwritten before the row is stored, so history cannot be backdated.
CREATE OR REPLACE FUNCTION app.audit_logs_force_occurred_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  NEW.occurred_at := clock_timestamp();
  RETURN NEW;
END;
$$;
--> statement-breakpoint

DROP TRIGGER IF EXISTS audit_logs_no_mutation ON public.audit_logs;
--> statement-breakpoint
CREATE TRIGGER audit_logs_no_mutation
  BEFORE UPDATE OR DELETE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.audit_logs_block_mutation();
--> statement-breakpoint
CREATE TRIGGER audit_logs_no_truncate
  BEFORE TRUNCATE ON public.audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION app.audit_logs_block_mutation();
--> statement-breakpoint
CREATE TRIGGER audit_logs_force_occurred_at
  BEFORE INSERT ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION app.audit_logs_force_occurred_at();
--> statement-breakpoint

-- Fail closed if a trigger is missing or disabled (for example the table was
-- recreated, or someone ran DISABLE TRIGGER): grants, policies and triggers do
-- not survive DROP/CREATE. `tgenabled = 'O'` means the trigger fires normally
-- in origin sessions (replica-only `'R'` or disabled `'D'` do not count).
DO $$
BEGIN
  IF NOT EXISTS (
       SELECT 1 FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       WHERE c.relname = 'audit_logs'
         AND c.relnamespace = 'public'::regnamespace
         AND t.tgname = 'audit_logs_no_mutation'
         AND t.tgenabled = 'O'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       WHERE c.relname = 'audit_logs'
         AND c.relnamespace = 'public'::regnamespace
         AND t.tgname = 'audit_logs_no_truncate'
         AND t.tgenabled = 'O'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       WHERE c.relname = 'audit_logs'
         AND c.relnamespace = 'public'::regnamespace
         AND t.tgname = 'audit_logs_force_occurred_at'
         AND t.tgenabled = 'O'
     ) THEN
    RAISE EXCEPTION 'AUDIT_TRIGGER_MISSING'
      USING ERRCODE = '42501',
            HINT = 'audit_logs must carry the enabled append-only and occurred_at triggers';
  END IF;
END $$;
