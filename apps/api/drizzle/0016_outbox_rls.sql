-- 0016 — integration_outbox isolation and retention lock
-- (ADR-010 L12–L14, owner CP5). Runs as the migration owner; no secrets.
--
-- The runtime role may enqueue, read and update (claim/CAS) its tenant's rows,
-- but never DELETE or TRUNCATE them: sent rows are retained until the F8
-- retention decision, and the worker never deletes. The post-condition fails
-- closed if RLS, the policy or the privilege set did not stick.
ALTER TABLE public.integration_outbox ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY integration_outbox_tenant_isolation ON public.integration_outbox FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.integration_outbox FROM bitabar_app;
--> statement-breakpoint
DO $$
DECLARE
  permissive_all int;
BEGIN
  IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.integration_outbox'::regclass) THEN
    RAISE EXCEPTION 'OUTBOX_RLS_INVALID'
      USING ERRCODE = '42501',
            HINT = 'run 0016 as the integration_outbox owner';
  END IF;
  SELECT count(*) INTO permissive_all
    FROM pg_policy p
   WHERE p.polrelid = 'public.integration_outbox'::regclass
     AND p.polpermissive AND p.polcmd = '*';
  IF permissive_all <> 1 THEN
    RAISE EXCEPTION 'OUTBOX_POLICY_INVALID'
      USING ERRCODE = '42501',
            HINT = 'expected exactly one permissive tenant policy';
  END IF;
  IF NOT has_table_privilege('bitabar_app', 'public.integration_outbox', 'SELECT')
     OR NOT has_table_privilege('bitabar_app', 'public.integration_outbox', 'INSERT')
     OR NOT has_table_privilege('bitabar_app', 'public.integration_outbox', 'UPDATE')
     OR has_table_privilege('bitabar_app', 'public.integration_outbox', 'DELETE')
     OR has_table_privilege('bitabar_app', 'public.integration_outbox', 'TRUNCATE') THEN
    RAISE EXCEPTION 'OUTBOX_GRANTS_INVALID'
      USING ERRCODE = '42501',
            HINT = 'runtime role needs SELECT/INSERT/UPDATE but never DELETE/TRUNCATE';
  END IF;
END $$;
