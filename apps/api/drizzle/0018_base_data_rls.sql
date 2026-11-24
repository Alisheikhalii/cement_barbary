-- 0018 — base data isolation and soft-delete lock (F1-07, ADR-011)
-- Runs as the migration owner. The runtime role may read and write (insert,
-- update) its tenant's rows, but never DELETE or TRUNCATE them: deletion is a
-- soft delete (deleted_at + version bump). Post-conditions fail closed.
ALTER TABLE public.destinations ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY destinations_tenant_isolation ON public.destinations FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.destinations FROM bitabar_app;
--> statement-breakpoint
ALTER TABLE public.halls ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY halls_tenant_isolation ON public.halls FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.halls FROM bitabar_app;
--> statement-breakpoint
ALTER TABLE public.hall_terminals ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY hall_terminals_tenant_isolation ON public.hall_terminals FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.hall_terminals FROM bitabar_app;
--> statement-breakpoint
ALTER TABLE public.loader_type_groups ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY loader_type_groups_tenant_isolation ON public.loader_type_groups FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.loader_type_groups FROM bitabar_app;
--> statement-breakpoint
ALTER TABLE public.loader_types ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY loader_types_tenant_isolation ON public.loader_types FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
REVOKE DELETE, TRUNCATE ON public.loader_types FROM bitabar_app;
--> statement-breakpoint
DO $$
DECLARE
  t text;
  permissive_all int;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'destinations',
    'halls',
    'hall_terminals',
    'loader_type_groups',
    'loader_types'
  ]::text[] LOOP
    IF NOT (SELECT relrowsecurity
              FROM pg_class
             WHERE oid = format('public.%I', t)::regclass) THEN
      RAISE EXCEPTION 'BASE_RLS_INVALID'
        USING ERRCODE = '42501',
              DETAIL = format('table %I', t),
              HINT = 'run 0018 as the table owner';
    END IF;

    SELECT count(*) INTO permissive_all
      FROM pg_policy p
     WHERE p.polrelid = format('public.%I', t)::regclass
       AND p.polpermissive AND p.polcmd = '*';
    IF permissive_all <> 1 THEN
      RAISE EXCEPTION 'BASE_POLICY_INVALID'
        USING ERRCODE = '42501',
              DETAIL = format('table %I', t),
              HINT = 'expected exactly one permissive tenant policy';
    END IF;

    IF NOT has_table_privilege('bitabar_app', format('public.%I', t), 'SELECT')
       OR NOT has_table_privilege('bitabar_app', format('public.%I', t), 'INSERT')
       OR NOT has_table_privilege('bitabar_app', format('public.%I', t), 'UPDATE')
       OR has_table_privilege('bitabar_app', format('public.%I', t), 'DELETE')
       OR has_table_privilege('bitabar_app', format('public.%I', t), 'TRUNCATE') THEN
      RAISE EXCEPTION 'BASE_GRANTS_INVALID'
        USING ERRCODE = '42501',
              DETAIL = format('table %I', t),
              HINT = 'runtime role needs SELECT/INSERT/UPDATE but never DELETE/TRUNCATE';
    END IF;
  END LOOP;
END $$;
