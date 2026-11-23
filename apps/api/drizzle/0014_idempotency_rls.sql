-- 0014 — idempotency_keys isolation and expired-only deletion
-- (ADR-010 L9/L11, owner CP4). Runs as the migration owner; contains no secrets.
--
-- Two independent controls:
--   1. the verbatim RLS template from docs/security/rls.md isolates tenants;
--   2. DELETE is narrowed by a RESTRICTIVE policy to expired rows only, so the
--      runtime role can sweep a stale key but can never remove a live claim or
--      a stored response. TRUNCATE is revoked outright.
-- The post-condition fails closed (42501) if any control did not stick, so a
-- migration run by a non-owner cannot leave the invariant silently absent.
ALTER TABLE public.idempotency_keys ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY idempotency_keys_tenant_isolation ON public.idempotency_keys FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
-- RESTRICTIVE: the only rows the runtime role may DELETE are expired ones
-- (the per-tenant sweep). Live rows can never be deleted by the app.
CREATE POLICY idempotency_keys_delete_expired ON public.idempotency_keys
  AS RESTRICTIVE FOR DELETE TO bitabar_app
  USING (expires_at < now());
--> statement-breakpoint
REVOKE TRUNCATE ON public.idempotency_keys FROM bitabar_app;
--> statement-breakpoint
DO $$
DECLARE
  permissive_all int;
  restrictive_delete int;
BEGIN
  IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.idempotency_keys'::regclass) THEN
    RAISE EXCEPTION 'IDEMPOTENCY_RLS_INVALID'
      USING ERRCODE = '42501',
            HINT = 'run 0014 as the idempotency_keys owner';
  END IF;
  SELECT count(*) INTO permissive_all
    FROM pg_policy p
   WHERE p.polrelid = 'public.idempotency_keys'::regclass
     AND p.polpermissive AND p.polcmd = '*';
  SELECT count(*) INTO restrictive_delete
    FROM pg_policy p
   WHERE p.polrelid = 'public.idempotency_keys'::regclass
     AND NOT p.polpermissive AND p.polcmd = 'd';
  IF permissive_all <> 1 OR restrictive_delete <> 1 THEN
    RAISE EXCEPTION 'IDEMPOTENCY_POLICY_INVALID'
      USING ERRCODE = '42501',
            HINT = 'expected exactly one permissive tenant policy and one restrictive delete policy';
  END IF;
  IF NOT has_table_privilege('bitabar_app', 'public.idempotency_keys', 'SELECT')
     OR NOT has_table_privilege('bitabar_app', 'public.idempotency_keys', 'INSERT')
     OR NOT has_table_privilege('bitabar_app', 'public.idempotency_keys', 'UPDATE')
     OR NOT has_table_privilege('bitabar_app', 'public.idempotency_keys', 'DELETE')
     OR has_table_privilege('bitabar_app', 'public.idempotency_keys', 'TRUNCATE') THEN
    RAISE EXCEPTION 'IDEMPOTENCY_GRANTS_INVALID'
      USING ERRCODE = '42501',
            HINT = 'runtime role needs SELECT/INSERT/UPDATE/DELETE but never TRUNCATE';
  END IF;
END $$;
