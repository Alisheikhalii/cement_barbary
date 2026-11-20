-- 0009 — suspending or deleting a tenant revokes ALL of its live sessions, not
-- only the cookie presented during the suspension window (phase review R1).
--
-- 0008 made refresh able to see a suspended tenant's session and revoke it,
-- but a dormant refresh token was never touched and rotated again after
-- reactivation. This trigger closes that gap at the status transition.
--
-- The trigger function is SECURITY INVOKER (the A17 "exactly four definer
-- functions" covenant is untouched): the operator performing the suspension
-- already holds UPDATE on auth_sessions (owner by definition; the runtime role
-- under that tenant's RLS context). It is not an RLS bypass path.
CREATE OR REPLACE FUNCTION app.revoke_sessions_on_tenant_inactive()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.status <> 'active' OR NEW.deleted_at IS NOT NULL THEN
    UPDATE public.auth_sessions
       SET revoked_at = now(),
           revoke_reason = 'tenant_inactive'
     WHERE tenant_id = NEW.id
       AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS tenants_revoke_sessions ON public.tenants;
--> statement-breakpoint
CREATE TRIGGER tenants_revoke_sessions
AFTER UPDATE OF status, deleted_at ON public.tenants
FOR EACH ROW
EXECUTE FUNCTION app.revoke_sessions_on_tenant_inactive();
