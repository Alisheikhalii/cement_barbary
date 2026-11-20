-- 0008 — refresh-session lookup must also resolve sessions whose tenant is
-- suspended or soft-deleted, so the refresh flow can REVOKE them (A18).
--
-- Before this migration app.auth_lookup_session joined `tenants` and filtered
-- on an active tenant. A suspended tenant therefore produced "no session":
-- refresh answered 401 but auth_sessions.revoked_at stayed NULL, and the same
-- cookie worked again after reactivation (phase review M1). Tenant/user state
-- is enforced one layer up in SessionService.rotate(), which re-checks A18
-- under RLS and revokes the session on an inactive account. The function keeps
-- every hardening rule from 0007: SECURITY DEFINER, pinned search_path, static
-- SQL, minimal columns, PUBLIC revoked, bitabar_app only.
--
-- Replacing the function keeps the same signature, return type and grants.
CREATE OR REPLACE FUNCTION app.auth_lookup_session(p_refresh_hash text)
RETURNS TABLE (
  session_id uuid,
  tenant_id uuid,
  user_id uuid,
  family_id uuid,
  expires_at timestamptz,
  revoked_at timestamptz,
  rotated_at timestamptz,
  reuse_detected boolean
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH input AS (
    SELECT decode(p_refresh_hash, 'hex') AS h
    WHERE p_refresh_hash ~ '^[0-9a-fA-F]{64}$'
  )
  SELECT
    s.id,
    s.tenant_id,
    s.user_id,
    s.family_id,
    s.expires_at,
    s.revoked_at,
    s.rotated_at,
    coalesce(s.previous_refresh_hash = input.h, false)
  FROM input
  JOIN public.auth_sessions s
    ON s.refresh_hash = input.h OR s.previous_refresh_hash = input.h
$$;
