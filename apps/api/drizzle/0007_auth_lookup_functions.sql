-- F1-04 T04: pre-auth lookup via SECURITY DEFINER functions (ADR-007 A3/A4/A8/
-- A17, owner condition 4). Runs as the migration owner (definer).
--
-- Hardening rules enforced here and asserted by test/auth-lookup.int.test.ts:
--   * SET search_path = pg_catalog, pg_temp — all table references are schema-
--     qualified (`public.…`), so a temp-table shadow on a pooled connection can
--     never hijack a lookup;
--   * no dynamic SQL (static statements only);
--   * minimal result columns (no PII, no ciphertext except password_hash and
--     the refresh hash comparison, which are the lookups' purpose);
--   * EXECUTE revoked from PUBLIC and granted to bitabar_app only.
-- Unknown input always yields the identical empty result — no enumeration at
-- the DB layer. Suspended/soft-deleted tenants and soft-deleted users are
-- invisible (same empty result).
--
-- OWNER CONDITION 4 NOTE: the approved plan listed three functions. A fourth,
-- app.auth_lookup_session(refresh_hash), is required because the refresh cookie
-- carries only an opaque token: without a pre-context lookup, T05's refresh,
-- logout and reuse-detection flows cannot find the session under RLS. It
-- follows the identical hardening rules. FLAGGED FOR OWNER APPROVAL at the
-- T03+T04 checkpoint; with the approval withheld it is removed with this
-- migration.

-- Defense in depth: functions created later in schema app must not inherit the
-- default PUBLIC EXECUTE either (default privileges are per creating role, and
-- migrations run as the owner).
ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
--> statement-breakpoint
-- 1. Login-time tenant fan-out cache: active tenants only, id + code only.
CREATE OR REPLACE FUNCTION app.list_tenants()
RETURNS TABLE (id uuid, code varchar)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.id, t.code
  FROM public.tenants t
  WHERE t.status = 'active' AND t.deleted_at IS NULL
$$;
--> statement-breakpoint
-- 2. Staff login lookup: `username@tenant-code`, at most one row (unique index).
-- Disabled users ARE returned (status = 'disabled') so the login flow answers
-- the same generic 401 — filtering them here would create an enumeration oracle.
CREATE OR REPLACE FUNCTION app.auth_lookup_username(p_tenant_code text, p_username text)
RETURNS TABLE (
  tenant_id uuid,
  user_id uuid,
  password_hash text,
  status varchar,
  must_change_password boolean,
  failed_attempts integer,
  next_attempt_at timestamptz,
  temporary_password_expires_at timestamptz,
  roles text[]
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT
    u.tenant_id,
    u.id,
    c.password_hash,
    u.status,
    c.must_change_password,
    c.failed_attempts,
    c.next_attempt_at,
    c.temporary_password_expires_at,
    (
      SELECT coalesce(array_agg(r.role_code ORDER BY r.role_code), '{}'::text[])
      FROM public.user_roles r
      WHERE r.tenant_id = u.tenant_id AND r.user_id = u.id
    )
  FROM public.tenants t
  JOIN public.users u ON u.tenant_id = t.id
  JOIN public.user_credentials c ON c.tenant_id = u.tenant_id AND c.user_id = u.id
  WHERE t.code = p_tenant_code
    AND t.status = 'active'
    AND t.deleted_at IS NULL
    AND u.username = p_username
    AND u.deleted_at IS NULL
$$;
--> statement-breakpoint
-- 3. Driver login fan-out: input is tenant_id + phone blind-index pairs only —
-- never a raw phone. Each pair is matched conjunctively (both parts required);
-- duplicates are collapsed so one phone cannot advance a delay counter twice.
-- Guard rails: non-array / null input and arrays beyond the cap return the
-- same empty result (bounded work, no shape oracle); elements are validated by
-- regex BEFORE any cast, so malformed input is skipped, never raised with an
-- echoing error. Cap = AUTH_LOOKUP_MAX_PAIRS (auth-lookup.ts) — far above any
-- realistic active-tenant count.
CREATE OR REPLACE FUNCTION app.auth_lookup_phone(p_pairs jsonb)
RETURNS TABLE (
  tenant_id uuid,
  user_id uuid,
  password_hash text,
  status varchar,
  must_change_password boolean,
  failed_attempts integer,
  next_attempt_at timestamptz,
  temporary_password_expires_at timestamptz,
  roles text[]
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH input AS (
    SELECT p_pairs AS j
    WHERE CASE
        WHEN jsonb_typeof(p_pairs) = 'array' THEN jsonb_array_length(p_pairs) <= 500
        ELSE false
      END
  ),
  pairs AS (
    SELECT DISTINCT
      (e ->> 'tenant_id')::uuid AS tenant_id,
      decode(e ->> 'phone_hash', 'hex') AS phone_hash
    FROM input, LATERAL jsonb_array_elements(input.j) AS e
    WHERE jsonb_typeof(e) = 'object'
      AND (e ->> 'tenant_id') ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND (e ->> 'phone_hash') ~ '^[0-9a-fA-F]{64}$'
  )
  SELECT
    u.tenant_id,
    u.id,
    c.password_hash,
    u.status,
    c.must_change_password,
    c.failed_attempts,
    c.next_attempt_at,
    c.temporary_password_expires_at,
    (
      SELECT coalesce(array_agg(r.role_code ORDER BY r.role_code), '{}'::text[])
      FROM public.user_roles r
      WHERE r.tenant_id = u.tenant_id AND r.user_id = u.id
    )
  FROM pairs
  JOIN public.users u ON u.tenant_id = pairs.tenant_id AND u.phone_hash = pairs.phone_hash
  JOIN public.tenants t ON t.id = u.tenant_id
  JOIN public.user_credentials c ON c.tenant_id = u.tenant_id AND c.user_id = u.id
  WHERE u.deleted_at IS NULL
    AND t.status = 'active'
    AND t.deleted_at IS NULL
$$;
--> statement-breakpoint
-- 4. Refresh/logout session resolution (owner-condition-4 note above). The
-- caller holds the cookie; the token's SHA-256 hash is matched against the
-- current hash (valid rotation) or the previous one (REUSE — revoke the whole
-- family in the flow). Input is hex-validated in a CTE so decode() only runs
-- on well-formed hashes. Revoked/rotated sessions are returned with their
-- state columns so the flow can act; the tenant must still be active.
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
  JOIN public.tenants t ON t.id = s.tenant_id
  WHERE t.status = 'active' AND t.deleted_at IS NULL
$$;
--> statement-breakpoint
-- 5. Grants: CREATE FUNCTION grants EXECUTE to PUBLIC by default — revoke it.
REVOKE ALL ON FUNCTION app.list_tenants() FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.auth_lookup_username(text, text) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.auth_lookup_phone(jsonb) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.auth_lookup_session(text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenants() TO bitabar_app;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.auth_lookup_username(text, text) TO bitabar_app;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.auth_lookup_phone(jsonb) TO bitabar_app;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.auth_lookup_session(text) TO bitabar_app;
