-- 0010 — SR-05 real database invariant (F1-05, owner-approved C7).
--
-- `user_roles` is the authorization source of truth. The runtime role may READ
-- it (freshness and role listing), but may no longer write it directly. All
-- writes go through two SECURITY DEFINER functions so the database itself
-- enforces:
--   * tenant from app.current_tenant_id() only (never a parameter);
--   * role existence/scope from public.roles (no PLATFORM_ADMIN/removed roles,
--     no caller-supplied scope);
--   * a live, same-tenant user (soft-deleted/other-tenant users are rejected);
--   * session revocation in the SAME transaction, only when a link changed.
--
-- Both functions are owned by the migration owner, pin search_path, contain no
-- dynamic SQL, are revoked from PUBLIC and granted only to bitabar_app.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.user_roles FROM bitabar_app;
--> statement-breakpoint

-- Fail closed if the REVOKE above was a no-op (for example, the migration ran
-- as a role that is not the table owner/grantor). Without this check the app
-- would keep direct DML and the SR-05 invariant would be silently absent.
DO $$
BEGIN
  IF has_table_privilege('bitabar_app', 'public.user_roles', 'INSERT')
     OR has_table_privilege('bitabar_app', 'public.user_roles', 'UPDATE')
     OR has_table_privilege('bitabar_app', 'public.user_roles', 'DELETE')
     OR has_table_privilege('bitabar_app', 'public.user_roles', 'TRUNCATE') THEN
    RAISE EXCEPTION 'SR05_REVOKE_INCOMPLETE'
      USING ERRCODE = '42501',
            HINT = 'run 0010 as the user_roles owner/grantor';
  END IF;
END $$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.assign_user_role(p_user_id uuid, p_role_code text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_scope text;
  v_inserted boolean := false;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'TENANT_CONTEXT_MISSING' USING ERRCODE = '42501';
  END IF;

  -- Scope comes from the catalog, never from the caller. Platform entries were
  -- removed from the catalog; an unknown/removed code simply finds no row.
  SELECT r.scope INTO v_scope
    FROM public.roles r
   WHERE r.code = p_role_code
     AND r.scope <> 'platform';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'INVALID_ROLE' USING ERRCODE = '22023';
  END IF;

  -- Lock the live account row in THIS tenant. Other-tenant and soft-deleted
  -- accounts are invisible here and are rejected.
  PERFORM 1
    FROM public.users u
   WHERE u.tenant_id = v_tenant
     AND u.id = p_user_id
     AND u.deleted_at IS NULL
     FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'USER_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.user_roles (tenant_id, user_id, role_code, role_scope)
  VALUES (v_tenant, p_user_id, p_role_code, v_scope)
  ON CONFLICT (tenant_id, user_id, role_code) DO NOTHING;

  v_inserted := FOUND;

  -- Same transaction as the link change, and only when a link was inserted.
  IF v_inserted THEN
    UPDATE public.auth_sessions
       SET revoked_at = now(),
           revoke_reason = 'role_change'
     WHERE tenant_id = v_tenant
       AND user_id = p_user_id
       AND revoked_at IS NULL;
  END IF;

  RETURN v_inserted;
END;
$$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.revoke_user_role(p_user_id uuid, p_role_code text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := app.current_tenant_id();
  v_deleted boolean := false;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'TENANT_CONTEXT_MISSING' USING ERRCODE = '42501';
  END IF;

  -- Validate the role against the catalog even for a revoke: a removed or
  -- platform role is a bad request, not a silent no-op.
  PERFORM 1
    FROM public.roles r
   WHERE r.code = p_role_code
     AND r.scope <> 'platform';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'INVALID_ROLE' USING ERRCODE = '22023';
  END IF;

  -- Lock the live, same-tenant account row. Other-tenant and soft-deleted
  -- accounts are rejected with the same "not removed" result.
  PERFORM 1
    FROM public.users u
   WHERE u.tenant_id = v_tenant
     AND u.id = p_user_id
     AND u.deleted_at IS NULL
     FOR UPDATE;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  DELETE FROM public.user_roles ur
   USING public.users u
   WHERE ur.tenant_id = v_tenant
     AND ur.user_id = p_user_id
     AND ur.role_code = p_role_code
     AND u.tenant_id = ur.tenant_id
     AND u.id = ur.user_id
     AND u.deleted_at IS NULL;

  v_deleted := FOUND;

  -- Same transaction as the link change, and only when a link was removed.
  IF v_deleted THEN
    UPDATE public.auth_sessions
       SET revoked_at = now(),
           revoke_reason = 'role_change'
     WHERE tenant_id = v_tenant
       AND user_id = p_user_id
       AND revoked_at IS NULL;
  END IF;

  RETURN v_deleted;
END;
$$;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.assign_user_role(uuid, text) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.revoke_user_role(uuid, text) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.assign_user_role(uuid, text) TO bitabar_app;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.revoke_user_role(uuid, text) TO bitabar_app;
