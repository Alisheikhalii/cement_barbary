-- F1-03 T05b: trim the role catalog to 3 roles (owner product decision, 2026-11-19).
-- Keeps FACTORY_OPERATOR, CARRIER_ADMIN, DRIVER. Removes PLATFORM_ADMIN,
-- CARRIER_OPERATOR and AUDITOR. CARRIER_ADMIN becomes the single carrier role
-- and takes over the CARRIER_OPERATOR duties (announcements, cancel approval,
-- permits) — OD-37 is closed. Forward-only: 0002/0003 are NOT edited.
-- Runs as the migration owner. Contains no secrets.

-- 1. Safety guard: refuse to remove a role that is still assigned. The
--    composite FK would block the DELETE anyway (23503); this raises a clear
--    error instead.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM user_roles
    WHERE role_code IN ('PLATFORM_ADMIN', 'CARRIER_OPERATOR', 'AUDITOR')
  ) THEN
    RAISE EXCEPTION 'role catalog trim aborted: user_roles still reference a removed role';
  END IF;
END $$;
--> statement-breakpoint
-- 2. Remove the three roles. The CHECK constraints (roles_scope_valid,
--    user_roles_no_platform) intentionally stay: they remain correct for any
--    future catalog change.
DELETE FROM roles WHERE code IN ('PLATFORM_ADMIN', 'CARRIER_OPERATOR', 'AUDITOR');
--> statement-breakpoint
-- 3. CARRIER_ADMIN is no longer "login only" (OD-37 closed). The permission
--    matrix itself is written in F1-05 (ADR-006 U2 stands otherwise).
UPDATE roles
SET description = 'Carrier company admin: announcements, cancel approval, permits, carrier users (OD-37 closed)'
WHERE code = 'CARRIER_ADMIN';
