-- F1-03 T04: role rows, grants and RLS for users/user_roles (ADR-006 U1, U4, U13).
-- Runs as the migration owner. Contains no secrets.

-- 1. The 6 roles are data inserted by a migration (U1): every environment
--    needs them; the seed never inserts roles. Idempotent by ON CONFLICT.
INSERT INTO roles (code, name_fa, scope, description) VALUES
  ('PLATFORM_ADMIN',   'مدیر پلتفرم',   'platform', 'Platform administration; CLI/seed only in v1, no web login (U4)'),
  ('FACTORY_OPERATOR', 'اپراتور کارخانه', 'tenant',   'Factory operator panel'),
  ('CARRIER_ADMIN',    'مدیر باربری',    'carrier',  'Login only; no operational permissions until OD-37 is decided (U2)'),
  ('CARRIER_OPERATOR', 'اپراتور باربری',  'carrier',  'Carrier operator panel'),
  ('DRIVER',           'راننده',         'driver',   'Driver PWA'),
  ('AUDITOR',          'بازرس',          'tenant',   'Read-only auditor')
ON CONFLICT (code) DO NOTHING;
--> statement-breakpoint
-- 2. roles is a global read-only catalog for the app (U1): SELECT stays from
--    the default privileges; all writes are revoked.
REVOKE INSERT, UPDATE, DELETE ON roles FROM bitabar_app;
--> statement-breakpoint
-- 3. RLS template from docs/security/rls.md, verbatim (U3, U5).
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY users_tenant_isolation ON users FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY user_roles_tenant_isolation ON user_roles FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
-- 4. Soft delete only for users (U13): the app sets deleted_at; hard DELETE is
--    revoked from the runtime role. user_roles keeps DELETE (role revocation).
REVOKE DELETE ON users FROM bitabar_app;
