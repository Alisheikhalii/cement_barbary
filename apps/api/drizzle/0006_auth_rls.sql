-- F1-04 T04: RLS and write rules for the auth tables (ADR-007 A16, A9, A19).
-- Runs as the migration owner. Contains no secrets.
-- The RLS template is copied verbatim from docs/security/rls.md.

ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY user_credentials_tenant_isolation ON user_credentials FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY auth_sessions_tenant_isolation ON auth_sessions FOR ALL TO bitabar_app
  USING (tenant_id = (SELECT app.current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
--> statement-breakpoint
-- Soft/append-only data: credentials are updated (never deleted with the user,
-- which is soft-deleted) and sessions are revoked via `revoked_at` (A9). The
-- runtime role therefore gets no DELETE on either table; a future purge of
-- expired sessions runs as the owner (recorded debt).
REVOKE DELETE ON user_credentials FROM bitabar_app;
--> statement-breakpoint
REVOKE DELETE ON auth_sessions FROM bitabar_app;
