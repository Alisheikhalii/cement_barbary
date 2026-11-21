# ADR-008: Authorization — RBAC, deny-by-default and ownership scoping

2026-11-21 | Accepted (owner approval with 7 conditions C1–C7, same day)

**Context:** F1-04 shipped authentication only: a global `AuthGuard` verifies a bearer access
token and `@Public()` opts routes out. No route checks a permission, so any authenticated principal
can call any protected route. GUIDELINES §6.2 requires a central `can(principal, action, resource)`
layer, an explicit access declaration on every endpoint, IDOR-safe ownership filters
(`tenant_id` + `carrier_id`/driver id, never `WHERE id` only) and a permission matrix kept in sync
by tests. PRD §2 defines three roles — `FACTORY_OPERATOR` (tenant), `CARRIER_ADMIN` (carrier),
`DRIVER` (driver) — after the owner's T05b trim (ADR-006). Two recorded debts feed this ADR: refresh
reads roles in a separate step after rotation (AGENT.md §7), and `users.carrier_id` does not exist
until F1-08, so carrier scope must fail closed today.

The owner approved this plan on 2026-11-21 and answered: Q1 yes (fresh roles on sensitive actions
only), Q2 yes (code permissions only through F1-08; later phases are documented as planned), Q3 yes
(a role change revokes all of that user's sessions). The binding conditions are C1–C7 below. Full
plan: `docs/plan/F1-05.md`.

**Decision (Z1–Z13):**

- **Z1 — Permissions are code; roles are data.** `apps/api/src/security/authz/permissions.ts`
  exports a typed catalog. Each entry has a `resource.action` name, a required **scope**
  (`tenant` | `carrier` | `own`) and a `sensitive` flag. `role-permissions.ts` maps role codes to
  permission names. There is **no `permissions` table**: the three roles are fixed by the owner, and
  changing who may do what is a reviewed code change with tests, not a runtime setting. This is not
  the BR-12 queue Policy engine — that stays operator-configurable data (F3). Rejected: a DB
  permission table (runtime-editable privilege is a new attack surface with no v1 requirement);
  CASL/Casbin (heavy for three roles; the need fits a small tested module).
- **Z2 — Catalog contents.** Only permissions needed by existing routes and by the next two tasks
  (F1-07 base data, F1-08 carriers) are added now: `destination.read/write`, `hall.read/write`,
  `loader_type.read/write` (tenant, `FACTORY_OPERATOR`, F1-07) and `carrier.read/write`,
  `carrier_membership.write`, `carrier_quota.write` (tenant, `FACTORY_OPERATOR`, F1-08; the two
  `.write` entries are sensitive per §F). Later phases add their own permissions together with their
  endpoints. The matrix doc shows later-phase rows in a separate **planned, not active** table so the
  PRD §2 responsibilities stay visible.
- **Z3 — Access markers; exactly one per route.** Every handler carries exactly one of:
  `@Public()` (no principal), `@SelfService()` (any authenticated principal, acts only on its own
  identity — e.g. `/auth/me`), or `@RequirePermission(p)` (one catalog permission). A route with
  **none or more than one** marker (for example `@Public()` + `@RequirePermission`) is rejected by
  (a) a boot assertion over Nest `DiscoveryService` — the app refuses to start, (b) the route-scan
  test, and (c) the guard at runtime with `403 FORBIDDEN` and a server-side error log. Runtime fails
  closed even if (a)/(b) were bypassed. A throwaway unlabeled controller is the scan's negative
  control and the boot-refusal fixture (owner C5/C6).
- **Z4 — One authorization guard, fixed order.** A new global `AuthorizationGuard` is registered
  **after** the existing `AuthGuard`; authentication stays where it is. Anonymous call to a
  protected route → the existing auth guard's generic `401 UNAUTHORIZED` (it answers first).
  Authenticated call without the permission → `403 FORBIDDEN` with a generic body that never
  names the missing permission or required role. Every `403` body is byte-identical to every other
  `403` body (owner C2). A test locks the registration order. The forced-change token
  (audience `bitabar-api:password-change`) never reaches the authorization guard as a principal: the
  auth guard verifies the access audience, so the change token is a generic 401 on protected routes.
- **Z5 — `can(principal, action, resource)`.** A pure, synchronous function in
  `security/authz/can.ts`. It looks up the principal's roles in the role→permission map, then
  resolves scope against the resource. Unknown role strings in a token are ignored — they never
  grant. A role-less principal gets `@SelfService` routes only; every permission check denies.
  Controllers never inspect roles themselves: an ESLint rule forbids importing role constants or
  reading `principal.roles` outside `security/authz/**` (same mechanism as the D11 DB boundary) and
  a negative + positive proof test proves the rule fires (owner C4).
- **Z6 — Stale roles: hybrid freshness.** Normal permissions trust the verified token roles
  (staleness bounded by the 10-minute access-token TTL). A permission flagged `sensitive` triggers a
  **fresh read** of the user's `status`, tenant status and roles from the DB inside the guard. The
  effective role set is the **intersection** of token roles and DB roles: a stale grant cannot act,
  and the DB can never add a role the token did not carry. A disabled/deleted user or a
  suspended/deleted tenant is refused with the generic `401` even with an unexpired token (owner
  C3). Cost: one indexed tenant-scoped query (~1 ms) on sensitive actions only — rare operator and
  carrier actions — instead of one extra transaction on every authenticated call, including driver
  polling at the F7 load peak. Rejected: per-request re-read (adds a DB transaction to every call);
  token-only roles (a revoked operator could still act for up to 10 minutes).
- **Z7 — Close the refresh debt.** (a) The refresh path reads `status` and roles **inside the same
  transaction** as the rotation `UPDATE`, so a new access token reflects one consistent snapshot.
  (b) Role assignment and revocation through `UsersRepository.assignRole/revokeRole` revoke **all**
  sessions of that user **in the same transaction** (owner Q3), so a role change cannot ride a
  refresh snapshot. With Z6, the remaining window for non-sensitive permissions is the accepted
  access-token TTL risk recorded in ADR-007 A7.
- **Z8 — Scope / ownership scaffold.** The guard resolves a branded `AccessScope`
  `{ tenantId, carrierId?, driverUserId? }` from the principal and stores it in the request's ALS
  context next to `TenantContext`. Repositories that need ownership scoping accept **only** an
  `AccessScope` (the constructor is not exported, so request data cannot build one) and filter
  `tenant_id` **and** `carrier_id` / driver id together with the row id — **never `WHERE id` only**.
  An out-of-scope row answers `404 NOT_FOUND`, not `403`, so the response does not confirm
  existence. A missing `carrierId` for a carrier-scoped permission fails closed. All `404` bodies are
  byte-identical to each other and to the unknown-route 404; a `403` is decided before any row
  lookup and never varies with row existence (owner C2).
- **Z9 — Safe interim for `CARRIER_ADMIN`.** A `carrier`-scoped permission needs `carrierId`; the
  principal has none until F1-08, so resolution fails closed (403) even if a carrier permission were
  mistakenly mapped. In F1-05 the role map gives `CARRIER_ADMIN` **no data permissions at all**
  (self-service only); a test asserts both layers. F1-08 adds `users.carrier_id`, a `cid` token claim
  (or a fresh read), sets `app.carrier_id`, and adds carrier RLS policies using
  `app.current_carrier_id()` — the guard code does not change.
- **Z10 — Sensitive-action contract ("guard ready, audit hook later").** `@RequirePermission(p)`
  with `p.sensitive = true` additionally requires: fresh intersected roles (Z6); a `reason` field in
  the body schema (`z.string().trim().min(10).max(500)`) — the route-scan test proves every sensitive
  route schema declares it, because guards run before pipes and the per-request validation happens in
  the Zod pipe; and an `AuditHook` interface
  `record({ actor, action, resource, reason, outcome })` called by an interceptor after the handler.
  F1-05 ships a **no-op** implementation; F1-06 replaces it with the real audit module. The reason is
  never logged verbatim by pino outside the hook (redaction test in T06).
- **Z11 — Mass assignment.** Every request-body Zod schema is `.strict()` (unknown keys → 400). A
  scan test fails if any body schema contains `role`, `roles`, `tenantId`, `tenant_id`, `carrierId`,
  `carrier_id`, `status`, `userId` or `createdBy` unless the schema is on a written allowlist with a
  reason (empty today). Identity and tenant always come from the principal, never the body.
- **Z12 — Matrix stays in sync.** `docs/security/permission-matrix.md` contains a generated block
  between markers (`<!-- matrix:begin -->…<!-- matrix:end -->`) produced from three inputs (the
  catalog, the role map and the production route scan) by
  `pnpm --filter @bitabar/api authz:matrix`. A test regenerates it in memory and fails on any
  difference. The BFLA suite iterates the same data (route × role → expected status), using a
  test-only probe module — no production endpoint is added.
- **Z13 — Swagger is environment-gated (owner C1).** Swagger registration moves into a small
  testable helper called by `main.ts` only when `nodeEnv !== 'production'`. A test boots the real
  module with production config and asserts `/api/docs` and `/api/docs-json` are `404`; development
  and test keep both. Production exposes no interactive schema of routes or permissions.

**Owner conditions (binding, 2026-11-21):**

- **C1 — Swagger off in production**, proven by a production-config test (Z13).
- **C2 — No existence oracle:** out-of-scope → 404, insufficient role → 403, all bodies identical
  per class; tests prove existence is not revealed (Z4/Z8).
- **C3 — Sensitive actions use token-role ∩ DB-role;** disabled/deleted user or suspended/deleted
  tenant refused (Z6).
- **C4 — The controller role-check lint rule has a negative + positive proof test** (Z5).
- **C5 — Route-scan negative control:** an unlabeled throwaway controller fails the scan and boot
  (Z3).
- **C6 — Two markers on one route fail** scan, boot and runtime (Z3).
- **C7 — No new business endpoint and no schema change in F1-05;** if either becomes necessary,
  stop and ask the owner.

**Alternatives considered:**

- **DB `permissions` table** — rejected (Z1): runtime-editable privilege is a new attack surface and
  no v1 requirement asks for it; the three roles are fixed by the owner.
- **CASL / Casbin** — rejected: a dependency and configuration language for what fits in a small
  pure function with an exhaustive test table.
- **Role checks inside controllers** — rejected: authorization must be central and uniform; the lint
  rule makes the alternative impossible.
- **Permissive unmarked routes** — rejected: a forgotten marker must fail closed and fail the build,
  not silently expose a route.
- **Per-request fresh role read** — rejected: adds a DB transaction to every authenticated call,
  including driver polling; sensitive actions pay the cost only.
- **Token-only roles** — rejected: a revoked operator could approve a cancellation for up to the
  access-token TTL.
- **403 for out-of-scope rows** — rejected: confirms that the row exists (IDOR oracle).
- **Real audit in F1-05** — rejected: the audit module and tables are F1-06; this phase ships the
  contract and a no-op hook so sensitive routes are ready.
- **Swagger in production** — rejected: it publishes the route/permission surface; C1 gates it.

**Accepted risks:**

- Non-sensitive permissions can be stale for up to the access-token TTL (10 min). A role change
  revokes every session, so the practical window is a token minted before the change that is used on
  a non-sensitive route. Sensitive actions re-read and intersect, so the window closes there. This
  is the ADR-007 A7 TTL risk, not a new one.
- Sensitive actions are **not audited** in F1-05: the hook is a no-op until F1-06. The interface,
  the reason requirement and the tests ship now so the audit module has one integration point.
- `CARRIER_ADMIN` has no data permission until F1-08; this is deliberate (Z9), not an oversight.
- The `reason` is client-supplied text; it is length-validated and will be stored by F1-06, but its
  truthfulness is a human/process control, not something code can verify.
- Generic 403/404 bodies reduce client-side debuggability. Server-side logs keep the internal
  reason with the request id; the client never receives a permission name or a row-existence signal.

**Consequences:**

- Every future endpoint must declare exactly one marker; a missing or contradictory marker fails
  startup and the route-scan test. Adding a permission means changing the catalog, the role map, the
  matrix and tests in one reviewed commit.
- F1-08 adds `users.carrier_id`, carrier RLS and the principal's `carrierId`; the guard and `can()`
  do not change. F1-06 replaces the no-op `AuditHook`.
- Role assignment/revocation now forces a re-login of that user (sessions revoked atomically).
- Sensitive actions pay one extra indexed query; other authenticated calls pay none.
- F1-05 expects **no migration** and **no new business endpoint** (C7); `db:generate` must report no
  schema changes.
- `docs/security/permission-matrix.md` is part of the contract: the sync test fails if the catalog,
  role map or route classification and the document diverge.
