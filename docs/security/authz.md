# Authorization — permissions, markers and ownership scopes

How authorization works and how to add a permission or an endpoint. Rules: ADR-008
(`docs/adr/008-authorization.md`); plan: `docs/plan/F1-05.md`; matrix:
`docs/security/permission-matrix.md`.

F1-05 adds a **central authorization layer** after authentication. Authentication answers "who are
you?" (ADR-007); authorization answers "may this principal do this to this resource?" Every route
must say which one it is, and a route that says nothing is rejected at startup, by the route-scan
test and at runtime.

## Request pipeline

1. `AuthGuard` (existing) verifies the bearer access token, or `@Public()` skips it. Failure is a
   generic `401`.
2. `AuthorizationGuard` reads the route's single access marker:
   - `@Public()` — no principal; the handler authenticates itself if it needs to.
   - `@SelfService()` — any authenticated principal, acting only on its own identity.
   - `@RequirePermission(p)` — the principal must hold `p`.
3. The guard resolves a branded `AccessScope` from the principal and stores it in the request's ALS
   context for repositories.
4. For a **sensitive** permission, the guard re-reads the user's status, tenant status and roles,
   intersects them with the token roles, and only then calls `can()`.
5. Pipes (Zod, `.strict()`) validate the body; the handler runs. Sensitive routes have a validated
   `reason` field in their schema and the `AuditHook` interceptor records the outcome (no-op until
   F1-06). A guard denial is logged server-side with the request id and a stable reason code only.

Guards run **before** pipes. That is why the sensitive `reason` requirement is enforced by the
route-scan test against the route's body schema, not by the guard.

## Access markers — exactly one per route

| Marker                  | Who                    | Use                                          |
| ----------------------- | ---------------------- | -------------------------------------------- |
| `@Public()`             | anyone                 | health, login/refresh/logout/password change |
| `@SelfService()`        | any authenticated role | `GET /api/v1/auth/me` — own identity only    |
| `@RequirePermission(p)` | principals with `p`    | every data route                             |

- None, or more than one (for example `@Public()` + `@RequirePermission`) → the app refuses to
  start, the route-scan test fails, and the runtime guard answers `403`.
- Markers are **handler-level only**. A class-level access marker is rejected by the scan and boot
  check, so a controller annotation cannot silently open unmarked handlers.
- `@Public()` is allowed only on the routes listed in the §D allowlist; a new public route requires
  a reviewed allowlist change. The scan treats any other public route as a failure.
- The route-scan test and the boot assertion are two independent checks over the same
  `DiscoveryService` data. A throwaway unlabeled controller is the negative control for both.

## Permission model

Permissions are **code**, roles are **data**. `security/authz/permissions.ts` holds a typed catalog;
each entry has a `resource.action` name, a scope and a `sensitive` flag. `role-permissions.ts` maps
the three role codes to permission names.

| Permission                 | Scope  | Sensitive | Roles              | Route arrives |
| -------------------------- | ------ | --------- | ------------------ | ------------- |
| `destination.read`         | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `destination.write`        | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `hall.read`                | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `hall.write`               | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `loader_type.read`         | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `loader_type.write`        | tenant | no        | `FACTORY_OPERATOR` | F1-07         |
| `carrier.read`             | tenant | no        | `FACTORY_OPERATOR` | F1-08         |
| `carrier.write`            | tenant | no        | `FACTORY_OPERATOR` | F1-08         |
| `carrier_membership.write` | tenant | **yes**   | `FACTORY_OPERATOR` | F1-08         |
| `carrier_quota.write`      | tenant | **yes**   | `FACTORY_OPERATOR` | F1-08         |

`CARRIER_ADMIN` and `DRIVER` have **no data permission** in F1-05; every authenticated role has
`@SelfService` access to its own identity. Later-phase permissions are listed in the matrix's
"planned, not active" section and are not in code until their endpoints exist.

`can(principal, action, resource)` is pure and synchronous: role → permission lookup, then scope
resolution. Unknown role strings in a token are ignored — they never grant; duplicate role codes
are deduped and cannot inflate the set. A role-less principal gets `@SelfService` only.

### Scopes

| Scope     | Required principal data  | Repository filter                                          |
| --------- | ------------------------ | ---------------------------------------------------------- |
| `tenant`  | `tenantId`               | `tenant_id = scope.tenantId AND id = :id`                  |
| `carrier` | `tenantId` + `carrierId` | `tenant_id AND carrier_id = scope.carrierId AND id`        |
| `own`     | `tenantId` + user id     | `tenant_id AND driver_user_id = scope.driverUserId AND id` |

A carrier-scoped permission without a `carrierId` **fails closed** (`403`). Until F1-08 adds
`users.carrier_id`, no principal has a carrier id, so even a mistakenly mapped carrier permission
cannot grant access.

## How to add a permission

1. Add the entry to `security/authz/permissions.ts` (`resource.action`, scope, sensitive) and to
   `security/authz/role-permissions.ts` for the roles that should hold it.
2. Run the matrix generator (T07 onward): `pnpm --filter @bitabar/api authz:matrix`; commit the
   regenerated block in `docs/security/permission-matrix.md`.
3. The exhaustive role × permission unit test and the matrix sync test must stay green. If the
   permission is sensitive, the sensitive-action tests and the `reason` scan apply.
4. No database change: permissions are code. Never add a `permissions` table.

## How to add an endpoint

1. Put the handler in a module controller and give it **exactly one** marker. Use
   `@RequirePermission(PERMISSIONS.x)` for data routes; never check `principal.roles` in a
   controller.
2. Define a `.strict()` Zod body schema at every nested object level, plus strict query/params
   schemas. Identity, tenant, carrier and status always come from the principal or the scope — never
   from the request.
3. If the permission is sensitive, include `reason: sensitiveReasonSchema` (import it from
   `apps/api/src/security/authz/sensitive-reason.ts`) in the schema; the `AuditHook` records it
   (no-op in F1-05). The shared schema trims, enforces 10–500, and rejects C0/C1 controls,
   zero-width characters (U+200B–U+200F), bidi controls (U+202A–U+202E, U+2066–U+2069) and lone
   surrogates. The boot scan samples the complete forbidden ranges, not merely the presence of a
   `reason` key.
4. Query through a repository that accepts **only** an `AccessScope` and filters `tenant_id` and
   `carrier_id`/driver id together with the row id. Never `WHERE id` only. An out-of-scope row is a
   `404`, not a `403`.
5. Add tests: anonymous → `401`; each role → expected `200`/`403`; out-of-scope row → `404` identical
   to a nonexistent row; missing permission name never appears in the body. The BFLA/matrix suite
   picks the route up automatically once the route scan sees it.
6. Run `lint`, `typecheck`, `test`, `test:int`, `format:check`, `build`. The boot check refuses an
   unmarked route, so a missing marker fails before any test.

## Status codes and response hygiene

| Status | When                                                                                                                                                         |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `401`  | missing/invalid/expired token; change token on a protected route; disabled/deleted user or suspended/deleted tenant or revoked session on a sensitive action |
| `403`  | authenticated but missing the required permission; unmarked/duplicate-marker route; carrier scope without a carrier id                                       |
| `404`  | out-of-scope row, nonexistent row, unknown route — all with the same generic body                                                                            |
| `400`  | Zod validation: unknown body keys, forbidden identity fields, missing/short/control-character reason                                                         |
| `429`  | authentication rate limits (ADR-007), never an authorization answer                                                                                          |

Every `403` body is byte-identical to every other `403`; every `404` body is byte-identical to
every other `404`, including the unknown-route 404 from the global filter. The body never names a
permission, a role, a tenant/carrier or whether a row exists. Server-side logs may carry the
internal reason with the request id; they never carry PII or tokens.

## Freshness and role changes

- Normal permissions trust the access-token `roles` claim. Staleness is bounded by the token TTL
  (10 min, ADR-007 A7).
- **Sensitive** permissions re-read `users.status`, tenant `status`, the role rows and the token
  session's liveness inside the guard. Effective roles = token roles ∩ DB roles. Disabled/deleted
  user, suspended/deleted tenant, or a logged-out/revoked `sid` → generic `401`.
- Refresh reads status and roles **inside the rotation transaction**, so a new token is one
  consistent snapshot.
- `UsersRepository.assignRole` / `revokeRole` revoke **all** sessions of that user in the same
  transaction. A role change forces re-login, so an old token cannot carry the old role forward.

## Sensitive actions

A permission with `sensitive: true` requires the role, a `reason` (10–500 trimmed characters, no
control characters) and fresh intersected roles. The `AuditHook` interface
`record({ actor, action, resource, reason, outcome })` is called by an interceptor after the handler;
F1-05 ships a **no-op** provider and F1-06 replaces it with the audit module. The reason is never
logged verbatim by pino outside the hook (T06 redaction test). A guard denial is logged server-side
with the request id and a stable reason code only — never the permission name, the role list or the
user-supplied reason text — while the client receives only the generic body. The current sensitive
list is in `docs/security/permission-matrix.md` §Sensitive actions (from plan §F).

## Scope enforcement pattern

```ts
// Inside security/authz/**, only here:
const scope = accessScopeFrom(principal); // branded, not constructible elsewhere

// A repository accepts the scope, never request data:
await repo.findForScope(scope, resourceId);
// SQL shape: WHERE tenant_id = :tenantId
//             AND carrier_id = :carrierId        (carrier scope)
//             AND driver_user_id = :driverUserId (own scope)
//             AND id = :id
```

The `AccessScope` constructor is not exported outside the authz module (a type test plus a runtime
check prove it). A missing required part of the scope is a `403`; a row outside the scope is a `404`.

## No role checks in controllers

The ESLint rule in `packages/config` forbids importing role constants or reading `principal.roles`
outside `security/authz/**` (the same mechanism as the D11 DB-boundary rule). A proof test runs the
rule on a violating controller fixture (fails with the rule id) and on a compliant
`security/authz/**` fixture (passes): negative + positive control.

## Matrix and route scan

- Every production route must carry exactly one marker; the scan test reads the real controllers.
- `docs/security/permission-matrix.md` has a generated block between `<!-- matrix:begin -->` and
  `<!-- matrix:end -->`. The `authz:matrix` script regenerates it from the catalog + role map +
  route scan; the test regenerates it in memory and fails on any difference.
- The BFLA suite iterates the same data: route × role × anonymous → expected status. It uses a
  **test-only probe module** with one route per catalog permission; no production business endpoint
  is added in F1-05.

## Swagger

Swagger (`/api/docs`, `/api/docs-json`) is registered only when `NODE_ENV !== 'production'`. A test
boots the real app with production config and proves both paths are `404`; development/test keep
both. Production exposes no interactive route/permission map.

## Current endpoint classification (locked by the route-scan test)

| Endpoint                            | Marker         | Who                     |
| ----------------------------------- | -------------- | ----------------------- |
| `GET /health/live`                  | `@Public`      | anyone                  |
| `GET /health/ready`                 | `@Public`      | anyone                  |
| `POST /api/v1/auth/login`           | `@Public`      | anyone                  |
| `POST /api/v1/auth/refresh`         | `@Public`      | cookie holder           |
| `POST /api/v1/auth/logout`          | `@Public`      | cookie holder           |
| `POST /api/v1/auth/password/change` | `@Public`      | change-token or bearer  |
| `GET /api/v1/auth/me`               | `@SelfService` | all 3 roles             |
| `/api/docs` (Swagger)               | outside Nest   | production: absent (C1) |
