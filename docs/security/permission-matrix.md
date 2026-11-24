# Permission matrix

Source of truth for **who may do what**. The block between `<!-- matrix:begin -->` and
`<!-- matrix:end -->` is generated from the permission catalog + role map + production route scan by
`pnpm --filter @bitabar/api authz:matrix`; a test regenerates it in memory and fails on any
difference. Rules: ADR-008 (`docs/adr/008-authorization.md`); how-to: `docs/security/authz.md`.

F1-05 defines permissions in code, not in the database. The active catalog contains only what
F1-05 needs plus the next two tasks (F1-07 base data, F1-08 carriers). Later phases appear in the
**planned, not active** table and are not enforced until their endpoints exist. A route with no
marker is rejected at startup and by the route-scan test.

Legend: `allow` = the role holds the permission; `deny` = it does not. `Sensitive` permissions
additionally require a `reason` and fresh intersected roles (ADR-008 Z6/Z10).

<!-- matrix:begin -->

### Permissions and roles

| Permission                 | Scope  | Sensitive | FACTORY_OPERATOR | CARRIER_ADMIN | DRIVER |
| -------------------------- | ------ | --------- | ---------------- | ------------- | ------ |
| `destination.read`         | tenant | no        | allow            | deny          | deny   |
| `destination.write`        | tenant | no        | allow            | deny          | deny   |
| `hall.read`                | tenant | no        | allow            | deny          | deny   |
| `hall.write`               | tenant | no        | allow            | deny          | deny   |
| `loader_type.read`         | tenant | no        | allow            | deny          | deny   |
| `loader_type.write`        | tenant | no        | allow            | deny          | deny   |
| `carrier.read`             | tenant | no        | allow            | deny          | deny   |
| `carrier.write`            | tenant | no        | allow            | deny          | deny   |
| `carrier_membership.write` | tenant | **yes**   | allow            | deny          | deny   |
| `carrier_quota.write`      | tenant | **yes**   | allow            | deny          | deny   |

### Routes

| Method | Path                                       | Marker               | Permission          |
| ------ | ------------------------------------------ | -------------------- | ------------------- |
| GET    | `/health/live`                             | `@Public`            | —                   |
| GET    | `/health/ready`                            | `@Public`            | —                   |
| POST   | `/api/v1/auth/login`                       | `@Public`            | —                   |
| POST   | `/api/v1/auth/refresh`                     | `@Public`            | —                   |
| POST   | `/api/v1/auth/logout`                      | `@Public`            | —                   |
| POST   | `/api/v1/auth/password/change`             | `@Public`            | —                   |
| GET    | `/api/v1/auth/me`                          | `@SelfService`       | —                   |
| GET    | `/api/v1/base/destinations`                | `@RequirePermission` | `destination.read`  |
| GET    | `/api/v1/base/destinations/:id`            | `@RequirePermission` | `destination.read`  |
| POST   | `/api/v1/base/destinations`                | `@RequirePermission` | `destination.write` |
| PATCH  | `/api/v1/base/destinations/:id`            | `@RequirePermission` | `destination.write` |
| DELETE | `/api/v1/base/destinations/:id`            | `@RequirePermission` | `destination.write` |
| GET    | `/api/v1/base/halls`                       | `@RequirePermission` | `hall.read`         |
| POST   | `/api/v1/base/halls`                       | `@RequirePermission` | `hall.write`        |
| GET    | `/api/v1/base/halls/:id`                   | `@RequirePermission` | `hall.read`         |
| PATCH  | `/api/v1/base/halls/:id`                   | `@RequirePermission` | `hall.write`        |
| DELETE | `/api/v1/base/halls/:id`                   | `@RequirePermission` | `hall.write`        |
| GET    | `/api/v1/base/halls/:hallId/terminals`     | `@RequirePermission` | `hall.read`         |
| POST   | `/api/v1/base/halls/:hallId/terminals`     | `@RequirePermission` | `hall.write`        |
| GET    | `/api/v1/base/halls/:hallId/terminals/:id` | `@RequirePermission` | `hall.read`         |
| PATCH  | `/api/v1/base/halls/:hallId/terminals/:id` | `@RequirePermission` | `hall.write`        |
| DELETE | `/api/v1/base/halls/:hallId/terminals/:id` | `@RequirePermission` | `hall.write`        |
| GET    | `/api/v1/base/loader-type-groups`          | `@RequirePermission` | `loader_type.read`  |
| POST   | `/api/v1/base/loader-type-groups`          | `@RequirePermission` | `loader_type.write` |
| GET    | `/api/v1/base/loader-type-groups/:id`      | `@RequirePermission` | `loader_type.read`  |
| PATCH  | `/api/v1/base/loader-type-groups/:id`      | `@RequirePermission` | `loader_type.write` |
| DELETE | `/api/v1/base/loader-type-groups/:id`      | `@RequirePermission` | `loader_type.write` |
| GET    | `/api/v1/base/loader-types`                | `@RequirePermission` | `loader_type.read`  |
| POST   | `/api/v1/base/loader-types`                | `@RequirePermission` | `loader_type.write` |
| GET    | `/api/v1/base/loader-types/:id`            | `@RequirePermission` | `loader_type.read`  |
| PATCH  | `/api/v1/base/loader-types/:id`            | `@RequirePermission` | `loader_type.write` |
| DELETE | `/api/v1/base/loader-types/:id`            | `@RequirePermission` | `loader_type.write` |

<!-- matrix:end -->

`/api/docs` and `/api/docs-json` are Swagger routes outside Nest: **absent in production** (owner
condition C1), present in development/test. They are not part of the generated block.

**Catalog status:** all ten permissions are in code now (T02). F1-05 had no production route;
F1-07 consumes `destination.*`, `hall.*` and `loader_type.*` today, and F1-08 will consume
`carrier.*`. `CARRIER_ADMIN` and `DRIVER` hold no data permission; every authenticated role has
`@SelfService` access to its own identity. The route classification above is locked by the
route-scan test.

## Planned, not active

These are PRD §2 responsibilities for later phases. They are **not** in the code catalog, not
enforced, and must be added together with their endpoints (ADR-008 Z2).

| Area                                                   | Role               | Scope   | Phase   | Sensitive |
| ------------------------------------------------------ | ------------------ | ------- | ------- | --------- |
| User create / disable / role assign-revoke / reset     | `FACTORY_OPERATOR` | tenant  | ≥ F1-06 | yes       |
| Load announcements: create / edit / cancel             | `CARRIER_ADMIN`    | carrier | F2      | yes       |
| Quota override approval (BR-21)                        | `FACTORY_OPERATOR` | tenant  | F2      | yes       |
| Queue policy create/edit; apply to existing (BR-12/14) | `FACTORY_OPERATOR` | tenant  | F3      | yes       |
| Mark driver absent (BR-07)                             | `FACTORY_OPERATOR` | tenant  | F3      | yes       |
| Revert free → queued load (BR-04)                      | `FACTORY_OPERATOR` | tenant  | F3      | yes       |
| Convert queued load to free (BR-04)                    | `CARRIER_ADMIN`    | carrier | F3      | yes       |
| Approve / reject driver cancellation (BR-16)           | `CARRIER_ADMIN`    | carrier | F3/F5   | yes       |
| Issue permit; swap driver/truck on permit (BR-20)      | `CARRIER_ADMIN`    | carrier | F3      | yes       |
| Manual wallet adjustment (BR-22), if any               | `FACTORY_OPERATOR` | tenant  | F4      | yes       |
| Driver reservations / time slots                       | `DRIVER`           | own     | F5      | no        |
| Reports and Excel export                               | `FACTORY_OPERATOR` | tenant  | F6      | no        |
| Tickets                                                | all roles          | scoped  | F6      | no        |
| Audit log read                                         | `FACTORY_OPERATOR` | tenant  | F1-06   | no        |

`CARRIER_ADMIN` carrier-scoped permissions become usable only in F1-08, when `users.carrier_id` and
carrier RLS exist. Until then carrier scope fails closed (403).

## Sensitive actions (guard ready, audit hook later — F1-06)

Every row requires the role, a `reason` (10–500 trimmed characters, **no control characters**),
fresh token ∩ DB roles and the `AuditHook` (no-op until F1-06). A guard denial is logged server-side
with the request id and a stable reason code only; the client never receives the permission name,
the role list or the reason text. This list is copied from plan §F.

| Action (PRD)                                       | Role               | Scope   | Phase |
| -------------------------------------------------- | ------------------ | ------- | ----- |
| User create / disable / role assign-revoke / reset | `FACTORY_OPERATOR` | tenant  | later |
| Carrier membership, monthly quota set (BR-21)      | `FACTORY_OPERATOR` | tenant  | F1-08 |
| Quota override approval (BR-21)                    | `FACTORY_OPERATOR` | tenant  | F2    |
| Policy create/edit; apply to existing (BR-12/14)   | `FACTORY_OPERATOR` | tenant  | F3    |
| Mark driver absent (BR-07)                         | `FACTORY_OPERATOR` | tenant  | F3    |
| Revert free → queued load (BR-04)                  | `FACTORY_OPERATOR` | tenant  | F3    |
| Convert queued load to free (BR-04)                | `CARRIER_ADMIN`    | carrier | F3    |
| Approve/reject driver cancellation (BR-16)         | `CARRIER_ADMIN`    | carrier | F3/F5 |
| Issue permit; swap driver/truck on permit (BR-20)  | `CARRIER_ADMIN`    | carrier | F3    |
| Manual wallet adjustment (BR-22), if any           | `FACTORY_OPERATOR` | tenant  | F4    |

In F1-05 the two active sensitive permissions are `carrier_membership.write` and
`carrier_quota.write` (both tenant-scoped, F1-08 endpoints). The rest join the catalog with their
endpoints.

## Response rules

- Insufficient role or permission → `403`, generic body, identical for every route and role.
- Row outside the principal's scope → `404`, identical to a nonexistent row and to an unknown route.
- Anonymous or invalid/expired token, disabled/deleted user, suspended/deleted tenant, or a revoked
  session on a sensitive action → generic `401`.
- A sensitive `reason` with control characters or outside 10–500 trimmed characters → `400`.
- No response names a permission, a role, a tenant/carrier or whether a resource exists.

## Changing the matrix

1. Change the catalog (`security/authz/permissions.ts`) and/or the role map
   (`security/authz/role-permissions.ts`) in a reviewed commit.
2. Run `pnpm --filter @bitabar/api authz:matrix` and commit the regenerated block.
3. Add or update tests: exhaustive role × permission, BFLA route × role, sensitive `reason`, and the
   matrix sync test. A changed matrix with no test change fails CI.
4. Do not edit the generated block by hand; edit the catalog or role map and regenerate.
