# ADR-011: Base data — destinations, halls/terminals and loader types

2026-11-23 | Accepted (owner plan approval F1-07, 2026-11-23; B1–B12 and R1–R5 binding)

**Context:** PRD §5.2 requires operator-managed base data before load announcements (F2) and the queue
engine (F3): destinations (one queue per destination, PRD §3, BR-01), halls with terminals (§3 "Hall"), and
loader types as **data, not an enum**, with grouping (BR-06 matches a driver's vehicle to an announcement's
loader type/group, including a "second loader group"). These are the project's **first real business
endpoints**, so they must prove the F1-05/F1-06 contracts end-to-end: `@RequirePermission`, `@Idempotent`,
audit before/after, strict Zod + mass-assignment scan, soft delete, pagination, RLS/U14 and the permission
matrix. Carriers are out (F1-08), as are the web UI (F1-09), announcements (F2) and the queue engine (F3).

**Decisions:**

- **B1 — REST under `/api/v1/base/*`.** Single path per handler; 25 routes; no new or changed permission.

  | Resource           | Routes                                                                                         | Permission                    |
  | ------------------ | ---------------------------------------------------------------------------------------------- | ----------------------------- |
  | Destinations       | `GET/POST /base/destinations`, `GET/PATCH/DELETE /base/destinations/:id`                       | `destination.read` / `.write` |
  | Halls              | `GET/POST /base/halls`, `GET/PATCH/DELETE /base/halls/:id`                                     | `hall.read` / `.write`        |
  | Terminals          | `GET/POST /base/halls/:hallId/terminals`, `GET/PATCH/DELETE /base/halls/:hallId/terminals/:id` | `hall.read` / `.write`        |
  | Loader-type groups | `GET/POST /base/loader-type-groups`, `GET/PATCH/DELETE /base/loader-type-groups/:id`           | `loader_type.read` / `.write` |
  | Loader types       | `GET/POST /base/loader-types`, `GET/PATCH/DELETE /base/loader-types/:id`                       | `loader_type.read` / `.write` |

  `POST` → 201 `{data}`, `PATCH` → 200 `{data}`, `DELETE` → 204. Every mutating route (15) carries
  `@Idempotent()`; the boot scan and route-scan tests enforce it (ADR-010 L10).

- **B2 — Fields.** All body/query/params schemas are `.strict()`; ids are UUID params.
  - destination: `name` (2–64), `provinceName` (0–64, optional), `isActive` (default true), `displayOrder`
    (int 0–9999, default 0).
  - hall: `name`, `isActive`, `displayOrder`.
  - terminal: `name`, `isActive`, `displayOrder`; the hall comes **only** from the path and is verified in
    scope.
  - loader-type group: `name`, `isActive`, `displayOrder`.
  - loader type: `name`, `groupId` (uuid, required), `isActive`, `displayOrder`.
  - Server-only and never accepted from a client: `id`, `tenantId`, `nameKey`, `version`,
    `createdAt/updatedAt/deletedAt`. The forbidden-key scan already rejects `tenantId`, `status`,
    `createdBy`, `carrierId`, `role` and their variants on body/query/params; this is why the plan uses
    `isActive`, never `status`.
- **B3 — Listing.** `@ZodQuery` strict: `page` ≥ 1 (default 1), `pageSize` 1–100 (default 50), optional
  `isActive` (bool), `q` (name substring on `name_key`, 1–64, LIKE-escaped), `sort` from an allowlist
  (`displayOrder`, `name`, `createdAt`; a leading `-` means descending; default `displayOrder,name`; id is
  the final tiebreak). Response `{data, meta: {page, pageSize, total}}`. Soft-deleted rows are never listed.
  Loader types additionally filter by `groupId`.
  - **R4 — known search limit (accepted).** `q` is a `LIKE` on `name_key` with **no trigram index**. This
    is acceptable for the expected volumes (tens to hundreds of rows per tenant); it is recorded here so a
    future phase can add an index or full-text search if a tenant's base data grows much larger.
- **B4 — Uniqueness.** `name_key` is the server-side normalization of `name` (NFC, trim, collapse
  whitespace, ZWNJ→space, Arabic ي/ك→Persian ی/ک, Persian/Arabic digits→ASCII, lowercase). Partial UNIQUE
  indexes `WHERE deleted_at IS NULL`: destinations `(tenant_id, name_key)`; halls `(tenant_id, name_key)`;
  terminals `(tenant_id, hall_id, name_key)`; groups `(tenant_id, name_key)`; loader types
  `(tenant_id, name_key)` — **not** per group, because a type name means one vehicle class across the
  tenant. A soft-deleted name is reusable. A `23505` maps to `409 CONFLICT` with a generic body and
  `details.field = "name"` (4xx details are allowed).
- **B5 — Soft delete with an in-use guard.** `DELETE` sets `deleted_at`. A parent referenced by a **live**
  child answers `409 IN_USE` (generic body, no child ids): a hall with live terminals, a group with live
  loader types. The check runs in the same transaction with the parent row locked `FOR UPDATE`, so a
  concurrent child insert (which also locks the parent) cannot create a live child under a row being
  deleted.
  - **AT-11 — binding locking rule (owner-approved at CP2).** The composite foreign key alone does NOT
    serialise a parent soft delete against a child insert: PostgreSQL takes only a `KEY SHARE` lock on the
    parent for the FK check, and `KEY SHARE` does not conflict with the `UPDATE` that sets `deleted_at`.
    Therefore **both** directions must lock explicitly, inside the same transaction:
    1. a child create **or move** first `SELECT … FOR UPDATE` the live parent row (hall or group) before
       inserting/updating the child; a missing/deleted parent is the generic 404;
    2. the parent soft delete first `SELECT … FOR UPDATE` its own row, then checks for live children in the
       same transaction, and only then sets `deleted_at`.
       T05/T06 must ship a concurrency test: 50 iterations of parallel (delete-parent vs create-child) on the
       real container, asserting that no live child ever exists under a deleted parent (the loser either
       loses the row lock and gets `409 IN_USE`, or its insert commits first and the delete then sees it).
  - **R3 — `ReferenceGuard` stays minimal:** one interface
    `{ isReferenced(tx, scope, id): Promise<boolean> }`, one in-transaction check for halls and one for
    groups, one unit test, registered directly in those two services. There is no registry framework and no
    generic plugin layer; F2/F3 add their own checks by calling the same small interface. Creating a child
    under an **inactive** parent is allowed; under a **deleted** parent it is the identical 404.
  - **`isActive = false` has no queue semantics yet.** F1-07 only stores and filters the flag; what an
    inactive destination/hall/loader type means for ordering, allocation or announcements is defined by
    the queue engine in **F3**. Deactivation is the normal operator alternative to deletion and does not
    cascade or hide live children.
- **B6 — Optimistic concurrency.** Every row has `version int`; `PATCH` and `DELETE` carry
  `expectedVersion`; a mismatch answers `409 STALE_VERSION`. Two operators can never silently overwrite
  each other.
  - **R5 — `DELETE` takes `expectedVersion` in the query string** (`?expectedVersion=n`). Because the
    idempotency fingerprint is exactly `{params, query, body}` (ADR-010 L9), this value is part of it. It
    is an integer carrying no sensitive data, and a different expected version is intentionally a different
    intent (a different fingerprint), not a replay.
- **B7 — Scope and IDOR.** Repositories accept only an `AccessScope`; every query is constrained by
  `tenant_id AND id` (terminals additionally by `hall_id`). Another tenant's row, a deleted row and a
  nonexistent row all answer the **same** 404. Composite foreign keys `(tenant_id, hall_id) → halls(tenant_id,
id)` and `(tenant_id, group_id) → loader_type_groups(tenant_id, id)` make a cross-tenant parent
  impossible at the database. A body `groupId` that belongs to another tenant, is deleted or does not
  exist answers the same generic 404 — no existence oracle.
- **B8 — Audit.** Every write appends directly via
  `AuditWriter.append({resourceType, resourceId, before, after, ...})` in the service transaction (atomic and
  fail-closed; ADR-009). These permissions are non-sensitive, so `SensitiveAuditInterceptor` does not run and
  `auditChange` would throw outside its scope — the direct append is the intended path, not a shortcut. Actions
  are `<entity>.created|updated|deleted` (`destination.updated`, `terminal.deleted`,
  `loader_type_group.created`, …). **The five tables deliberately have no `created_by` column:** the actor
  is recorded by `audit_logs` (each write appends in the same transaction), so a per-row FK
  would duplicate the audit trail and add a write-ordering dependency. Reads that need the author join
  `audit_logs` by `resource_type`/`resource_id`. Snapshot allowlists for the five entities contain the row `id`,
  the business fields, `version` and `deletedAt`; `name_key` is not needed and no PII exists. `metadata` carries only structural
  keys `{hallId}` / `{groupId}`, plus `{groupId, previousGroupId}` on a move (both structural UUIDs) — this is the first consumer, so the known "metadata has no allowlist"
  debt (F1-06 T09 L1) is avoided by contract. These permissions are non-sensitive, so no `reason` is
  accepted. An idempotent replay writes no second audit row (ADR-010).
- **B9 — Idempotency.** All 15 mutating routes carry `@Idempotent()`; responses are far below the 64 KiB
  stored-body cap. Effects stay inside the request transaction; no outbox topic is needed yet.
- **B10 — Database rules.** Migration `0017` (generated) creates the five tenant-owned tables;
  `0018` (custom) applies the RLS template to all five, revokes `DELETE`/`TRUNCATE` from `bitabar_app`
  (soft delete only), and fails closed with `BASE_RLS_INVALID` / `BASE_POLICY_INVALID` /
  `BASE_GRANTS_INVALID` if the flags, policies or privilege set did not stick. CHECKs: name length,
  `display_order BETWEEN 0 AND 9999`, `version >= 1`, `name_key <> ''`. **The upper bound of the
  `name_length` CHECK is unreachable in practice:** `name varchar(64)` rejects a 65-character value
  first with `22001`, so the CHECK's `<= 64` is a redundant backstop behind the column type (the test
  pins 22001; the API's 2–64 gate is the primary control). **No new function and no new trigger — the
  `SECURITY DEFINER` catalog stays at exactly 6.**
- **B11 — Boundaries.** Code lives in `src/modules/base-data/{destinations,halls,loader-types}/`
  (controller/service/repository/schemas); shared helpers in `src/common/pagination/` and
  `src/common/text/name-key.ts`. Each new controller is added to `PRODUCTION_CONTROLLERS` and to the
  `authz:matrix` script **in the same commit**; the matrix is regenerated per task.
- **B12 — Operator UI split.** F1-09 builds the web skeleton, login and operator shell; the base-data pages
  follow as a separate F1-09 sub-task with **3 pages** matching the PRD routes — `/destinations` (table +
  drawer form + active toggle), `/halls` (table; terminals edited in the hall detail drawer) and
  `/loader-types` (two tabs: groups, types), with default columns plus a column chooser (CLAUDE.md §5).
  This is confirmed again at F1-09 start.

**Alternatives considered:**

- **Hard delete or cascade soft delete** — rejected: history and audit must survive, and a cascade makes
  one operator action silently remove a hall's terminals. The owner chose blocking `409 IN_USE` (Q2).
- **Loader type as an enum** — rejected by PRD: loader types are tenant-managed data and change over time.
- **Global name uniqueness / uniqueness on name + province** — rejected: names are meaningful per tenant;
  the owner chose live-row uniqueness per tenant (Q1). Province stays an optional display attribute.
- **A full reference-guard registry** — rejected in this phase (R3): an interface plus two direct checks is
  enough for the only two parent/child relationships that exist; F2/F3 can extend it when they add a real
  reference.
- **A trigram index for `q` now** — deferred (R4): the volume does not justify it; adding it later is a
  forward migration with no API change.
- **`PUT` with full replacement** — rejected: `PATCH` with `expectedVersion` expresses the operator's
  intent and keeps request bodies minimal.

**Accepted risks:**

- `q` performs a sequential `LIKE` scan on `name_key`; bounded by the small per-tenant row counts (R4).
- Clients must send `expectedVersion` on update/delete; a missing value is a 400, not a silent overwrite.
- `isActive = false` is stored but has no ordering/queue meaning until F3 defines it. Until then an
  inactive row is still a valid parent and still visible to F2 reads unless a later phase decides otherwise.
- Soft-deleted rows are retained and not restorable through the API in F1-07; a restore flow is a future
  product decision.
- Deleting a destination/hall is soft only; DB-level `DELETE`/`TRUNCATE` are revoked from the runtime role,
  so a retention purge is an owner/runbook operation (F8 pattern).

**Consequences:**

- F1-07 adds five tenant-owned tables (`0017`, `0018`), all covered automatically by the U14 guard.
- The route scan now sees 25 new routes; `PRODUCTION_CONTROLLERS` and the matrix script gain three
  controllers, and the permission matrix is regenerated.
- These are the first consumers of `@Idempotent`, `AuditWriter` and `AccessScope` in a real endpoint, which
  validates those contracts for every later module.
- The definer catalog and the public/self-service allowlists are unchanged.
