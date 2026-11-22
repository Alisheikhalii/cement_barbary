# ADR-009: Audit log — transactional, append-only, tenant-scoped, PII-safe

2026-11-22 | Accepted (owner plan approval F1-06, 2026-11-22, conditions C2/C3)

**Context:** PRD §5.1 requires an audit log — who, when, what, before/after, IP. GUIDELINES §4 requires
`audit_logs` to be append-only. F1-05 shipped the sensitive-action contract (ADR-008 Z10) with a **no-op**
`AuditHook`: the interface, the `reason` field and the interceptor exist, but nothing is persisted. F1-05 also
recorded debts for this phase: guard denials are not audited, the interceptor's `outcome` is not necessarily the
final HTTP status, and no audit exists for the assign/revoke role oracle. This ADR fixes the persistence model;
the implementation plan is `docs/plan/F1-06.md`.

The owner approved the plan on 2026-11-22 and answered: **Q1** failed logins do **not** become audit rows (the
structured security log carries them; the next successful login records `prior_failed_attempts`); **Q2** the
client IP is stored **encrypted** with a keyed blind index for lookup, never raw. Binding conditions relevant to
this ADR: **C2** retention purge is debt with an F8 runbook item (no purge code now); **C3** the guarantee of
atomicity applies to success rows, while failure/denial rows are best-effort.

**Decision (L1–L7):**

- **L1 — Two write paths, one table.**
  - **(a) Transactional append.** `AuditWriter.append(entry)` runs inside the **caller's** `TenantDb.run`
    transaction. `TenantDb` reuses the active transaction for the same scope (`src/db/tenant-db.ts:59-67`), so the
    audit row and the business change commit or roll back together. A missing audit row therefore means the change
    did not happen; a broken audit insert makes the change fail (fail-closed).
  - **(b) Sensitive-route hook.** The persistent `AuditHook` used by `SensitiveAuditInterceptor` must open
    `TenantContext.run({ tenantId })` **and** an **outer** `TenantDb.run` around the handler, because
    `TenantContext` is deliberately not request-scoped and no HTTP middleware opens it. The handler's repository
    calls then reuse that transaction, so a successful sensitive action and its audit row are one commit. A
    failure outcome is written after the rollback in a fresh transaction.
  - **Why one table:** an audit row must never live in a second store that can diverge from the business data.
    Rejected: an async queue writer (loses atomicity and ordering, and a lost audit becomes invisible), a separate
    audit database (second backup/restore path for a v1 with one server), and DB triggers on every table (captures
    changes but cannot carry actor, `reason` or the sensitive-action semantics, and would duplicate every write).
- **L2 — Before/after through `AuditContext`.** Domain services record what changed with
  `auditChange({ resourceType, resourceId, before, after })`; the interceptor/writer consumes it. Snapshots pass
  through `toAuditSnapshot(entity, row)`: a **per-entity field allowlist**, unknown keys dropped (a new column is
  invisible until someone adds it to the allowlist — fail-closed). Phone and national ID are replaced by the
  existing `maskPhone()` / `maskNationalId()` output. `*_enc`, `*_hash`, password hashes, tokens, cookies and
  `Authorization` values are not allowlistable at all. Each jsonb column is capped by a DB `CHECK`
  (`octet_length(col::text) ≤ 16384`, owner CP2): the text form of a jsonb value is its logical, uncompressed
  payload, so a highly compressible snapshot cannot slip under a stored-size cap. Escape-heavy JSON counts
  slightly larger than its raw bytes, which only makes the cap stricter.
- **L3 — Append-only is enforced twice.**
  - Grants: `bitabar_app` has `SELECT, INSERT` on `audit_logs`; `UPDATE`, `DELETE` and `TRUNCATE` are explicitly
    **REVOKE**d (the default privileges from `0001_rls_foundation` would otherwise grant them).
  - Triggers: a `BEFORE UPDATE OR DELETE` row trigger and a `BEFORE TRUNCATE` statement trigger call
    `app.audit_logs_block_mutation()`, a **SECURITY INVOKER** function pinned to
    `search_path = pg_catalog, pg_temp` that raises `42501` (`AUDIT_APPEND_ONLY`). The trigger also stops the
    migration owner, so an accidental owner-role `psql` session cannot rewrite history. It is not a definer
    function: the catalog stays at exactly 6 `SECURITY DEFINER` functions in schema `app`.
  - Post-condition: right after the REVOKEs, the migration checks `has_table_privilege('bitabar_app', …)` for
    all three write privileges and fails with `42501 AUDIT_REVOKE_INCOMPLETE` if any survived (the `0010`
    pattern) — a non-owner run cannot silently leave the invariant absent.
- **L4 — Actor model.** `actor_type ∈ {user, system}`; `actor_user_id` carries a composite FK
  `(tenant_id, actor_user_id) → users(tenant_id, id)`, so an audit row can never point at another tenant's user;
  `actor_session_id` is recorded without a FK (sessions are soft-revoked, and an audit row must outlive them).
  CLI and seed writes are `system` with a stable `metadata.tool`.
- **L5 — Auth events (timing-safe).** Recorded inside the transactions that already write, and only on paths that
  are never timing-compared with the unknown-user path (ADR-007 A3): `auth.login.success` (metadata `method` and
  `prior_failed_attempts`, read before the counter reset — this is how a delay episode becomes observable),
  `auth.logout`, `auth.session.revoked_new_device` (BR-18), `auth.refresh.reuse_detected` (family-revocation
  transaction), `auth.password.changed`, `auth.password.reset` (CLI), `user.role.assigned`, `user.role.revoked`.
  **Failed logins and delay hits are not rows (Q1):** an insert only on the known-account failure path would
  re-open the timing oracle closed in F1-04, and an unknown identifier has no tenant to own a row. They go to the
  structured security log with a reason code, the HMAC identifier from `rateLimitKeys` and the request id.
- **L6 — Denials and final status.** An authenticated `403` on a **sensitive** permission writes an
  `outcome = denied` row (its own transaction, best-effort, from the authorization guard); non-sensitive denials
  stay log-only (they are the common case and carry no reason). Every row stores the final `http_status`, read
  from the response at finalize — closing the F1-05 note that `outcome` alone does not necessarily equal the
  HTTP result.
- **L7 — `reason` is user text.** Stored exactly as validated by `sensitiveReasonSchema` (trimmed, 10–500, no
  control/zero-width/bidi characters). It is client-supplied prose whose truthfulness is a human control, not
  something code can verify. It is never logged verbatim by pino (T06 redaction rule) and never returned to a
  client that is not authorized to read the (future) audit view.

**What is guaranteed, and what is not (owner C3):**

- **Guaranteed:** a **success** audit row commits in the same transaction as the change it describes. If the
  business change commits, the audit row is there; if the audit insert fails, the change does not commit.
- **Not guaranteed:** `failure` and `denied` rows are written **after** the original transaction has rolled back,
  in a separate transaction. If the database or the process dies in that window, the row is lost. The failure is
  logged (request id, outcome, error class — no reason text) and the HTTP response is never changed by it. The
  security log still records the denial, so the loss is observability, not a silent authorization bypass.
- **Not built:** retention purge. `audit_logs` grows forever in F1-06 (C2). The purge is an owner-run operation
  with a retention period decided in F8 (`docs/runbooks/audit-retention.md`). Because the trigger blocks DELETE for
  **every** role — the migration owner included — the F8 purge must arrive as a reviewed migration that disables
  the trigger, deletes the expired range and re-enables it (and the post-condition must still find the triggers
  enabled). Recorded in AGENT.md §7.
- **Not built:** an audit read/report endpoint or UI. F1-06 only writes; reading is F6 reporting scope.

**Owner answers:**

- **Q1 — failed logins:** not audit rows; security log only; next success records `prior_failed_attempts`.
- **Q2 — IP:** `ip_enc` (AES-256-GCM via `PiiService`, AAD `tenant:audit_logs.ip_enc:<rowId>`) plus
  `ip_hash` (keyed blind index, field `audit_logs.ip`) for "all events from this IP" lookups. Never raw; both
  columns NULL together or set together. Logs keep the existing rule: no raw IP outside the encrypted column.

**Alternatives considered:**

- **Async audit queue** — rejected: an audit row that can be lost or reordered while the change is already
  committed is worse than no audit for compliance purposes.
- **One generic JSONB `data` column** — rejected: actor/action/resource/outcome are the query axes; typed columns
  let the DB enforce the enum, the FK and the size caps.
- **Triggers on `users`/`user_roles` to capture every change** — rejected: no actor, no reason, no tenant-safe
  session context, and it duplicates the write path; service-level `auditChange` keeps semantics.
- **Plaintext `inet` IP** — rejected by the owner (Q2): the audit table would become a second PII store.
- **Storing guard-denial rows for every 403** — rejected: volume without value; only sensitive denials are rows.
- **Audit row for every failed login** — rejected (Q1): timing oracle + no tenant for unknown identifiers.
- **`SECURITY DEFINER` append function** — rejected: no crossing is needed (the caller already has the tenant
  context), and the definer catalog is deliberately fixed at 6.

**Accepted risks:**

- Audit volume grows with every sensitive action and auth event; no purge until F8 (C2).
- `failure`/`denied` rows can be lost in a crash window (C3).
- `reason` is free text supplied by an authorized operator; it may contain personal data about a third party, by
  human choice. It is stored encrypted-at-rest only by the disk/backup layer, not column-encrypted.
- The trigger blocks UPDATE/DELETE/TRUNCATE but not `ALTER TABLE … DISABLE TRIGGER` or `DROP TRIGGER`; those are
  migration-owner operations that require a reviewed migration. A role that becomes the table owner can also drop
  the trigger — `bitabar_app` is not and must never become the owner.
- Snapshots are allowlist-based; a field added to an entity but not to its audit snapshot is not audited until the
  allowlist is extended (deliberate: no accidental PII).

**Consequences:**

- Every sensitive route's success path now pays one INSERT inside its existing transaction; failure paths pay one
  extra short transaction.
- Every new audited resource needs an entity entry in `toAuditSnapshot` and an `auditChange` call; the
  `docs/security/audit.md` checklist is the review gate.
- `audit_logs` joins the RLS inventory as a tenant-owned table; the U14 guard covers it automatically.
- The `NoopAuditHook` binding is removed in T05; a test asserts the production provider is the persistent hook.
