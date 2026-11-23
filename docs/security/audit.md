# Audit, idempotency and outbox — developer guide

How to record changes, make a mutating endpoint idempotent and enqueue an external side effect. Decisions:
ADR-009 (audit), ADR-010 (idempotency/outbox); plan: `docs/plan/F1-06.md`; DB rules:
`docs/security/rls.md`. This file is the checklist a reviewer uses.

## Audit — what is recorded

| Action                                  | When                                         | Actor       | Before/after                         |
| --------------------------------------- | -------------------------------------------- | ----------- | ------------------------------------ |
| `auth.login.success`                    | successful login                             | user        | — (metadata: method, prior failures) |
| `auth.logout`                           | logout with a live session                   | user        | —                                    |
| `auth.session.revoked_new_device`       | BR-18 revocation of another session          | user        | session ids                          |
| `auth.refresh.reuse_detected`           | rotated-token reuse, family revoked          | user        | —                                    |
| `auth.password.changed`                 | successful password change                   | user        | —                                    |
| `auth.password.reset`                   | operator CLI reset                           | system      | —                                    |
| `user.role.assigned` / `.revoked`       | `UserRoleService` writes                     | user/system | role set before/after                |
| Any sensitive permission's handler      | `SensitiveAuditInterceptor`, success/failure | user        | via `auditChange()`                  |
| Sensitive permission, authenticated 403 | authorization guard                          | user        | — (outcome `denied`)                 |
| Domain service writes (F1-07+)          | `AuditWriter.append` in the caller's tx      | user        | via `auditChange()`                  |

**Never audited as rows:** failed logins, delay hits, non-sensitive denials, replays of idempotent requests,
health checks. Failed logins go to the structured security log only (see below). A login that stops at the
forced-password-change step creates no session and writes nothing, so it is not a row either; the completed change
records `auth.password.changed`.

**Role changes (F1-06 T06, D2).** `UserRoleService` is the only caller of the SR-05 role functions. A nonexistent,
other-tenant or soft-deleted user gets the identical generic 404 for **assign and revoke**, so neither operation is a
user-existence oracle. A real change writes `user.role.assigned`/`.revoked` with the full role-code set before and
after (`before`/`after` `{ roles: [...] }`), `metadata.roleCode`, and the actor (`user` + session, or `system` with
`metadata.tool` for the CLI). The visibility check, the role write and the row share one transaction. Idempotent
assign/revoke writes no row because nothing changed.

**`reason` is free text (owner CP1 A6).** It is capped at `SENSITIVE_REASON_MAX_LENGTH` (500, shared constant,
Zod-validated) and stored as written. **The UI must warn operators not to enter personal data** (phone numbers,
national IDs, third-party names) in a reason: it is not column-encrypted, and the warning is the only control
against a human typing PII into it.

## Guarantees

- **Success rows are atomic with the change.** `AuditWriter.append()` runs inside the caller's `TenantDb.run`
  transaction (nested `TenantDb.run` reuses it). If the change commits, the row exists; if the audit insert fails,
  the change does not commit. That failure is **not** swallowed: `PersistentAuditHook` propagates it, the
  interceptor's transaction rolls back and the request fails with 500 (fail-closed). Only `failure`/`denied` writes
  are best-effort.
- **Failure and denial rows are best-effort.** They are written after the original transaction rolled back, in a
  separate transaction, bounded by a 2 s timeout. A DB/process failure in that window loses the row; the failure is
  logged with the request id and the HTTP response is never changed. The security log still records the denial.
- **A failed best-effort write is never silent (owner CP1).** `PersistentAuditHook` logs
  `{ reqId, outcome, code: 'AUDIT_WRITE_FAILED', err: sanitizeErrorForLog(error) }` — structural fields only, never
  the payload, the reason text or the IP. There is no metrics hook in F1-06; when one is added it must increment
  `audit.write_failed` at the same point.
- **Final HTTP status.** Success rows store the status Nest will send: `@HttpCode` metadata first, otherwise the
  POST default 201 / otherwise 200, and the handler's own status when it used `@Res()`. Failure rows store the
  error's status (500 for an unknown error); denial rows store 403. This closes the F1-05 “outcome ≠ final status”
  note. Caveat: a handler that uses `@Redirect` (or lets a later interceptor/Nest layer change the status after
  this one settles) is recorded with the derived status; no such route exists in F1-06.
- **The row describes the changed resource, not the route.** When the handler called `auditChange()`, the row's
  `resource_type`/`resource_id` come from the LAST change (the snapshot allowlist is keyed by that entity), and
  `metadata.handler` keeps the `Controller.method` for traceability. Without a change, the row describes the
  handler. Multiple changes: the last one fills `before`/`after`, `metadata.changeCount`/`resources` list them.
- **Carrier scope.** The interceptor opens the full principal scope (`tenantId` + `carrierId` when present), and
  the hook reuses that active scope instead of re-entering `TenantContext.run` (a different scope would be rejected
  while the transaction is open). Guard denial rows have no active scope and open their own.
- **Append-only.** `bitabar_app` has `SELECT, INSERT` only; a row trigger blocks UPDATE/DELETE and a statement
  trigger blocks TRUNCATE for every role, including the migration owner. The migration fails closed if a REVOKE
  did not stick (`42501 AUDIT_REVOKE_INCOMPLETE`).
- **No production read endpoint** in F1-06. Reading is F6 reporting; a future endpoint must enforce
  `tenant_id` scoping and never expose `ip_enc` or unmasked snapshots to a non-privileged role.

## How to add an audited action (review checklist)

1. Define the action name as `resource.verb` (lowercase, dot-separated, ≥2 segments; CHECK in the table).
2. Add an entity entry to `toAuditSnapshot` **only if** before/after is meaningful. The entry is an allowlist of
   column names; PII columns map to the masking helpers; `*_enc`, `*_hash`, password/token/cookie columns are never
   allowed. A new column is invisible to audit until it is added deliberately.
   Size caps are enforced by both sides with the **same measure**: the DB CHECK is `octet_length(col::text) ≤ 16384`
   and `AuditWriter` counts the same jsonb text form (separator spaces included) before SQL, so a boundary snapshot
   is rejected as `AUDIT_ENTRY_INVALID` instead of aborting the caller's transaction on a CHECK. `reason` is counted
   in characters (code points), matching PostgreSQL `length()` — a Persian + emoji string of 500 characters is valid.
3. In the service, after the write succeeds and inside the same transaction, call
   `auditChange({ resourceType, resourceId, before, after })`, then `AuditWriter.append({ action, outcome:
'success', … })` — or let a sensitive route's interceptor do it. The row then names the changed entity/id (the
   snapshot allowlist key must be that `resourceType`).
4. Include `reason` **only** where the route schema declares it; never invent a reason for a non-sensitive action.
5. Add a test: success row exists with the right tenant/actor; a rolled-back business change leaves no row; the
   PII sweep (no phone, national id, password, token, cookie or raw IP in any text/jsonb column) stays green.
6. If the action's tenant comes from a request body — stop, it is a design defect; tenant is always from context.

## Actor, IP and request id

- `actor_type = 'user'`: `actor_user_id` from the verified principal; `actor_session_id` = token `sid`.
- `actor_type = 'system'`: CLI, seed, worker; `metadata.tool` names the tool. No user id.
- IP: `ip_enc` (AES-256-GCM, AAD `tenant:audit_logs.ip_enc:<id>`) + `ip_hash` (keyed blind index, field
  `audit_logs.ip`). Both NULL or both set. **Never** store or log the raw IP; lookups use `ip_hash`.
  Confirmed for T05: this is the same `PiiService` pattern as users — encryption AAD = tenant + column + row id
  (the row id is generated before encrypting), blind index = HMAC over `tenant:field:normalized`; the integration
  test decrypts with that exact AAD and fails if it differs.
- `request_id` is the server-generated id (`genReqId: randomUUID`), trimmed; a client header is ignored.

## Failed logins and the security log

No audit row (owner Q1). The auth layer logs `{ reqId, reasonCode, identifierHash, ip }` — never the raw username,
phone or tenant code (ADR-007 A11 key hygiene). The next successful login records `prior_failed_attempts`, so a
delay/lockout episode is reconstructable from the log plus that field.

## Idempotency — caller contract

- Any POST/PUT/PATCH/DELETE route under `@RequirePermission` **must** carry `@Idempotent()`; startup and the
  route-scan test reject a missing marker (opt-out allowlist empty; the marker on a GET is rejected too).
- The client sends `Idempotency-Key: ^[A-Za-z0-9_-]{16,128}$`; missing/malformed → `400
IDEMPOTENCY_KEY_REQUIRED`. The key is opaque, never logged — the pino access log redacts
  `req.headers["idempotency-key"]` and the structural redactor treats `idempotency-key`/`idempotency_key` as a
  secret key (T07 review HIGH).
- Same key + same payload → replay (`Idempotent-Replayed: true`, stored status and body only); same key +
  different payload → `422 IDEMPOTENCY_KEY_REUSED`; a concurrent duplicate waits on the unique key and, when the
  lock wait expires (SQLSTATE 55P03), gets `409 IDEMPOTENCY_IN_PROGRESS` with `Retry-After: 1` — never a 500.
- **Only successful responses are stored (owner CP4).** Any thrown error — including a business 4xx — rolls back
  the claim and the handler's writes; a retry with the same key re-executes. Do not design a route that depends
  on a cached failure.
- **Handler contract (owner CP4).** A marked handler may only cause effects **inside the request transaction**:
  an outbox enqueue in the same transaction is the pattern; a direct SMS/HTTP/payment call is a review defect,
  because the 8000 ms cap aborts the transaction but cannot cancel JS work. The same cap is applied as `SET
LOCAL statement_timeout`, so the database side stops; a DB-bound handler that overruns answers `503
IDEMPOTENCY_TIMEOUT` and stores no key.
- **Fingerprint surface (owner CP4).** SHA-256 over canonical `{params, query, body}` only — sorted keys, array
  order kept, missing body ≡ `null`. The route is in `METHOD + route template`, the principal (tenant + user) is
  in the scope key, and **no header** is included (`Idempotency-Key` and `Authorization` included). One intent on
  another route or by another principal is a separate row; a rotated token still replays.
- Scope is tenant + user + method + route template; a key is single-use per route and expires after 24 h. An
  expired row is taken over by a CAS update: two racing duplicates still produce exactly one handler execution
  and one row (the loser replays or gets 409).
- The response stored for replay is encrypted (AAD `tenant:idempotency_keys.response_enc:<rowId>`) and capped at
  64 KiB; over the cap is a generic 500 with a code-only log and no stored body. Never put a token, password or
  cookie in a replayable response body.
- **Replay writes no audit row.** The original request's row describes the one side effect. The interceptor
  flags a replay, so `SensitiveAuditInterceptor` skips its success row when both features meet on one route.

## Outbox — adapter contract

- Enqueue inside the business transaction with `OutboxWriter.enqueue({ topic, dedupeKey, payload })`. Duplicate
  `(tenant, topic, dedupeKey)` is a no-op. The payload is encrypted (AAD
  `tenant:integration_outbox.payload_enc:<rowId>`) and capped at 64 KiB; it may carry a phone number.
- **Delivery is at-least-once with no global ordering guarantee.** Workers run concurrently, retries move a row
  back in time, and topics can interleave. A consumer needing order must carry a sequence/version in the payload
  and order at the destination.
- The adapter is called outside any transaction with a timeout; it receives `outbox.id` as its idempotency key and
  **must** dedupe on it (the mock enforces this). `OUTBOX_ADAPTER_TIMEOUT_MS` must be strictly below
  `OUTBOX_LEASE_SECONDS × 1000` — startup fails otherwise, so a send can never outlive its lease by design.
- Each tick, per tenant: a **pre-claim sweep** moves an expired lease whose `attempts >= max_attempts` to `dead`
  (`LEASE_EXPIRED_MAX_ATTEMPTS`); the claim itself refuses `attempts >= max_attempts`, so one poison row cannot
  block the batch. Tenants are processed in isolation (try/catch per tenant, code-only log).
- Retries use exponential backoff with jitter; `dead` after `max_attempts`. `last_error_code` is a stable code —
  never provider text, never a payload value. Every `dead` transition emits `{ eventCode: OUTBOX_DEAD_LETTER,
outboxId, topic, errorCode, tenantId }` and increments the metrics seam; no payload is logged. `eventCode` is on
  the log allowlist so these operational events stay visible while OTP-like `*code` keys remain redacted.
- Worker flags: `OUTBOX_WORKER_ENABLED` (default off), `OUTBOX_POLL_MS`, `OUTBOX_BATCH_SIZE`,
  `OUTBOX_LEASE_SECONDS`, `OUTBOX_MAX_ATTEMPTS`, `OUTBOX_BACKOFF_BASE_SECONDS`, `ADAPTER_MOCK_ENABLED`. A
  **production** process refuses the worker and the mock flag (config validation and boot provider check). Real
  providers land later behind the same interface with a feature flag (GUIDELINES §12).

## Retention

`audit_logs` is not purged in F1-06 (owner C2). Owner-run retention in F8:
`docs/runbooks/audit-retention.md`. The purge runs as the migration owner (needs trigger disable in a reviewed
migration); the trigger blocks DELETE for every role including the owner.

**Owner can still disable the trigger (owner CP2).** The triggers stop UPDATE/DELETE/TRUNCATE for every role, but
they do not stop `ALTER TABLE audit_logs DISABLE TRIGGER` / `DROP TRIGGER` — those are table-owner operations. The
migration `0012` fails closed if any trigger is missing or not `tgenabled = 'O'`, and an integration test asserts
the same state, but nothing prevents a later owner session from turning one off. Therefore: production owner
credentials are used **only** by the migration runner, are never handed to application or operator tooling, and
trigger state is monitored (F8 runbook item; see AGENT.md §7). `bitabar_app` is not the owner and has
`TRIGGER`/`REFERENCES` revoked, so it cannot change this.

`idempotency_keys` expired rows are swept
by the runtime job (DELETE allowed only for `expires_at < now()`); `integration_outbox` `sent` rows are kept until
the F8 retention decision.

## Verification

- `pnpm --filter @bitabar/api test:int` includes `test/audit-append-only.int.test.ts`,
  `test/audit-writer.int.test.ts`, `test/idempotency.int.test.ts`, `test/outbox.int.test.ts`,
  `test/user-role-oracle.int.test.ts`.
- Privilege matrix: `bitabar_app` on `audit_logs` → SELECT, INSERT only; `idempotency_keys` → no DELETE of live
  rows; `integration_outbox` → no DELETE/TRUNCATE.
- Definer catalog test must still report exactly 6 functions.
- Dev check: seed + CLI role change, then as owner `SELECT action, outcome, before, after, ip_hash FROM
audit_logs` — no plaintext phone, national id or raw IP.
