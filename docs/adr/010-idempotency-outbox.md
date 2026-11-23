# ADR-010: Idempotency keys and the transactional outbox

2026-11-22 | Accepted (owner plan approval F1-06, 2026-11-22, conditions C1/C4/C6)

**Context:** GUIDELINES §5.4 requires every state-changing request to carry an `Idempotency-Key` and to store its
result for 24 hours; §12 requires the Outbox pattern for every external call with retry and without duplicate side
effects, with `Mock` and `Real` implementations behind an interface and a feature flag. No endpoint in the project
is mutating yet (F1-05 added none), so this phase builds the mechanism and proves it on test-only probe routes;
F1-07 is the first real consumer. The owner approved the plan with **C1** (a handler time cap), **C4** (exact SQL
of every migration approved before writing; definer catalog stays 6) and **C6** (no new HTTP endpoint), and chose
the **Postgres poller** over Redis/BullMQ for the worker (Q3).

**Decision — Idempotency (L8–L11):**

- **L8 — One-transaction claim.** `@Idempotent()` is a Nest interceptor. For a marked route it opens
  `TenantContext.run({ tenantId })` + one **outer** `TenantDb.run` and, inside that transaction:
  `SET LOCAL lock_timeout` → `INSERT … ON CONFLICT DO NOTHING` the claim row → run the handler (its repositories
  reuse the same transaction via `TenantDb`'s nested reuse) → `UPDATE` the row to `completed` with the status and
  the encrypted response → commit. Because the claim is never visible before the handler commits, a crash or a
  rollback leaves **no row**: retrying with the same key simply runs the handler again. There is no stale
  `in_progress` state to clean up.
  - **Concurrent duplicate:** the second request blocks on the unique key. If the first commits, the second sees
    `completed` and **replays**; if the lock wait exceeds `IDEMPOTENCY_LOCK_TIMEOUT_MS` (default 2000), it answers
    `409 IDEMPOTENCY_IN_PROGRESS` with `Retry-After: 1`.
  - **Handler cap (owner C1; amended at CP4):** `IDEMPOTENCY_HANDLER_TIMEOUT_MS` (default **8000**, bounds
    1000–30000) bounds how long a handler may hold the claim and its rows. A timeout aborts the transaction, so
    **the key is not stored** and a retry with the same key executes again; the client gets a generic `503
IDEMPOTENCY_TIMEOUT`. `Promise.race` does **not** cancel the handler, so the same value is applied as `SET
LOCAL statement_timeout`, which stops the database side; JS work that already left the process cannot be
    stopped. **Rule (owner CP4 change 1):** a `@Idempotent()` handler may only cause effects inside the request
    transaction — an outbox enqueue in the same transaction is the pattern; a direct SMS/HTTP/payment call is a
    review defect. The default is above the DB statement timeout (5000 ms) so an ordinary slow query surfaces as
    its own error first, unless the route's cap is configured lower.
  - **Lock contention (owner CP4 change 3):** when the duplicate's wait on the unique key exceeds
    `IDEMPOTENCY_LOCK_TIMEOUT_MS` (default 2000), PostgreSQL raises SQLSTATE `55P03`; the interceptor translates
    it to `409 IDEMPOTENCY_IN_PROGRESS` with `Retry-After: 1` — never a 500. A DB statement killed by the aligned
    `statement_timeout` (`57014`) maps to the same `503` as the JS cap.
- **L9 — Key semantics.**
  - Header `Idempotency-Key`, `^[A-Za-z0-9_-]{16,128}$`; missing or malformed on a marked route → `400
IDEMPOTENCY_KEY_REQUIRED`. The key is opaque and never logged.
  - Scope is `(tenant_id, user_id, route_key, idem_key)`, where `route_key = METHOD + " " + route template`
    (e.g. `POST /api/v1/base/destinations`) — **not** the raw URL, so a query string cannot split a scope.
  - Fingerprint = SHA-256 of a canonical JSON of `{params, query, body}` (recursively sorted keys, array order
    kept, `undefined` omitted). Stored as `bytea(32)`. **Exactly these three surfaces (owner CP4 change 4):** the
    route and the principal are dimensions of the scope key, and **no header** — including `Idempotency-Key` and
    `Authorization` — is part of it, so a replay with a rotated token still matches and transport metadata can
    never turn one intent into two.
  - Same key + same fingerprint + `completed` → **replay**: stored status and JSON body, plus
    `Idempotent-Replayed: true`. Headers are not replayed (only status + body).
  - Same key + different fingerprint → `422 IDEMPOTENCY_KEY_REUSED`, generic body (no diff, nothing about the
    original payload).
  - **Only successful responses are stored (owner CP4 change 5).** Any thrown error — a business 4xx included —
    rolls the transaction back: no row, no stored body, and a retry with the same key re-executes. This is the
    documented contract, not an accident: a 4xx is a decision about one attempt, not a result to cache for 24 h.
  - Expired row (`expires_at < now()`, 24 h from `IDEMPOTENCY_TTL_HOURS`, DB clock) → a CAS `UPDATE … WHERE
expires_at < now()` takes it over and the handler runs as a new request. When two duplicates race the takeover,
    only one CAS can match (the other waits, sees the moved `expires_at`, and replays or answers 409), so exactly
    one handler executes and the table keeps one row (owner CP4 change 2; test proves it).
  - Tenant, user and route key always come from the server (principal + route metadata), never from the request.
- **L10 — Coverage.** Every production `@RequirePermission` route with POST/PUT/PATCH/DELETE must carry
  `@Idempotent()`; the opt-out allowlist is **empty**. The boot check and the route-scan test enforce it (a new
  mutating route without the marker fails startup and CI). `@Public` auth routes are exempt — they already have
  their own rotation/CAS semantics (ADR-007 A8/A19) — and `@SelfService` is GET-only.
- **L11 — Storage hygiene.** `response_enc` is encrypted with `PiiService` (AES-256-GCM, AAD
  `tenant:idempotency_keys.response_enc:<rowId>`) and capped at 64 KiB; a larger response is a generic 500 and is
  logged, never stored in plaintext. A replay decrypts it inside the tenant scope; a ciphertext moved to another
  row or tenant fails to decrypt. DELETE is allowed only through a RESTRICTIVE policy `expires_at < now()`, so the
  runtime role cannot delete a live key; cleanup deletes expired rows per tenant. Replay is not a new mutation, so
  it writes **no** second audit row — the original audit row describes the one side effect.

**Decision — Outbox (L12–L14):**

- **L12 — Producer inside the transaction.** `OutboxWriter.enqueue({ topic, dedupeKey, payload })` inserts into
  `integration_outbox` in the caller's transaction, so a business change and its outgoing message commit together.
  `payload_enc` is encrypted (payloads may include a phone number), `topic` matches `^[a-z][a-z0-9_.]{2,63}$`,
  and the unique `(tenant_id, topic, dedupe_key)` makes a duplicate enqueue a no-op.
- **L13 — Postgres poller (owner Q3).** A Nest module behind `OUTBOX_WORKER_ENABLED` (off by default in test and
  production until F8). Each tick iterates active tenants through the existing `app.list_tenants()` and, per tenant,
  first runs a **pre-claim dead sweep** (`status='processing' AND locked_until < now() AND attempts >=
max_attempts` → `dead`, `last_error_code='LEASE_EXPIRED_MAX_ATTEMPTS'`), then claims a batch with `… WHERE
attempts < max_attempts AND ((status = 'pending' AND next_attempt_at <= now()) OR (status = 'processing' AND
locked_until < now())) ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT n`, marks `processing` with
  `lock_token` and `locked_until`, commits, calls the adapter **outside** any transaction with a timeout, and
  CAS-updates on `(id, lock_token)` to `sent` or back to `pending` with exponential backoff and jitter — `dead`
  after `max_attempts`. **The sweep and the `attempts < max_attempts` predicate mean `attempts` can never exceed
  the ceiling and one poison row can never break the tenant's batch (owner CP5 change 1).** Each tenant is wrapped
  in try/catch: a failing or suspended tenant never stops the others, and the log carries a structural event code
  only (owner CP5 change 2). The lease (`locked_until`) recovers a worker that dies mid-send. `last_error_code` is
  a stable sanitized code; provider text is never stored or logged. **No new `SECURITY DEFINER` function** — the
  loop uses the existing tenant list function and runs inside `TenantDb` per tenant.
  - **Every transition to `dead` emits a sanitized event** (`eventCode: OUTBOX_DEAD_LETTER`, topic, outbox id,
    error code, tenant id — no payload) and increments the outbox metrics seam, so a dead letter is never silent
    (owner CP5 change 6). `OUTBOX_ADAPTER_TIMEOUT_MS` must be strictly below `OUTBOX_LEASE_SECONDS × 1000`;
    startup fails otherwise (owner CP5 change 4). A production process refuses `OUTBOX_WORKER_ENABLED=true` and
    `ADAPTER_MOCK_ENABLED=true`, at config validation and again in a boot provider check (owner CP5).
  - Rejected: BullMQ/Redis now (a second runtime dependency and still needs this table for transactional enqueue;
    Redis arrives in F3/F5 for queue locks and the allocation job, behind the same dispatcher interface).
- **L14 — At-least-once with no duplicate side effects and no ordering guarantee.** Delivery can repeat after a
  crash between send and mark, and **there is no global ordering guarantee**: workers run concurrently, a retry
  moves a row back in time, and a later-enqueued topic may be delivered first. A consumer that needs order must
  carry its own sequence/version in the payload and order at the destination (ADR-010 owner CP5 change 3).
  The adapter receives
  `outbox.id` as its idempotency key; `MockAdapter` (topic `mock.echo`, flag `ADAPTER_MOCK_ENABLED`) dedupes by it.
  A test kills the worker between send and mark and asserts exactly one effect. Real providers must implement the
  same contract (documented in `docs/security/audit.md` §Outbox).

**Owner conditions:**

- **C1** handler time cap — above (default 8000 ms, timeout ⇒ rollback, no key, retry executes, 503).
- **C4** exact migration SQL shown and approved at CP4 (0013/0014) and CP5 (0015/0016); the definer catalog stays
  exactly 6.
- **C6** no new HTTP endpoint; all probes are test-only and refused by the production boot scan.

**Alternatives considered:**

- **Redis for idempotency** — rejected: the claim must be atomic with the business change; a Redis key cannot be
  committed with a Postgres row, and a second state store creates a divergence window.
- **Claim in one transaction, handler in another** — rejected: the exact failure mode the guideline forbids (a
  stored "success" for a change that rolled back, or a re-executed change).
- **Plaintext stored response** — rejected: a replay body can contain personal data; the PII service already
  exists.
- **Hashing the client key instead of storing it** — considered; deferred. The key is scoped to one user, one
  tenant and one route, expires in 24 h, is never logged, and is not personal data we collect. If the owner later
  prefers keys never be recoverable, the column can become a 32-byte hash without changing semantics.
- **Postgres LISTEN/NOTIFY instead of polling** — rejected for v1: polling is simpler to operate, `SKIP LOCKED`
  handles concurrency, and the volume is low; notify adds a connection edge case.
- **Immediate synchronous send after commit** — rejected: violates "no duplicate side effects" and couples
  response latency to a provider.
- **DB trigger enqueue** — rejected: a trigger cannot see the service's payload shape or topic.

**Accepted risks:**

- At-least-once delivery: a crash window can repeat a send; correctness depends on the adapter honoring the id
  key (mock enforces it; real adapters must, documented and tested per adapter).
- Idempotency rows cost storage for 24 h; response bodies up to 64 KiB per key, encrypted.
- A client that never retries after a `409` leaves its own request undone; the contract is standard and documented.
- The poller is a single in-process loop per API instance; with several instances, `SKIP LOCKED` keeps them safe,
  but throughput is bounded by `OUTBOX_POLL_MS` and the batch size.
- The idempotency key is client-supplied; the charset prevents separators but cannot prevent a client encoding
  arbitrary data in base64url. It is scoped, expiring and never logged.

**Consequences:**

- F1-06 adds two tables (`idempotency_keys`, `integration_outbox`) and their RLS migrations; both are tenant-owned
  and covered by the U14 guard.
- Every future mutating endpoint must carry `@Idempotent()`; the check refuses startup when it is missing.
- Every external side effect must go through `OutboxWriter`; a direct provider call from a request handler is a
  review defect.
- `OUTBOX_WORKER_ENABLED` defaults to off; F8 enables it explicitly and documents the poll interval.
