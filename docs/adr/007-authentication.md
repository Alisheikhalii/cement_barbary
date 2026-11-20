# ADR-007: Authentication — passwords, tokens and sessions

2026-11-20 | Accepted (owner plan approval with 8 conditions, same day)

**Context:** F1-04 adds login for the three roles (`FACTORY_OPERATOR`, `CARRIER_ADMIN`, `DRIVER`).
GUIDELINES §6.1 requires Argon2id passwords with lockout and forbids default passwords; AGENT.md §6
records the hard rule that login failures must be identical and similarly timed (no user
enumeration). Owner decisions of 2026-11-20: v1 is **password-only for every role** — SMS OTP is
designed, not built (plan §J); staff identify as `username@tenant-code` (Q1); drivers by phone (Q1
fan-out); rate limits live in Postgres behind an interface with TTL cleanup (Q2); the dev SMS
outbox is deferred together with OTP (Q3); first passwords are operator-set one-time passwords with
forced change (Q4); the password policy is split — staff 12–128 characters, drivers an 8–20 digit
PIN with a common-PIN blocklist (Q5). The owner approved the plan with 8 hardening conditions,
folded into A1–A3, A7, A8, A11, A17 and A19 below. Full plan: `docs/plan/F1-04.md`.

**Decision (A1–A20):**

- **A1 — Passwords: Argon2id** via `@node-rs/argon2` (prebuilt native binaries). Parameters come
  from env config — `AUTH_ARGON2_MEMORY_KIB` (default 19456 = 19 MiB), `AUTH_ARGON2_TIME` (2),
  `AUTH_ARGON2_PARALLELISM` (1) — with the OWASP minimum as the documented **floor**: startup
  rejects anything weaker (condition 7). Stored as the PHC string in
  `user_credentials.password_hash` (`CHECK … LIKE '$argon2id$%'`). A stored hash declaring
  parameters beyond 4 × the configured values (`ARGON2_STORED_HASH_MAX_FACTOR`) — or any malformed
  PHC — is rejected **before** Argon2 runs, so a tampered hash cannot turn `verify()` into a
  memory/CPU DoS (owner T02 fix).
- **A2 — Progressive delay instead of a hard lock** (condition 1): each consecutive failure delays
  the next attempt by `base × 2^(n-1)`, capped (env `AUTH_LOCK_BASE_SECONDS` 1 /
  `AUTH_LOCK_MAX_SECONDS` 300); counters reset on success; a delayed account gets the same generic
  401 as a wrong password — never a 429, never a "locked" message.
- **A3 — No user enumeration:** one generic failure `401 INVALID_CREDENTIALS` with identical
  status, body and headers for unknown user, malformed identifier, wrong password, delayed,
  disabled or deleted accounts; the unknown-user path runs a dummy Argon2 verify. Structural
  equality tests **plus a timing-similarity test** (condition 3): over ≥ 20 samples per failure
  kind, |Δ medians| ≤ max(50 ms, 20 %).
- **A4 — Tenant resolution at login (Q1):** the client never sends a tenant id. Staff identifier is
  `username@tenant-code`, resolved server-side; the driver phone fans out server-side over a 60
  s-cached tenant list with per-tenant blind-index HMACs (ADR-006 U8 unchanged), one DB round trip.
- **A5 — Driver login = phone + password;** a phone present in several tenants is verified against
  each match, and delay counters advance on every matched row.
- **A6 — Pluggable `CredentialMethod` interface:** `verify(input) → identity { tenantId, userId,
roles }` or the generic failure. `PasswordMethod` now; `OtpMethod` later (plan §J) with no
  changes to the login flow, token/session code or the F1-04 tables.
- **A7 — Access token (condition 8):** JWT HS256 via `jose`, TTL 10 min
  (`AUTH_ACCESS_TOKEN_TTL_SECONDS`), claims `sub/tid/sid/roles/jti/iat/exp` — **no PII**; verify
  pins `algorithms: ['HS256']` (no alg switching) and checks `iss`/`aud`/`exp`.
- **A8 — Refresh token (condition 5):** opaque 32-byte random, only its SHA-256 hash at rest;
  HttpOnly cookie `bitabar_refresh` (`Secure` except local http dev; `SameSite=Lax` — Lax already
  withholds the cookie from cross-site POSTs and the cookie endpoints are POST-only;
  `Path=/api/v1/auth` — the auth endpoints sit under the global API prefix, unlike /health; 30 d).
  Rotation on every refresh; presenting the **immediately previous** rotated token **revokes the
  whole token family** (only that one hash is retained; older tokens are simply unknown).
- **A9 — `auth_sessions`** (tenant-owned, RLS): refresh hashes, `family_id`, rotation/revocation
  fields, `ip`, `user_agent`; soft-revoke only. Concurrent refreshes are serialized by a single
  conditional `UPDATE … WHERE refresh_hash = <old>` (T05): the row lock makes exactly one replay
  win; a loser sees its token as `previous_refresh_hash` and triggers family revocation.
- **A10 — BR-18:** a successful driver login revokes the user's other sessions in the same
  transaction (last device wins).
- **A11 — Rate limiting (Q2, condition 1):** a `RateLimiter` interface over the Postgres
  `auth_rate_limits` table (fixed window, atomic upsert, lazy expiry + hourly sweep); limits per
  account (the A2 delay), per IP (`AUTH_RL_LOGIN_IP_PER_MIN`, 20) and per tenant-code
  (`AUTH_RL_LOGIN_TENANT_PER_MIN`, 60) — all env config. A Redis implementation can replace the DB
  one later without caller changes.
- **A12 — CSRF:** SameSite=Lax **plus** an Origin / `Sec-Fetch-Site` check on the cookie endpoints;
  the access token never rides a cookie.
- **A13 — Secrets from env only:** `AUTH_TOKEN_SECRET` (base64 → 32–64 random bytes), startup-checked
  distinct from both PII keys; seed passwords from `DEV_SEED_OPERATOR/CARRIER/DRIVER_PASSWORD`
  with no defaults; `.env.example` holds placeholders only.
- **A14 — Logging hygiene:** pino key-based redaction extended to passwords, tokens, cookie/auth
  headers and the future OTP keys; no password, token or phone in logs, error messages or test
  snapshots; error messages never echo the identifier.
- **A15 — Endpoints:** `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`,
  `POST /auth/password/change`, `GET /auth/me`. An authentication guard only; permission checks are
  F1-05.
- **A16 — RLS on every new table:** the verbatim template on `user_credentials` and
  `auth_sessions` with isolation probes; `auth_rate_limits` joins the U14 allowlist with a written
  reason; the guard test and its negative control stay green.
- **A17 — Pre-auth lookup via SECURITY DEFINER functions** (condition 4): `app.list_tenants()`,
  `app.auth_lookup_username(tenant_code, username)`, `app.auth_lookup_phone(pairs jsonb)` and —
  added at the T03+T04 checkpoint for the opaque-refresh design of A8, with owner approval —
  `app.auth_lookup_session(refresh_hash_hex)`, which resolves the refresh cookie to its session
  without a tenant context and flags rotated-token reuse. All four are owned by the migration
  owner, `SET search_path = pg_catalog, pg_temp` pinned, **no dynamic SQL**, minimal columns only
  (no PII, no ciphertext beyond the `password_hash` an authentication lookup exists to read),
  `EXECUTE` revoked from PUBLIC and granted to `bitabar_app` only. Enumeration tests prove unknown
  tenant-code/username/phone all return the same empty result. A catalog test asserts these four
  are the **complete** set of SECURITY DEFINER functions in schema `app`, so a fifth cannot appear
  silently.
- **A18 — Freshness at refresh:** refresh re-reads `status` and roles; a disabled or deleted user
  is revoked and gets the generic 401.
- **A19 — First password, forced change and reset (Q4, conditions 2+6):**
  `must_change_password = true` login returns **no session**, only a 5-minute single-purpose change
  token (JWT `scope: 'password_change'`); a successful change clears the flag and **revokes all
  sessions**. Operator CLI one-time passwords: short expiry (`temporary_password_expires_at`,
  `AUTH_TEMP_PASSWORD_TTL_HOURS` default 24 h), single use, stored only as the Argon2 hash, read
  from a hidden prompt or printed once to stdout — never logged or written to a file. An operator
  reset revokes all sessions too. No self-service reset in v1 (no delivery channel until §J).
- **A20 — Password policy (Q5):** staff 12–128 characters, any type; drivers a numeric PIN of 8–20
  digits plus a ~100-entry common-PIN blocklist; never equal to the login identifier; dual-role
  accounts follow the staff rule.

**Alternatives considered:**

- Redis for rate limiting — deferred (Q2): the Postgres table sits behind the `RateLimiter`
  interface, so the swap is local; Redis earns its place with queues/notifications later.
- A permissive `bitabar_auth` DB role instead of definer functions — rejected: it would expose
  whole columns to that role; a function returns at most one row of minimal columns.
- A hard 15-minute lockout — rejected by the owner (condition 1): knowing a driver's phone must not
  be enough to keep that driver locked out.
- `SameSite=Strict` on the refresh cookie — deferred with a stated reason (condition 5): Lax
  already blocks cross-site POSTs to our POST-only cookie endpoints; re-evaluate when the SPA
  ships.
- Asymmetric JWT keys — rejected: one issuer and one verifier in v1; HS256 is sufficient.
- Self-service "forgot password" — rejected for v1 (Q4): there is no delivery channel until SMS
  exists (plan §J); extra token machinery is extra attack surface.
- OTP login in v1 — deferred by the owner: designed in plan §J (plug-in point, `otp_challenges`
  DDL, security rules), built in a later phase.

**Accepted risk — one-rotation-back reuse detection (owner T05 approval):**

`auth_sessions` retains only the immediately previous refresh hash. Replaying the token that was
rotated out **one** rotation ago is detected and revokes the family. A token two or more rotations
old no longer matches any stored hash, so it is treated as **plain-invalid** (generic 401) and does
**not** revoke the family. This is accepted: the stale token can never authenticate, and keeping a
full token history would grow unbounded and make every legitimately expired token a family-killer.
The residual gap is narrower detection of very old theft — the 10-minute access-token TTL and
`last_used_at` monitoring in F7 bound it.

**Clock assumptions (owner T05 approval):**

Access-token `exp` is evaluated against the **Node process clock**; session expiry
(`auth_sessions.expires_at`, rotation windows) is evaluated by **PostgreSQL**. All app and database
hosts therefore **must run NTP**; a divergence beyond the 5-second `clockTolerance` on JWT verify
rejects fresh tokens (or, in the other direction, extends them by the skew). The 5 s tolerance is
deliberate and small; do not raise it as a substitute for time sync.

**Accepted risk — password hashes are readable through the login lookup (owner checkpoint 2):**

Verifying a password requires the stored Argon2id PHC string, so a caller of
`app.auth_lookup_username` that already knows a tenant code **and** a username can read that one
user's `password_hash`. The owner accepted this residual exposure. It is bounded, not open-ended:

- the function returns at most one row of minimal columns and never enumerates — a wrong tenant
  code, unknown user or unknown phone all produce the identical empty result, so the function cannot
  be used to discover which accounts exist;
- the hash is Argon2id at ≥ the OWASP floor (A1); cracking a lone hash stays expensive, and a stored
  hash declaring absurd parameters is rejected before Argon2 runs;
- reaching the lookup already costs the caller the generic-401 path, the per-IP and per-tenant
  rate limits (A11) and the progressive delay (A2);
- the runtime role has no other cross-tenant read path: these four (and only these four) functions
  are the **complete** set of SECURITY DEFINER functions in schema `app`, asserted by catalog test.
  Any new definer function must repeat A17's checklist — owner-run, pinned `search_path`, static
  SQL, minimal columns, PUBLIC revoked, `bitabar_app` only — and pass the same review.

**Consequences:**

- The login lookup is the only controlled RLS crossing without a tenant context (A17); every future
  auth table follows A16 and the U14 guard.
- All brute-force-relevant numbers are env config with documented floors — tuning them is an ops
  decision, not a code change; weakening Argon2 below the floor fails startup.
- `OtpMethod` plugs into A6 without touching sessions, tokens or the F1-04 tables.
- Session rows accumulate: a purge job for expired/revoked `auth_sessions` is recorded technical
  debt (AGENT.md §7).
- `AUTH_TOKEN_SECRET` must exist before the app starts; access-token key rotation is recorded debt.
