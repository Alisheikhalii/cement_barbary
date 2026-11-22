# Authentication — login, tokens, sessions

How authentication works. Rules: ADR-007 (`docs/adr/007-authentication.md`); code:
`apps/api/src/modules/auth/`; plan: `docs/plan/F1-04.md`. OTP login is **designed, not built** —
see plan §J.

## Identifiers and the login flow

- Staff (`FACTORY_OPERATOR`, `CARRIER_ADMIN`): one identifier field, `username@tenant-code`.
- Drivers (`DRIVER`): phone number (normalized per `docs/security/pii.md`) + numeric PIN.
- The client **never sends a tenant id**. Staff resolution reads the tenant code from the
  identifier; the driver phone fans out server-side over a cached tenant list (60 s TTL) with
  per-tenant blind-index HMACs — one DB round trip.
- Every failure is identical: `401 {error:{code:"INVALID_CREDENTIALS"}}` — same status, body and
  headers for unknown user, malformed identifier, wrong password, delayed, disabled or deleted
  accounts. The unknown-user path runs a dummy Argon2 verify so timing stays similar (enforced by
  structural tests and a timing test: |Δ medians| ≤ max(50 ms, 20 %)).
- Wrong passwords trigger a **progressive per-account delay**: `base × 2^(failures-1)` seconds,
  capped (defaults 1 s / 300 s), reset on success. A delayed account gets the same generic 401.

## Credential methods (pluggable)

Login runs behind a `CredentialMethod` interface: `verify(input) → identity { tenantId, userId,
roles }`. `PasswordMethod` is the only implementation in v1; `OtpMethod` (SMS) plugs in later
without changing the login flow, tokens, sessions or tables (plan §J).

## Passwords

- Hashing: **Argon2id** (`@node-rs/argon2`), PHC string in `user_credentials.password_hash`.
- Parameters from env — `AUTH_ARGON2_MEMORY_KIB` (default 19456), `AUTH_ARGON2_TIME` (2),
  `AUTH_ARGON2_PARALLELISM` (1). The OWASP minimum (19 MiB / 2 / 1) is the **floor**: startup fails
  on weaker settings. Stored hashes declaring more than 4 × the configured parameters (or any
  malformed PHC) are rejected **before** Argon2 runs — no DoS via tampered stored hashes.
- Policy: staff 12–128 characters; drivers a numeric PIN of 8–20 digits plus a common-PIN
  blocklist; never equal to the login identifier — checked against **every** form of it (the bare
  username, `username@tenant-code`, the normalized phone, and every alias of that phone such as
  `912…`, `98912…`, `+98…` or spaced digits); dual-role and role-less accounts follow the staff
  rule.
- First passwords are **operator-set one-time passwords**: short expiry
  (`temporary_password_expires_at`, `AUTH_TEMP_PASSWORD_TTL_HOURS`, default 24 h), single use,
  hash-only, delivered out-of-band (CLI hidden prompt / stdout once). Login with
  `must_change_password` returns only a 5-minute change token — no session. A change or an operator
  reset revokes **all** sessions of the user.

## Tokens

|                   | Access token                                     | Refresh token                                          |
| ----------------- | ------------------------------------------------ | ------------------------------------------------------ |
| Format            | JWT HS256 (`jose`)                               | opaque 32-byte random (base64url)                      |
| Lifetime          | 10 min (`AUTH_ACCESS_TOKEN_TTL_SECONDS`)         | 30 days                                                |
| Claims / content  | `sub tid sid roles jti iat exp` — **no PII**     | random only; **SHA-256 hash stored**                   |
| Transport         | JSON body → client memory (Authorization header) | HttpOnly cookie `bitabar_refresh`, `Path=/api/v1/auth` |
| Verify            | algorithm pinned `['HS256']`, `iss/aud/exp`      | hash compare + rotation check                          |
| Theft containment | short TTL                                        | rotation; reuse → **whole family revoked**             |

Cookie flags: `HttpOnly` always; `Secure` always except local dev over plain http; `SameSite=Lax`
(Lax already blocks cross-site POSTs to the POST-only cookie endpoints); `Path=/api/v1/auth`
(the auth routes sit under the global prefix). On rotation the cookie's Max-Age is the session's
**remaining** lifetime, not a fresh 30 days (`refreshCookieMaxAgeSeconds`).

**CSRF (refresh + logout).** A custom header `X-Bitabar-CSRF: 1` is required — browsers cannot set
a custom header cross-origin without a preflighted CORS grant, and the CORS allowlist is ours.
When the browser sends `Origin`, it must match the configured allowlist exactly; with no `Origin`,
a present `Sec-Fetch-Site` must be `same-origin`. The check runs in a guard BEFORE the handler
touches the cookie, so a valid and an invalid cookie answer the same 403; rejections never set or
clear a cookie. Logout with a rotated-out token follows the reuse rule.

Rotation is one conditional `UPDATE … WHERE refresh_hash = <old> AND revoked_at IS NULL AND
expires_at > now()`: PostgreSQL's row lock makes exactly one of any number of simultaneous
refreshes succeed; the losers re-read the committed row, see their token as
`previous_refresh_hash`, and the family is revoked as reuse. A refresh token is resolved before a
tenant context exists only through `app.auth_lookup_session` (T04). Logout is idempotent and silent
for unknown/malformed tokens — it never becomes an oracle.

## Rate limits (all env config)

| Bucket          | Key                             | Default | Answer on overflow      |
| --------------- | ------------------------------- | ------- | ----------------------- |
| Per account     | A2 progressive delay            | 1 s ×2ⁿ | generic 401 (never 429) |
| Per identifier  | `AUTH_RL_LOGIN_ACCOUNT_PER_MIN` | 10/min  | `429` + `Retry-After`   |
| Per IP          | `AUTH_RL_LOGIN_IP_PER_MIN`      | 20/min  | `429` + `Retry-After`   |
| Per tenant-code | `AUTH_RL_LOGIN_TENANT_PER_MIN`  | 60/min  | `429` + `Retry-After`   |

Storage: Postgres `auth_rate_limits` behind a `RateLimiter` interface (fixed window, atomic
upsert, lazy + hourly TTL cleanup). A Redis implementation can replace it without caller changes.
**Key hygiene:** the IP bucket key holds the client IP (a counter dimension, not an account);
account and tenant-code keys are HMAC-SHA256 of the identifier (domain-separated `PII_HMAC_KEY`), so
the persisted row never contains a raw phone, username or tenant code. Unknown identifiers consume
exactly the same buckets as known ones, so a 429 cannot reveal existence. The wait time is computed
by PostgreSQL in the same upsert statement as the counter (no Node/DB clock subtraction), and it is
returned **only** in the `Retry-After` header: the 429 body carries no `details`, so two blocked
responses are byte-identical even when they land in different seconds of the same window.

**Deployment constraint (F8).** Express `trust proxy` stays **off** by default — a client-sent
`X-Forwarded-For` never changes `request.ip` (unit test `trust-proxy.test.ts`). In production,
behind Nginx, it must be enabled **explicitly for the internal proxy hop only** (`app.set('trust
proxy', 1)`, never `true`): otherwise every request carries Nginx's address and the per-IP limit
becomes one shared bucket that throttles all drivers together. `request.ip` must resolve to the
real client IP — verify with a request carrying a known `X-Forwarded-For` through the proxy.
Enabling `true` (trust every hop) instead lets anyone forge the header and evade the limit; the
application itself must not set it from env without this review.

The progressive delay write (`user_credentials.failed_attempts`/`next_attempt_at`) runs with
`SET LOCAL synchronous_commit = off` — best-effort anti-brute-force state — and every failure path
that must NOT write a counter (unknown tenant/user/phone, delayed account, expired temp password,
correct password on a disabled account) performs the same no-op bookkeeping transaction. Response
timing therefore does not depend on whether the account exists (A3).

## Endpoints

`POST /api/v1/auth/login` · `POST /api/v1/auth/refresh` (cookie + CSRF) ·
`POST /api/v1/auth/logout` (cookie + CSRF) · `POST /api/v1/auth/password/change` (change token or
Bearer + current password) · `GET /api/v1/auth/me` (Bearer).

A global authentication guard makes everything **deny by default**; only `@Public()` routes are
reachable without a bearer access token (health, and the four auth routes that authenticate
themselves). Access tokens travel in the JSON body; the refresh token exists only in the cookie.
`must_change_password` returns only a 5-minute change token (audience `bitabar-api:password-change`)
with no session and no cookie; the token carries a fingerprint of the current stored hash, so a
password change or an operator reset invalidates it and a concurrent double-submit applies at most
once (compare-and-swap). A change re-checks that the account and tenant are still active, is
throttled with the same per-account window as login, revokes every session, then opens one fresh
session. Login accepts only `application/json` — a cross-site HTML form cannot authenticate the
victim or plant a cookie (login-CSRF). Authentication guard only — permissions are F1-05.

## Tables and RLS

- `user_credentials`, `auth_sessions`: tenant-owned, the verbatim RLS template from
  `docs/security/rls.md`, isolation probes in `test/rls.int.test.ts`.
- `auth_rate_limits`: global, on the U14 allowlist (security counters, no tenant ownership, no
  PII).
- Pre-auth lookups cross RLS only through SECURITY DEFINER functions (`app.list_tenants()`,
  `app.auth_lookup_username`, `app.auth_lookup_phone`, and `app.auth_lookup_session` — the last
  resolves the opaque refresh cookie to its session for refresh/logout/reuse detection, added at
  the T03+T04 checkpoint for the A8 design): pinned `search_path`, no dynamic SQL, minimal columns
  (no PII, no ciphertext), `EXECUTE` revoked from PUBLIC, granted to `bitabar_app` only.

## How to add an auth table

1. Schema in `apps/api/src/db/schema/` with the standard helpers; tenant-owned tables lead their
   indexes with `tenant_id`.
2. `db:generate` for the DDL; a `--custom` migration for the RLS template (or a written allowlist
   entry with a reason).
3. Isolation probes in `test/rls.int.test.ts`; the U14 guard must stay green.
4. Never store plaintext secrets: passwords as Argon2id PHC, tokens as SHA-256 hashes.
5. Extend the pino redaction list for any new sensitive key.

## Logging rules

Passwords, PINs, tokens, cookies/`authorization` headers, phones and (later) OTP codes never
appear in logs, error messages, files or test snapshots. Redaction is key-based — never put these
values into free-text log messages, URLs or error strings.
