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
  blocklist; never equal to the identifier; dual-role accounts follow the staff rule.
- First passwords are **operator-set one-time passwords**: short expiry
  (`temporary_password_expires_at`, `AUTH_TEMP_PASSWORD_TTL_HOURS`, default 24 h), single use,
  hash-only, delivered out-of-band (CLI hidden prompt / stdout once). Login with
  `must_change_password` returns only a 5-minute change token — no session. A change or an operator
  reset revokes **all** sessions of the user.

## Tokens

|                   | Access token                                     | Refresh token                                   |
| ----------------- | ------------------------------------------------ | ----------------------------------------------- |
| Format            | JWT HS256 (`jose`)                               | opaque 32-byte random (base64url)               |
| Lifetime          | 10 min (`AUTH_ACCESS_TOKEN_TTL_SECONDS`)         | 30 days                                         |
| Claims / content  | `sub tid sid roles jti iat exp` — **no PII**     | random only; **SHA-256 hash stored**            |
| Transport         | JSON body → client memory (Authorization header) | HttpOnly cookie `bitabar_refresh`, `Path=/auth` |
| Verify            | algorithm pinned `['HS256']`, `iss/aud/exp`      | hash compare + rotation check                   |
| Theft containment | short TTL                                        | rotation; reuse → **whole family revoked**      |

Cookie flags: `HttpOnly` always; `Secure` always except local dev over plain http; `SameSite=Lax`
(Lax already blocks cross-site POSTs to the POST-only cookie endpoints) + Origin/`Sec-Fetch-Site`
check on cookie endpoints (CSRF).

## Rate limits (all env config)

| Bucket          | Key                            | Default | Answer on overflow      |
| --------------- | ------------------------------ | ------- | ----------------------- |
| Per account     | A2 progressive delay           | 1 s ×2ⁿ | generic 401 (never 429) |
| Per IP          | `AUTH_RL_LOGIN_IP_PER_MIN`     | 20/min  | `429` + `Retry-After`   |
| Per tenant-code | `AUTH_RL_LOGIN_TENANT_PER_MIN` | 60/min  | `429` + `Retry-After`   |

Storage: Postgres `auth_rate_limits` behind a `RateLimiter` interface (fixed window, atomic
upsert, lazy + hourly TTL cleanup). A Redis implementation can replace it without caller changes.

## Endpoints

`POST /auth/login` · `POST /auth/refresh` (cookie) · `POST /auth/logout` (cookie) ·
`POST /auth/password/change` · `GET /auth/me` (Bearer). Authentication guard only — permissions
are F1-05.

## Tables and RLS

- `user_credentials`, `auth_sessions`: tenant-owned, the verbatim RLS template from
  `docs/security/rls.md`, isolation probes in `test/rls.int.test.ts`.
- `auth_rate_limits`: global, on the U14 allowlist (security counters, no tenant ownership, no
  PII).
- Pre-auth lookups cross RLS only through SECURITY DEFINER functions (`app.list_tenants()`,
  `app.auth_lookup_username`, `app.auth_lookup_phone`): pinned `search_path`, no dynamic SQL,
  minimal columns (no PII, no ciphertext), `EXECUTE` revoked from PUBLIC, granted to
  `bitabar_app` only.

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
