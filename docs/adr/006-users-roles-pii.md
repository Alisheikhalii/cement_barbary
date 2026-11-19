# ADR-006: Users, roles and PII protection

2026-11-19 | Accepted

**Context:** F1-03 adds the user model: a global role catalog, tenant-owned `users` and `user_roles`, and the
protection of personal data (phone, national ID) that GUIDELINES §4 requires. Owner decisions of 2026-11-19:
`PLATFORM_ADMIN` exists as data but gets no web login in v1 (Q1); the phone is encrypted exactly like the national
ID (Q2); the national-ID columns are added now but stay **empty** for the whole phase (Q3). Owner-required
hardening (a)–(g) from the plan approval is folded into U7–U16 below. Full plan: `docs/plan/F1-03.md`.

**Decision (U1–U17):**

- **U1 — Roles are data.** A global table `roles(code PK, name_fa, scope, description)` holds exactly 6 rows:
  `PLATFORM_ADMIN` (scope `platform`), `FACTORY_OPERATOR` (`tenant`), `CARRIER_ADMIN` (`carrier`),
  `CARRIER_OPERATOR` (`carrier`), `DRIVER` (`driver`), `AUDITOR` (`tenant`). Rows are inserted **by a migration**
  (every environment needs them), never by the seed. `roles` has no `tenant_id`; the runtime role gets SELECT only.
- **U2 — No permissions in F1-03.** No `permissions` table. `CARRIER_ADMIN` is stored as "login only; no operational
  permissions until OD-37 is decided". F1-05 maps roles to permissions.
- **U3 — `users` is tenant-owned** (`tenant_id NOT NULL`), using the RLS template from `docs/security/rls.md`
  verbatim. One person = one user row per tenant, with one or more roles.
- **U4 — `PLATFORM_ADMIN` cannot be assigned to a tenant user** (owner Q1). Enforced in the DB by `user_roles`
  carrying a `role_scope` column with a composite FK `(role_code, role_scope) → roles(code, scope)` and
  `CHECK (role_scope <> 'platform')` — no trigger needed. In v1, platform work (create a tenant) is done by the
  migration owner through a CLI or the seed; **there is no web login for `PLATFORM_ADMIN` in F1** (recorded in
  AGENT.md §6).
- **U5 — `user_roles` is tenant-owned with RLS**, composite FK `(tenant_id, user_id) → users(tenant_id, id)` so a
  role link can never point to another tenant's user, even for the owner role. Unique
  `(tenant_id, user_id, role_code)`. Hard delete allowed (revoking a role).
- **U6 — `users.created_by` gets a composite FK** `(tenant_id, created_by) → users(tenant_id, id)` (`MATCH SIMPLE`,
  NULL allowed). `tenants.created_by` stays without an FK because platform actors are not tenant users (U4).
  Closes D8 from ADR-005.
- **U7 — Phone and national ID are encrypted** (owner Q2) with AES-256-GCM (Node `node:crypto`, no new dependency).
  Random 12-byte IV per value; AAD = `tenant_id + table.column`, so a ciphertext moved to another row, column or
  tenant fails to decrypt (change (c)). Blob format in `bytea`:
  `[format version 1B][key_version 1B][IV 12B][tag 16B][ciphertext]` — the `key_version` sits next to the ciphertext
  so keys can rotate later without a data-format change (change (a)). Unknown format version or key_version, a wrong
  key, or any tampered byte fails with a generic error containing no plaintext.
- **U8 — Lookups use a blind index.** `*_hash bytea` = HMAC-SHA256(`PII_HMAC_KEY`, `tenant_id + ":" + field + ":" +
normalized value`). Lookups and uniqueness use the hash only; uniqueness is **per `(tenant_id, *_hash)`, never
  global** (change (d)) — the tenant is inside the HMAC input and inside the UNIQUE constraint, so the same phone in
  two tenants yields different hashes and both inserts succeed. Plain SHA-256 is not used (10-digit IDs and 11-digit
  phones are brute-forceable without a secret).
- **U9 — Normalization before hashing:** Persian/Arabic digits become ASCII. Phone: `+989…`, `989…`, `9…`, `09…` →
  `09XXXXXXXXX` (`^09\d{9}$`). National ID: 10 digits with the official checksum. Invalid input →
  `DomainError.badInput` (message never echoes the input, change (g)).
- **U10 — Keys:** `PII_ENC_KEY` and `PII_HMAC_KEY` (base64, decoding to **exactly 32 random bytes**), `PII_KEY_ID`
  (1–255, default 1; the `key_version` written into every ciphertext). Zod env validation fails startup on: missing
  key, wrong decoded length, or **identical enc/hmac keys** — three separate checks, three tests (change (b)). Error
  text contains no key material. Key rotation (multiple active key_versions) is recorded as technical debt, not
  built now; the key_version byte makes it possible later.
- **U11 — Masking:** the pino logger redacts `phone`, `nationalId`, `national_id`, `*_enc`, `*_hash` at any depth.
  No plaintext phone or national ID may appear in logs, error messages or test snapshots (change (g)). Helpers
  `maskPhone()` (`0912***0001`) and `maskNationalId()` (`******1234`).
- **U12 — `users` columns:** `id`, `tenant_id`, `username varchar(32) NULL` (CHECK `^[a-z0-9._-]{3,32}$`),
  `display_name varchar(200) NOT NULL`, `status varchar(16) NOT NULL DEFAULT 'active'` CHECK in (`active`,
  `disabled`), `phone_enc`/`phone_hash bytea NULL`, `national_id_enc`/`national_id_hash bytea NULL`, timestamps,
  `created_by`, `deleted_at`. CHECKs: `username IS NOT NULL OR phone_hash IS NOT NULL`; each `_enc` is NULL exactly
  when its `_hash` is NULL. Partial unique indexes (`deleted_at IS NULL`) on `(tenant_id, username)`,
  `(tenant_id, phone_hash)`, `(tenant_id, national_id_hash)`. Unique `(tenant_id, id)` for the composite FKs. No
  password column (F1-04). **The national-ID columns stay empty in F1-03: no code path may write to them (owner
  Q3); the write path is F4 scope (driver profile).**
- **U13 — Soft delete only for users:** `DELETE` on `users` is revoked from `bitabar_app`; the app sets
  `deleted_at`. `user_roles` rows may be hard-deleted (role revocation).
- **U14 — Stronger guard test:** every table in `public` must have `tenant_id` + RLS + policy, or be on an explicit
  allowlist with a written reason per entry: `tenants` (platform-owned registry, RLS applied in F1-02), `roles`
  (global read-only catalog, app has SELECT only). A new table that is neither fails the tests (change (f)).
- **U15 — `UsersRepository`, no HTTP.** Works only through `TenantDb.run()` and the PII service: `create`,
  `findById`, `findByUsername`, `findByPhone`, `assignRole`, `revokeRole`, `listRoles`, `softDelete`. Never accepts
  `tenantId` as an argument (ADR-005). No method accepts or writes a national ID in F1-03 (Q3); no
  `findByNationalId` yet. No HTTP endpoint until RBAC guards exist (F1-05).
- **U16 — Dev seed:** `apps/api/src/db/seed/dev-seed.ts` via `pnpm --filter @bitabar/api db:seed:dev` (change (e)):
  **never run in CI**, excluded from the production build (`tsconfig.build.json`) and from every Docker image
  (`.dockerignore`), and refuses to run unless `NODE_ENV=development` and the DB host is `localhost`/`127.0.0.1`
  (refusal covered by a test). Runs as the migration owner (it creates the tenant, U4). Idempotent (upsert by tenant
  code and username). Data: tenant `dev-factory`, 5 users (one per assignable role), phones only from the gitleaks
  allowlist (`09120000001`…`09120000005`), national ID NULL, no passwords. Encryption goes through the same PII
  service.
- **U17 — Test data:** phones from the gitleaks allowlist only; national IDs generated at runtime with a valid
  checksum (helper in `test/setup/`), never literals; test keys random per run.

**Alternatives considered:**

- Permissions table in F1-03 — rejected (owner OD-37): no permission is invented before F1-05.
- A "platform" tenant whose users hold `PLATFORM_ADMIN` — rejected (owner Q1): mixes platform and factory data; CLI
  and seed cover v1 platform work.
- Phone in plaintext — rejected (owner Q2): a DB backup would expose every driver's number.
- Plain SHA-256 blind index — rejected: brute-forceable without a secret (U8).
- Trigger instead of the composite-FK + CHECK for U4 — rejected: the FK pattern is declarative, visible in the
  schema, and enforced for every role including the owner.

**Consequences:**

- Keys must exist before the app starts; rotating them later is a data migration over the `key_version` byte (debt).
- Any future tenant-owned table follows the U14 guard; global tables require an allowlist entry with a reason.
- `national_id_*` writes, password storage, OTP, JWT, RBAC guards, audit, idempotency and carriers remain out of
  scope until their phases (F1-04, F1-05, F1-06, F1-08, F4).
- The seed is a development-only tool: it is absent from builds, images and CI, and refuses to run outside local dev.
