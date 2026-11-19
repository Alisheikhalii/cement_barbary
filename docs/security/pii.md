# PII protection (phone, national ID)

How personal data is stored and looked up. Rules: ADR-006 (U7–U11, U17); code: `apps/api/src/security/pii/`.

## Storage format

Every encrypted value is one `bytea` blob:

```
[format version 1B][key_version 1B][IV 12B][GCM tag 16B][ciphertext]
```

- Algorithm: AES-256-GCM (`node:crypto`), random 12-byte IV per value — two encryptions of the same value differ.
- AAD (authenticated extra data): `tenant_id:table.column:row_id`. A blob copied to another row, column or tenant
  fails to decrypt; one tampered byte fails. The id parts must be UUIDs and the column a plain `table.column`
  identifier, so `:` separates unambiguously (`buildAad` enforces this).
- The row id is generated **app-side** (`randomUUID`) before encrypting, so it is known at write time.
- `key_version` = the active `PII_KEY_ID` at write time. Decryption reads it from the blob, so a future rotation
  can keep old keys for old rows without a format change.

## Blind index (lookup without plaintext)

Next to each encrypted column sits a `*_hash bytea`:

```
HMAC-SHA256(PII_HMAC_KEY, tenant_id + ":" + field + ":" + normalized_value)
```

- Lookups (`findByPhone`) hash the normalized input and compare hashes only.
- Uniqueness is a partial unique index on `(tenant_id, *_hash) WHERE deleted_at IS NULL` — per tenant, never global.
- The HMAC key is a different secret from the encryption key. Plain SHA-256 is forbidden (brute-forceable).

## Normalization (before hashing)

- Persian (۰۱۲۳۴۵۶۷۸۹) and Arabic (٠١٢٣٤٥٦٧٨٩) digits become ASCII.
- Phone: `+989…`, `989…`, `9…`, `09…` all normalize to `09XXXXXXXXX`; validated against `^09\d{9}$`.
- National ID: 10 digits, official checksum. Invalid input → `DomainError.badInput`.

## Keys

| Env var        | Meaning                                                                         |
| -------------- | ------------------------------------------------------------------------------- |
| `PII_ENC_KEY`  | base64, decodes to exactly 32 random bytes                                      |
| `PII_HMAC_KEY` | base64, decodes to exactly 32 random bytes — **must differ from `PII_ENC_KEY`** |
| `PII_KEY_ID`   | 1–255, default 1; written as `key_version`                                      |

Startup fails on a missing key, a wrong decoded length, or identical keys; error text never contains key material.
Generate: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`. Only placeholders go into
`.env.example`. Key rotation is recorded technical debt (AGENT.md §7).

## Masking and logging

- pino redacts, at any depth, any key that mentions a phone / mobile / national id or carries an
  `*_enc` / `*_hash` (or camelCase `…Enc` / `…Hash`) suffix — see `apps/api/src/security/pii/log-redact.ts`.
- No plaintext phone or national ID in logs, error messages or test snapshots. Error messages never echo the input.
- **Redaction is key-based**: it cannot see PII inside free-text values. Never put a phone or national ID into a
  URL (query strings are logged), an error message, or a log message string.
- Display helpers: `maskPhone()` → `0912***0001`, `maskNationalId()` → `******1234`.

## How to add a new encrypted field

1. Normalize and validate the input in `security/pii/normalize.ts`.
2. Add `<field>_enc bytea` + `<field>_hash bytea` columns (NULL pair: both NULL or both set — add a CHECK).
3. Partial unique index on `(tenant_id, <field>_hash) WHERE deleted_at IS NULL`.
4. Generate the row id app-side before writing; build the AAD with `buildAad(tenantId, 'table.column', rowId)`.
5. Write through the PII service (`encrypt` + `blindIndex`), never through raw SQL with plaintext.
6. Read through `decrypt` with the same AAD (same tenant, column AND row id); never log the decrypted value.
7. Add the field name and `*_enc`/`*_hash` patterns to the pino redact list if not already covered.
8. Tests: round trip, wrong-AAD failure (tenant, column AND row), per-tenant uniqueness, redaction.
