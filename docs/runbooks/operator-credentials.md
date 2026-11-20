# Operator credentials runbook

How to create an operator/staff account or reset a user's password with a
one-time password (F1-04). Run these commands from the repository root on a
machine that has the API's `.env` (or the same environment variables) and a
reachable database.

## When to use which command

- **New staff account** (`FACTORY_OPERATOR` or `CARRIER_ADMIN`): use
  `create-user` with `--username`. Staff log in as `username@tenant-code`.
- **New driver account**: use `create-user` with `--role DRIVER` and
  `--phone`. Drivers log in with their phone number.
- **Forgot / lost password**: use `reset-password` with the same login
  (`--username` for staff, `--phone` for drivers). There is no "show password"
  command — the old password is not recoverable.

Both commands generate the password themselves. You never type, pass or store
a password; passing one as an argument is not possible.

## Create an account

```bash
pnpm --filter @bitabar/api exec tsx src/cli/create-user.ts \
  --tenant dev-factory \
  --username <username> \
  --display-name "<display name>"
```

Create a driver:

```bash
pnpm --filter @bitabar/api exec tsx src/cli/create-user.ts \
  --tenant dev-factory \
  --role DRIVER \
  --phone <phone> \
  --display-name "<display name>"
```

Flags:

| Flag                 | Required                     | Notes                                                          |
| -------------------- | ---------------------------- | -------------------------------------------------------------- |
| `--tenant`           | yes                          | Tenant code, exactly as stored (`dev-factory` in development). |
| `--display-name`     | yes                          | Human name shown in the UI.                                    |
| `--username`         | staff: yes; driver: optional | Lowercase login name: 3–32 chars of `a-z 0-9 . _ -`.           |
| `--role`             | no                           | `FACTORY_OPERATOR` (default), `CARRIER_ADMIN`, or `DRIVER`.    |
| `--phone`            | driver: yes; staff: optional | Normalized before storage.                                     |
| `--allow-production` | non-local or non-dev runs    | See below.                                                     |

The command refuses to reuse an existing username or phone; it never silently
overwrites an account.

## Reset a password

Staff (generates a 20-character password):

```bash
pnpm --filter @bitabar/api exec tsx src/cli/reset-password.ts \
  --tenant dev-factory \
  --username <username>
```

Driver (generates a 10-digit PIN):

```bash
pnpm --filter @bitabar/api exec tsx src/cli/reset-password.ts \
  --tenant dev-factory \
  --phone <phone>
```

Exactly one of `--username` or `--phone` is required. The account's stored role
decides the password type — staff always get a 20-character password, a
driver-only account gets a 10-digit PIN — even when a staff account is looked
up by phone. A reset also revokes every live session for that user in the same
transaction.

## The one-time password rule

- **Shown once.** The generated password is written to stdout exactly once,
  after the database write succeeds. Copy it and deliver it to the user through
  a safe channel immediately.
- **Never in shell history, environment variables or arguments.** The password
  is generated inside the process with `node:crypto`; it is never read from
  `--password`, an env var, or a file. Do not paste it into an issue, chat, log
  or ticket.
- **Stored only as an Argon2id hash.** The database never holds the plaintext.
- **Must change at first login.** The account is created with
  `must_change_password = true`; the user is forced to set a new password.
- **Expires.** The one-time password is valid for
  `AUTH_TEMP_PASSWORD_TTL_HOURS` hours (default 24). After that, the user must
  ask for a new reset.

The command's success output looks like:

```text
One-time password (shown once, NEVER logged or stored in plaintext):
  tenant: <code>
  login:  <username@code | phone>
  role:   <role>
  password: <generated>

The user must change it at first login. It expires at <ISO timestamp>.
```

Nothing else is printed on success.

## Production

The commands run without the extra flag only when **both** conditions hold:
`NODE_ENV` is exactly `development` or `test`, and `DATABASE_URL` points at a
**local** database (`localhost`, `127.0.0.1` or `[::1]`). Anything else —
`production`, a custom or unset variable, or a development label on a host
with a remote database — is refused unless you pass `--allow-production`:

```text
refused: running outside a local development/test database requires --allow-production
```

The guard exists so that a stray command in a production shell (or one where
`NODE_ENV` was never set, or a copied dev `.env` points at the live database)
cannot create or reset an account by accident. When you genuinely need it, add
the flag deliberately, on the exact command you intend to run. The flag is the
only production-specific switch; the password is still generated and printed
once.

The CLI also refuses a `DATABASE_URL` whose role is a superuser, has
`BYPASSRLS`, or owns the auth tables — it must be the ordinary runtime role
(`bitabar_app`). The API performs the same check at startup. **F8 note:** these commands currently run the TypeScript sources
through `tsx` (a dev dependency). Before deployment, compile the two entries
into `dist/` and document the production invocation; do not install dev
dependencies in the production image just to run them.

## If the password is lost

Run `reset-password` again for the same account. A new one-time password is
generated, the old hash is replaced, and all of the user's sessions are
revoked. There is no way to recover the previous password.
