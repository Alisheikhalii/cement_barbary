# Data handling rules (public repository)

The GitHub repository `cement_barbary` is **PUBLIC** until project completion (owner decision OWN-17).
Anything committed can be read by anyone and stays in Git history.

## Rules

1. **Synthetic data only.** Never commit real mobile numbers, national IDs, SHEBA/IBAN numbers,
   vehicle plates, names, addresses, or screenshots containing them. This applies to code, tests,
   seed scripts, fixtures, docs, issues, and PR descriptions.
2. **Allowed fake values** (whitelisted in `.gitleaks.toml`):
   - Mobile: `09000000000`, `09120000000` to `09120000009`
   - SHEBA: `IR` followed by 24 zeros
   - National ID: generate in tests at runtime; do not hard-code 10-digit values next to a
     `national_id` label.
3. **Scoped history allowlists (F1-06).** Two narrowly scoped `[[allowlists]]` entries exist because
   synthetic fixtures were committed before they were moved to the allowed forms: one for the T06
   synthetic negative-case password literal (`5b6c813`, auth-audit test only), one for the T08/T09
   outbox/attack test fixtures (`444e045`, `3b89fe0`, exact test files only). Each uses
   `condition = "AND"` with exact commits and paths; there is no broad numeric or directory pattern.
   A negative control is part of the T09 close-out: a realistic value outside those paths is still
   detected (verified with a temporary file that was removed). New entries need the same scoping and
   an owner decision.
4. **Secrets** live only in `.env` (git-ignored) or the server's secret manager. `.env.example` holds
   placeholders only.
5. **Before every push:** run the full-history Gitleaks scan (command below). A finding blocks the push.
6. If a real secret or personal record was committed: stop, tell the owner, rotate the secret.
   Rewriting public history does not remove copies that were already fetched.

## Scan command (Docker, read-only mount)

```sh
docker run --rm -v "<repo-path>:/repo:ro" zricethezav/gitleaks:v8.28.0 \
  git /repo --config /repo/.gitleaks.toml --redact --no-banner
```

CI runs the same scan on every push and pull request (`secrets-scan` job).
