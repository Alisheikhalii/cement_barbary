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
3. **Secrets** live only in `.env` (git-ignored) or the server's secret manager. `.env.example` holds
   placeholders only.
4. **Before every push:** run the full-history Gitleaks scan (command below). A finding blocks the push.
5. If a real secret or personal record was committed: stop, tell the owner, rotate the secret.
   Rewriting public history does not remove copies that were already fetched.

## Scan command (Docker, read-only mount)

```sh
docker run --rm -v "<repo-path>:/repo:ro" zricethezav/gitleaks:v8.28.0 \
  git /repo --config /repo/.gitleaks.toml --redact --no-banner
```

CI runs the same scan on every push and pull request (`secrets-scan` job).
