# ADR-003: Public repository and synthetic-data policy

2026-11-18 | Accepted

**Context:** CLAUDE.md originally required a private repo named `bitabar`. The owner decided (OWN-17) that `github.com/Alisheikhalii/cement_barbary` stays **PUBLIC** until project completion. The project audit (S1) rated public visibility as a High risk.

**Decision:**

- Keep the repo public and reduce the risk:
  - `.gitleaks.toml`: the default rules, plus rules for Iranian mobile numbers, SHEBA/IBAN numbers, and labeled national IDs. It allowlists a small set of fake values.
  - Synthetic data only, everywhere (`docs/security/data-handling.md`, GUIDELINES §13).
  - A full-history Gitleaks scan before every push, and in CI (`secrets-scan` job).
- The product name stays BitaBar, and packages stay under the `@bitabar/*` scope.

**Alternatives considered:** make the repo private now (the owner declined for now); rename the repo to `bitabar` (not requested).

**Consequences:** business documents are world-readable. Anything committed by mistake must be treated as leaked: rotate the secret, because rewriting history does not help. The owner can switch to private at any time; nothing in the code depends on visibility.
