# ADR-002: Claude Code read deny-list

2026-11-16 | Accepted

**Context:** CLAUDE.md §3.5-A requires that heavy or sensitive files (`node_modules`, lockfiles, build output, images, `.env`) are technically blocked from being read into the AI context. This protects secrets and saves tokens.

**Decision:** `.claude/settings.json` uses `permissions.deny` with those paths. Because deny rules take priority over allow rules, a blanket `.env.*` pattern would also block `.env.example`. So the list uses specific patterns instead: `.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`.

**Alternatives considered:** a blanket `.env.*` deny with an allow for `.env.example` (does not work, because deny wins); documenting the rule only in CLAUDE.md (not enforced).

**Consequences:** the lockfile can only be inspected with `pnpm why` or `pnpm list`, never by reading it. Any new env file name must be added to the deny-list.
