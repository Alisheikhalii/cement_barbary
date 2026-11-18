# ADR-004: Temporary audit exception for GHSA-fc5q-39xc-vjpf (picomatch)

**Status:** Accepted (temporary) | **Date:** 2026-11-18 | **Owner approval:** yes (F0 authorization) | **Review by:** 2026-12-18

**Context:** `pnpm audit --audit-level=high` fails CI on GHSA-fc5q-39xc-vjpf (high, ReDoS through single-branch repeated extglobs). The official GitHub advisory lists affected versions `<= 4.0.7` and **no patched version**. The npm registry's latest picomatch is 4.0.7 (4.0.8 does not exist). pnpm's audit data shows `>=4.0.8` as "patched", but that version has not been published.

**Exposure:** picomatch 4.0.7 is transitive and dev-only. It comes in through `fdir`/`tinyglobby` used by `typescript-eslint`, Vite/Vitest, and `lint-staged`. No production dependency includes it. Glob patterns come only from committed config files, so no end user can supply one. The worst case is a malicious pattern in a pull request hanging a CI job, which the job timeout (20 min) stops.

**Decision:** ignore exactly this one advisory via `auditConfig.ignoreGhsas` in `pnpm-workspace.yaml`. Keep `--audit-level=high` in CI. No other advisory is suppressed. The moderate minimatch advisory (GHSA-g3hv-75wg-m249) stays visible in the audit output.

**Removal requirement:** remove the exception as soon as an official fix is published (or a dependency update drops picomatch ≤4.0.7), then confirm that `pnpm audit --audit-level=high` passes. At each review date, check the advisory again (`gh api advisories/GHSA-fc5q-39xc-vjpf`) and `pnpm view picomatch version`. Extend the exception only with owner approval.

**Alternatives rejected:** keep CI red (it hides new failures and blocks F0 Definition of Done). Audit only production dependencies (it would also hide future dev-tool advisories). Lower the threshold to critical (it hides other high advisories).
