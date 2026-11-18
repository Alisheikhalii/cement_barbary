# ADR-001: Toolchain versions and npm registry

2026-11-18 | Accepted

**Context:** On Windows, `pnpm test` crashed because the Rolldown and lightningcss native binding packages (`@rolldown/binding-win32-x64-msvc`, `lightningcss-win32-x64-msvc`) were missing from `node_modules`. They are required by Vitest 5 (via Vite 8). The lockfile already listed them. The install had been done through the user-level `registry.npmmirror.com` mirror, which also has no `pnpm audit` endpoint.

**Decision:**

- Keep the current versions (Node 24, pnpm 11.11.0, TypeScript 6, ESLint 10, Vitest 5). A clean reinstall fixed the problem, so pinning Vitest 4 was not needed.
- Add a project-level `.npmrc` with `registry=https://registry.npmjs.org/` (owner decision OD-F0a, Option A). Global or user-level npm settings are not changed.

**Alternatives considered:** pin Vitest 4.x (rejected because it was not needed); keep the mirror (rejected because it gives a different source than CI and no audit).

**Consequences:** local, CI, and audit all use the same registry, and `pnpm install --frozen-lockfile` passes. Downloads from npmjs.org can be slow or flaky from this network (retries were seen). If Windows native bindings go missing again, delete `node_modules` and reinstall. `pnpm audit` currently reports 1 high advisory (picomatch ≤4.0.7, GHSA-fc5q-39xc-vjpf) and 1 moderate advisory (minimatch), both in dev-only tooling. No patched picomatch has been published yet, so the CI audit step will fail until one is released or the owner accepts an exception.
