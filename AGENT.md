# AGENT.md – حافظه پروژه (همیشه به‌روز)

## ۱. وضعیت فعلی

- فاز فعلی: F0 (قدم صفر) — F0-01..09 محلی انجام شد؛ **Commit/Push نشده** (منتظر تایید مالک) | آخرین Tag: — | آخرین Commit: 75680a7
- CI: — | تاریخ آخرین به‌روزرسانی: ۱۴۰۵/۰۸/۲۷
- ریپو: `github.com/Alisheikhalii/cement_barbary` (شاخه `main`)

## ۲. نقشه پروژه (فقط خلاصه)

- Monorepo با pnpm workspaces + Turborepo (ساختار GUIDELINES §۲).
- `packages/config`: tsconfig پایه (strict)، ESLint flat config، Prettier — همه پکیج‌ها از این ارث می‌برند.
- `packages/shared`: ثوابت/تایپ/Schemaهای مشترک Front و Back (فعلاً فقط `constants`).
- `packages/ui`: توکن‌های Design System (`src/tokens.ts` + `src/tokens.css` + `tailwind-preset.ts`)، تست هم‌خوانی و منع URL خارجی.
- `apps/api`، `apps/web`: فعلاً فقط اسکلت پوشه.
- `infra/compose/docker-compose.dev.yml`: PostgreSQL 17 + Redis 7 (فقط 127.0.0.1، healthcheck، پروژه `bitabar-dev`).
- مدل داده: هنوز وجود ندارد.
- Endpointها: هنوز وجود ندارد.
- فایل‌های طراحی ظاهری: `docs/specs/{carrier,operator,driver}-panel.html` — فقط در فاز UI خوانده شوند؛ PNGها در deny هستند.

## ۳. تصمیمات مهم (ADR خلاصه + لینک)

- قوانین deny خواندن در `.claude/settings.json`. چون deny بر allow غلبه دارد، به‌جای `.env.*` الگوهای مشخص (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`) گذاشته شد تا `.env.example` قابل‌خواندن بماند.
- `.gitattributes` با `eol=lf`: توسعه روی ویندوز، CI و سرور لینوکس.
- ADR-001 نسخه ابزارها + `.npmrc` رجیستری رسمی npm | ADR-002 deny-list | ADR-003 ریپو PUBLIC + داده مصنوعی | ADR-004 استثنای موقت audit برای picomatch (`docs/adr/`).

## ۴. انجام‌شده (Changelog) ← جدیدترین بالا

- [۱۴۰۵/۰۸/۲۷ | uncommitted | F0-01..09] نصب تمیز از npmjs (رفع binding ویندوز Rolldown/lightningcss)، `.npmrc`، `.gitleaks.toml` + `docs/security/data-handling.md`، اصلاح مسیر Design System و متن Private، Docker Compose dev + `infra/scripts/dev-up.sh`، `packages/ui` توکن‌ها (۵ تست)، CI: job `compose-config`، ADR-001..004، ضمیمه گزارش ممیزی.
- [۱۴۰۵/۰۸/۲۵ | cb3ac5e | F0/قدم صفر] ساختار درختی Monorepo، README، `.nvmrc`(24)، `.editorconfig`، `.gitattributes`، `.env.example`، `.gitignore` کامل.

## ۵. در حال انجام / بعدی

- منتظر تایید مالک: Commit های کوچک + Push (F0-05) → اولین اجرای CI → محافظت سبک main → Tag `v0.0.0` → گزارش F0.

## ۶. پرسش‌های باز و فرض‌ها (برای مالک)

- (تصمیم مالک OWN-17، ۱۴۰۵/۰۸/۲۶) ریپو تا پایان پروژه PUBLIC می‌ماند؛ محافظت سبک روی main (منع Force Push و حذف) منتظر تایید جداگانه مالک.

## ۷. بدهی فنی و ریسک‌های شناخته‌شده

- `pnpm audit`: picomatch ≤4.0.7 (GHSA-fc5q-39xc-vjpf، High، فقط dev، نسخه اصلاح‌شده منتشر نشده) با استثنای موقت ADR-004 در `pnpm-workspace.yaml` نادیده گرفته می‌شود؛ بازبینی تا 2026-12-18 و حذف به‌محض انتشار اصلاح. minimatch 10.2.6 (Moderate، dev) باز و قابل مشاهده است.
- دانلود از registry.npmjs.org روی این شبکه کند/ناپایدار است (retry).

## ۸. دستورهای مهم (اجرا، تست، Migration، Seed، Deploy)

- `sh infra/scripts/dev-up.sh` | `docker compose -f infra/compose/docker-compose.dev.yml down` (بدون `-v`)
- Gitleaks: `docker run --rm -v "<repo>:/repo:ro" zricethezav/gitleaks:v8.28.0 git /repo --config /repo/.gitleaks.toml --redact`
- `pnpm install` | `pnpm lint` | `pnpm typecheck` | `pnpm test` | `pnpm build` | `pnpm format`

## ۹. وضعیت امنیت و بنچمارک (آخرین نتیجه + لینک گزارش)

- هنوز اجرا نشده (فاز F7).
