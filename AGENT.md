# AGENT.md – حافظه پروژه (همیشه به‌روز)

## ۱. وضعیت فعلی

- فاز فعلی: **F1** — F1-01 (اسکلت API) پیاده‌سازی شد؛ **Commit/Push نشده** (منتظر بازبینی مالک) | آخرین Tag: — | آخرین Commit: 892292c
- CI: سبز (F0) | تاریخ آخرین به‌روزرسانی: ۱۴۰۵/۰۸/۲۷
- ریپو: `github.com/Alisheikhalii/cement_barbary` (شاخه `main`)

## ۲. نقشه پروژه (فقط خلاصه)

- Monorepo با pnpm workspaces + Turborepo (ساختار GUIDELINES §۲).
- `packages/config`: tsconfig پایه (strict)، ESLint flat config، Prettier — همه پکیج‌ها از این ارث می‌برند.
- `packages/shared`: ثوابت/تایپ/Schemaهای مشترک Front و Back (فعلاً فقط `constants`).
- `packages/ui`: توکن‌های Design System (`src/tokens.ts` + `src/tokens.css` + `tailwind-preset.ts`)، تست هم‌خوانی و منع URL خارجی.
- `apps/api`: **NestJS 11 (ESM/NodeNext)** — Config با اعتبارسنجی Zod، پاسخ/خطای استاندارد (`{data,meta}`/`{error}`)، لاگ JSON با nestjs-pino + request-id، Health (`/health/live`، `/health/ready` بدون پیشوند)، Swagger در `/api/docs`، Helmet + CORS محیطی، ZodValidationPipe. (F1-01)
- `apps/web`: فعلاً فقط اسکلت پوشه.
- `infra/compose/docker-compose.dev.yml`: PostgreSQL 17 + Redis 7 (فقط 127.0.0.1، healthcheck، پروژه `bitabar-dev`).
- مدل داده: هنوز وجود ندارد.
- Endpointها: هنوز وجود ندارد.
- فایل‌های طراحی ظاهری: `docs/specs/{carrier,operator,driver}-panel.html` — فقط در فاز UI خوانده شوند؛ PNGها در deny هستند.

## ۳. تصمیمات مهم (ADR خلاصه + لینک)

- قوانین deny خواندن در `.claude/settings.json`. چون deny بر allow غلبه دارد، به‌جای `.env.*` الگوهای مشخص (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`) گذاشته شد تا `.env.example` قابل‌خواندن بماند.
- `.gitattributes` با `eol=lf`: توسعه روی ویندوز، CI و سرور لینوکس.
- ADR-001 نسخه ابزارها + `.npmrc` رجیستری رسمی npm | ADR-002 deny-list | ADR-003 ریپو PUBLIC + داده مصنوعی | ADR-004 استثنای موقت audit برای picomatch (`docs/adr/`).
- ADR-005 دیتابیس/ایزولاسیون Tenant: Drizzle + `pg`، دو نقش DB (owner برای Migration، `bitabar_app` محدود برای Runtime)، RLS + `TenantDb` (D1–D13) — `docs/adr/005-database-drizzle-rls.md`.
- **تصمیمات مالک برای F1 (۱۴۰۵/۰۸/۲۷):** ORM = **Drizzle** (طبق برنامه معماری مالک؛ ADR در F1-02 نوشته می‌شود). نقش `CARRIER_ADMIN` فعلاً **فقط ورود، بدون هیچ مجوز عملیاتی** (موقت، در انتظار OD-37). ترتیب رسمی Taskهای F1 طبق برنامه مالک: F1-01 اسکلت API، F1-02 دیتابیس/Drizzle/Migration/Tenant Context، F1-03 کاربران و نقش‌ها (+Seed)، F1-04 احراز هویت، F1-05 RBAC، F1-06 Audit/Idempotency/Outbox، F1-07 داده پایه، F1-08 باربری‌ها، F1-09 اسکلت Web، F1-10 تست ایزولاسیون/IDOR/RLS (+ورود ۴ نقش)، F1-11 Dockerfile و Build ایمیج در CI. محل UI پنل اپراتور (احتمالاً داخل F1-09) در شروع F1-09 تایید می‌شود.
- `apps/api` به‌صورت **ESM** اجرا می‌شود (هم‌راستا با بقیه ریپو)؛ تست‌های NestJS با `unplugin-swc` (esbuild متادیتای decorator ندارد). `@nestjs/cli` برای build/dev استفاده می‌شود (GUIDELINES §۳.۵-د).

## ۴. انجام‌شده (Changelog) ← جدیدترین بالا

- [۱۴۰۵/۰۸/۲۷ | uncommitted | F1-01] اسکلت NestJS API: Config با Zod (fail-fast)، پاسخ/خطای استاندارد، DomainError، ZodValidationPipe، لاگ JSON (nestjs-pino) + request-id، Health endpoints، Swagger، Helmet + CORS محیطی. ۱۹ تست (۵ واحد + ادغام supertest) + smoke test واقعی روی build سبز. وابستگی‌های جدید: NestJS 11، zod 4، nestjs-pino/pino، helmet، supertest، unplugin-swc، @nestjs/cli. `allowBuilds` در pnpm-workspace: swc=true، scarf=false.
- [۱۴۰۵/۰۸/۲۷ | uncommitted | F0-01..09] نصب تمیز از npmjs (رفع binding ویندوز Rolldown/lightningcss)، `.npmrc`، `.gitleaks.toml` + `docs/security/data-handling.md`، اصلاح مسیر Design System و متن Private، Docker Compose dev + `infra/scripts/dev-up.sh`، `packages/ui` توکن‌ها (۵ تست)، CI: job `compose-config`، ADR-001..004، ضمیمه گزارش ممیزی.
- [۱۴۰۵/۰۸/۲۵ | cb3ac5e | F0/قدم صفر] ساختار درختی Monorepo، README، `.nvmrc`(24)، `.editorconfig`، `.gitattributes`، `.env.example`، `.gitignore` کامل.

## ۵. در حال انجام / بعدی

- **منتظر بازبینی مالک روی F1-01** → سپس Commit/Push (با اجازه) → F1-02 (دیتابیس/Drizzle/Migration/Tenant Context) با تایید مالک.

## ۶. پرسش‌های باز و فرض‌ها (برای مالک)

- (تصمیم مالک OWN-17، ۱۴۰۵/۰۸/۲۶) ریپو تا پایان پروژه PUBLIC می‌ماند؛ محافظت سبک روی main (منع Force Push و حذف) منتظر تایید جداگانه مالک.
- (OD-37) مجوزهای نهایی نقش `CARRIER_ADMIN` تعیین نشده؛ فعلاً نقش فقط‌ورود است. در F1-05 در `docs/security/permission-matrix.md` مستند و Placeholder می‌شود.
- UI صفحات داده پایه پنل اپراتور دقیقاً در کدام Task قرار می‌گیرد؟ فرض: داخل F1-09؛ در شروع F1-09 با مالک تایید می‌شود.

## ۷. بدهی فنی و ریسک‌های شناخته‌شده

- `pnpm audit`: picomatch ≤4.0.7 (GHSA-fc5q-39xc-vjpf، High، فقط dev، نسخه اصلاح‌شده منتشر نشده) با استثنای موقت ADR-004 در `pnpm-workspace.yaml` نادیده گرفته می‌شود؛ بازبینی تا 2026-12-18 و حذف به‌محض انتشار اصلاح. minimatch 10.2.6 (Moderate، dev) باز و قابل مشاهده است.
- دانلود از registry.npmjs.org روی این شبکه کند/ناپایدار است (retry).
- `glob` ≤14.0.1 (Moderate، GHSA-3g3m-2fjr-6pw4) از طریق `@nestjs/cli` — فقط ابزار build توسعه؛ در F1 با انتشار اصلاح `@nestjs/cli` به‌روز شود.

## ۸. دستورهای مهم (اجرا، تست، Migration، Seed، Deploy)

- `sh infra/scripts/dev-up.sh` | `docker compose -f infra/compose/docker-compose.dev.yml down` (بدون `-v`)
- Migration: `pnpm --filter @bitabar/api db:generate` (ساخت) | `db:check` | `db:migrate` (اجرا با `DATABASE_MIGRATION_URL`) | `db:migrate:prod` (روی build). هرگز خودکار هنگام Start اجرا نمی‌شود.
- فعال‌سازی لاگین نقش Runtime در dev: `sh infra/scripts/db-app-user.sh` (نیازمند `APP_DB_PASSWORD` واقعی در `.env`).
- Gitleaks: `docker run --rm -v "<repo>:/repo:ro" zricethezav/gitleaks:v8.28.0 git /repo --config /repo/.gitleaks.toml --redact`
- `pnpm install` | `pnpm lint` | `pnpm typecheck` | `pnpm test` (بدون Docker) | `pnpm test:int` (Testcontainers — نیازمند Docker) | `pnpm build` | `pnpm format`

## ۹. وضعیت امنیت و بنچمارک (آخرین نتیجه + لینک گزارش)

- هنوز اجرا نشده (فاز F7).
