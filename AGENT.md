# AGENT.md – حافظه پروژه (همیشه به‌روز)

## ۱. وضعیت فعلی

- فاز فعلی: **F1** — F1-01 (اسکلت API) و F1-02 (دیتابیس/Drizzle/Migration/RLS/Tenant Context) کامل شدند (Commit محلی، **Push نشده**) | آخرین Tag: — | آخرین Commit: 0cea632
- CI: سبز (F0) | تاریخ آخرین به‌روزرسانی: ۱۴۰۵/۰۸/۲۹
- ریپو: `github.com/Alisheikhalii/cement_barbary` (شاخه `main`)

## ۲. نقشه پروژه (فقط خلاصه)

- Monorepo با pnpm workspaces + Turborepo (ساختار GUIDELINES §۲).
- `packages/config`: tsconfig پایه (strict)، ESLint flat config، Prettier — همه پکیج‌ها از این ارث می‌برند.
- `packages/shared`: ثوابت/تایپ/Schemaهای مشترک Front و Back (فعلاً فقط `constants`).
- `packages/ui`: توکن‌های Design System (`src/tokens.ts` + `src/tokens.css` + `tailwind-preset.ts`)، تست هم‌خوانی و منع URL خارجی.
- `apps/api`: **NestJS 11 (ESM/NodeNext)** — Config با اعتبارسنجی Zod، پاسخ/خطای استاندارد (`{data,meta}`/`{error}`)، لاگ JSON با nestjs-pino + request-id، Health (`/health/live`، `/health/ready` بدون پیشوند)، Swagger در `/api/docs`، Helmet + CORS محیطی، ZodValidationPipe. (F1-01)
- `apps/api/src/db` (F1-02، تنها مرز DB طبق ADR-005): `schema/` (Drizzle، جدول `tenants`)، `database.providers` (Pool/DB داخلی، نقش `bitabar_app`)، `TenantContext` (AsyncLocalStorage، اعتبارسنجی UUID با Zod)، `TenantDb.run` (تراکنش + `set_config` تراکنسیِ پارامتری برای `app.tenant_id`/`app.carrier_id`، reuse تودرتو با همان scope، fail-closed با `TENANT_CONTEXT_MISSING`، Proxy محافظ: handle پس از پایان run می‌میرد)، `migrate.ts` (CLI فقط با `DATABASE_MIGRATION_URL`، هرگز خودکار هنگام Start)، `db-health`. قانون ESLint: import خام `pg`/`drizzle-orm`/توکن‌های DB خارج از `src/db/**` ممنوع (تست اثبات در `test/eslint-boundary.test.ts`).
- `apps/web`: فعلاً فقط اسکلت پوشه.
- `infra/compose/docker-compose.dev.yml`: PostgreSQL 17 + Redis 7 (فقط 127.0.0.1، healthcheck، پروژه `bitabar-dev`).
- مدل داده: جدول `tenants` (RLS فعال + سیاست ایزولاسیون؛ INSERT/DELETE برای نقش Runtime ممنوع) + توابع `app.current_tenant_id()`/`app.current_carrier_id()` (fail-closed: بدون context هیچ سطری دیده نمی‌شود). Migrationها: `apps/api/drizzle/0000_init_tenants.sql` و `0001_rls_foundation.sql`.
- Endpointها: فقط Health (`/health/live`، `/health/ready` با پینگ واقعی DB: 200/503).
- فایل‌های طراحی ظاهری: `docs/specs/{carrier,operator,driver}-panel.html` — فقط در فاز UI خوانده شوند؛ PNGها در deny هستند.

## ۳. تصمیمات مهم (ADR خلاصه + لینک)

- قوانین deny خواندن در `.claude/settings.json`. چون deny بر allow غلبه دارد، به‌جای `.env.*` الگوهای مشخص (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`) گذاشته شد تا `.env.example` قابل‌خواندن بماند.
- `.gitattributes` با `eol=lf`: توسعه روی ویندوز، CI و سرور لینوکس.
- ADR-001 نسخه ابزارها + `.npmrc` رجیستری رسمی npm | ADR-002 deny-list | ADR-003 ریپو PUBLIC + داده مصنوعی | ADR-004 استثنای موقت audit برای picomatch (`docs/adr/`).
- ADR-005 دیتابیس/ایزولاسیون Tenant: Drizzle + `pg`، دو نقش DB (owner برای Migration، `bitabar_app` محدود برای Runtime)، RLS + `TenantDb` (D1–D13) — `docs/adr/005-database-drizzle-rls.md`.
- ADR-006 کاربران/نقش‌ها/PII: نقش‌ها داده‌اند (۶ نقش، فقط Migration)، `users`/`user_roles` با RLS و FK ترکیبی، رمزنگاری AES-256-GCM با AAD و key_version، Blind Index با HMAC جدا، یکتایی per-tenant، Seed فقط dev — `docs/adr/006-users-roles-pii.md` (+ `docs/security/pii.md`).
- **تصمیمات مالک برای F1 (۱۴۰۵/۰۸/۲۷):** ORM = **Drizzle** (طبق برنامه معماری مالک؛ ADR در F1-02 نوشته می‌شود). نقش `CARRIER_ADMIN` فعلاً **فقط ورود، بدون هیچ مجوز عملیاتی** (موقت، در انتظار OD-37). ترتیب رسمی Taskهای F1 طبق برنامه مالک: F1-01 اسکلت API، F1-02 دیتابیس/Drizzle/Migration/Tenant Context، F1-03 کاربران و نقش‌ها (+Seed)، F1-04 احراز هویت، F1-05 RBAC، F1-06 Audit/Idempotency/Outbox، F1-07 داده پایه، F1-08 باربری‌ها، F1-09 اسکلت Web، F1-10 تست ایزولاسیون/IDOR/RLS (+ورود ۴ نقش)، F1-11 Dockerfile و Build ایمیج در CI. محل UI پنل اپراتور (احتمالاً داخل F1-09) در شروع F1-09 تایید می‌شود.
- `apps/api` به‌صورت **ESM** اجرا می‌شود (هم‌راستا با بقیه ریپو)؛ تست‌های NestJS با `unplugin-swc` (esbuild متادیتای decorator ندارد). `@nestjs/cli` برای build/dev استفاده می‌شود (GUIDELINES §۳.۵-د).

## ۴. انجام‌شده (Changelog) ← جدیدترین بالا

- [۱۴۰۵/۰۸/۲۹ | F1-03 T01] برنامه F1-03 با تایید مالک و تغییرات الزامی (a)–(g) پچ شد؛ ADR-006 (کاربران/نقش‌ها/PII، U1–U17) و `docs/security/pii.md` نوشته شد؛ تصمیمات Q1–Q3 مالک در §۶ ثبت شد.

- [۱۴۰۵/۰۸/۲۸ | 2275734..0cea632 | F1-02 T01–T10] دیتابیس و ایزولاسیون Tenant: ADR-005؛ env دیتابیس با Zod؛ schema `tenants` (UUID v7، index یکتای partial، checkها) + Migrationهای 0000/0001 (نقش `bitabar_app` محدود: NOLOGIN/NOBYPASSRLS/NOSUPERUSER، DML-only، default privileges؛ توابع context با search_path سنجاق‌شده؛ RLS روی tenants با الگوی subselect)؛ Migration runner جدا (owner) + `infra/scripts/db-app-user.sh`؛ Testcontainers (PostgreSQL 17 واقعی) + CI (test:int + قفل هم‌گامی db:generate)؛ DatabaseModule + `/health/ready` واقعی؛ `TenantContext`/`TenantDb` (ALS، set_config تراکنسی پارامتری، reuse تودرتو، fail-closed، محافظ Proxy برای handle)؛ سوئیت RLS با ۱۴ تست (۱۰ سناریو + اثبات نقش + تست leak + guard «هر جدول tenant_id دارای RLS+policy است» با کنترل منفی)؛ قانون مرزی ESLint D11 + تست اثبات. نتیجه: ۴۱ تست واحد + ۳۰ تست ادغام سبز. بازبینی Opus در T04/T08/T09 انجام شد.
- [۱۴۰۵/۰۸/۲۷ | 0d26f3c | F1-01] اسکلت NestJS API: Config با Zod (fail-fast)، پاسخ/خطای استاندارد، DomainError، ZodValidationPipe، لاگ JSON (nestjs-pino) + request-id، Health endpoints، Swagger، Helmet + CORS محیطی. ۱۹ تست (۵ واحد + ادغام supertest) + smoke test واقعی روی build سبز. وابستگی‌های جدید: NestJS 11، zod 4، nestjs-pino/pino، helmet، supertest، unplugin-swc، @nestjs/cli. `allowBuilds` در pnpm-workspace: swc=true، scarf=false.
- [۱۴۰۵/۰۸/۲۷ | uncommitted | F0-01..09] نصب تمیز از npmjs (رفع binding ویندوز Rolldown/lightningcss)، `.npmrc`، `.gitleaks.toml` + `docs/security/data-handling.md`، اصلاح مسیر Design System و متن Private، Docker Compose dev + `infra/scripts/dev-up.sh`، `packages/ui` توکن‌ها (۵ تست)، CI: job `compose-config`، ADR-001..004، ضمیمه گزارش ممیزی.
- [۱۴۰۵/۰۸/۲۵ | cb3ac5e | F0/قدم صفر] ساختار درختی Monorepo، README، `.nvmrc`(24)، `.editorconfig`، `.gitattributes`، `.env.example`، `.gitignore` کامل.

## ۵. در حال انجام / بعدی

- F1-02 کامل و به‌صورت محلی Commit شده (Commit نهایی T10 در انتظار تایید بازبینی مالک). **Push/Tag فقط با اجازه مالک.**
- بعدی: **F1-03** (کاربران و نقش‌ها + Seed) — با تایید مالک.

## ۶. پرسش‌های باز و فرض‌ها (برای مالک)

- (تصمیم مالک OWN-17، ۱۴۰۵/۰۸/۲۶) ریپو تا پایان پروژه PUBLIC می‌ماند؛ محافظت سبک روی main (منع Force Push و حذف) منتظر تایید جداگانه مالک.
- (OD-37) مجوزهای نهایی نقش `CARRIER_ADMIN` تعیین نشده؛ فعلاً نقش فقط‌ورود است. در F1-05 در `docs/security/permission-matrix.md` مستند و Placeholder می‌شود.
- (تصمیم مالک Q1 برنامه F1-03، ۱۴۰۵/۰۸/۲۹) نقش `PLATFORM_ADMIN` فقط به‌عنوان داده وجود دارد و به هیچ کاربر Tenant داده نمی‌شود (CHECK + FK ترکیبی در DB). **ورود وب برای این نقش در v1 به تعویق افتاده**؛ کار پلتفرم (ساخت Tenant) فقط از طریق Migration owner با CLI/Seed انجام می‌شود. در F1-10 ورود فقط برای ۴ نقش تست می‌شود.
- (تصمیم مالک Q2/Q3 برنامه F1-03، ۱۴۰۵/۰۸/۲۹) موبایل مثل کد ملی رمزنگاری می‌شود. ستون‌های رمزنگاری‌شده کد ملی در F1-03 ساخته می‌شوند ولی **در این فاز هیچ داده‌ای در آن‌ها نوشته نمی‌شود** (مسیر نوشتن در F4 با پروفایل راننده).
- UI صفحات داده پایه پنل اپراتور دقیقاً در کدام Task قرار می‌گیرد؟ فرض: داخل F1-09؛ در شروع F1-09 با مالک تایید می‌شود.

## ۷. بدهی فنی و ریسک‌های شناخته‌شده

- `pnpm audit` (۱۴۰۵/۰۸/۲۸): ۳ Moderate فقط در ابزار dev — esbuild ≤0.24.2 (از طریق drizzle-kit) و glob ≤14.0.1 (از طریق @nestjs/cli و testcontainers)؛ هیچ‌کدام در Runtime قرار نمی‌گیرند و `--audit-level=high` سبز است. picomatch ≤4.0.7 (High، فقط dev) همچنان با استثنای موقت ADR-004 پوشش داده می‌شود؛ بازبینی تا 2026-12-18.
- دانلود از registry.npmjs.org روی این شبکه کند/ناپایدار است (retry).
- **docker.io برای Pull جدید 403 می‌دهد** (شبکه ایران): راه‌حل = Pull از `docker.arvancloud.ir/<image>` سپس `docker tag` به نام اصلی (برای `testcontainers/ryuk:0.14.0` و `zricethezav/gitleaks:v8.28.0` انجام و کش شد).
- ریسک بسته‌شده در T09: handle تراکنشِ نگه‌داری‌شده پس از پایان `TenantDb.run` می‌توانست روی connection استفاده‌مجددشده داخل تراکنش Tenant دیگر اجرا شود؛ با Proxy محافظ در `tenant-db.ts` بسته شد (تست leak در `test/rls.int.test.ts`).

## ۸. دستورهای مهم (اجرا، تست، Migration، Seed، Deploy)

- `sh infra/scripts/dev-up.sh` | `docker compose -f infra/compose/docker-compose.dev.yml down` (بدون `-v`)
- Migration: `pnpm --filter @bitabar/api db:generate` (ساخت) | `db:check` | `db:migrate` (اجرا با `DATABASE_MIGRATION_URL`) | `db:migrate:prod` (روی build). هرگز خودکار هنگام Start اجرا نمی‌شود.
- فعال‌سازی لاگین نقش Runtime در dev: `sh infra/scripts/db-app-user.sh` (نیازمند `APP_DB_PASSWORD` واقعی در `.env`).
- Gitleaks: `docker run --rm -v "<repo>:/repo:ro" zricethezav/gitleaks:v8.28.0 git /repo --config /repo/.gitleaks.toml --redact`
- `pnpm install` | `pnpm lint` | `pnpm typecheck` | `pnpm test` (بدون Docker) | `pnpm test:int` (Testcontainers — نیازمند Docker؛ شامل سوئیت ایزولاسیون `test/rls.int.test.ts`) | `pnpm build` | `pnpm format`
- قفل هم‌گامی Schema↔Migration: `pnpm --filter @bitabar/api db:generate` باید «No schema changes» بگوید و `git diff --exit-code -- apps/api/drizzle` تمیز بماند (در CI هم enforce می‌شود).

## ۹. وضعیت امنیت و بنچمارک (آخرین نتیجه + لینک گزارش)

- ایزولاسیون Tenant (F1-02): سوئیت RLS **۱۴/۱۴ سبز** (۱۰ سناریو + اثبات نقش `bitabar_app` + تست leak + guard) و مرز ESLint D11 با تست اثبات — ۱۴۰۵/۰۸/۲۸. gitleaks: بدون نشتی (۱۴ Commit آخر). ممیزی امنیتی کامل و بنچمارک در فاز F7.
