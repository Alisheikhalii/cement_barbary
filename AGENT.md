# AGENT.md – حافظه پروژه (همیشه به‌روز)

## ۱. وضعیت فعلی

- فاز فعلی: **F1** — F1-03 **کامل شد** (T01–T08، Commitهای محلی تا 156a698 + T08)؛ بعدی F1-04 (احراز هویت) با تایید مالک | آخرین Tag: — | آخرین Commit: 3ac43eb
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
- `apps/api/src/modules/users` (F1-03 T06): `UsersRepository` — تنها مسیر خواندن/نوشتن کاربران (TenantDb + PiiService، بدون HTTP)؛ `apps/api/src/security/pii`: رمزنگاری AES-256-GCM+AAD، Blind Index، نرمال‌سازی، mask؛ `apps/api/src/db/seed/dev-seed.ts` (T07): Seed مصنوعی فقط-dev با guard محیطی، خارج از build/Docker/CI. فیلتر خطا: `details` فقط برای <500 در پاسخ HTTP (تصمیم مالک، T06).
- `infra/compose/docker-compose.dev.yml`: PostgreSQL 17 + Redis 7 (فقط 127.0.0.1، healthcheck، پروژه `bitabar-dev`).
- مدل داده: جدول `tenants` (RLS فعال + سیاست ایزولاسیون؛ INSERT/DELETE برای نقش Runtime ممنوع) + توابع `app.current_tenant_id()`/`app.current_carrier_id()` (fail-closed: بدون context هیچ سطری دیده نمی‌شود). Migrationها: `apps/api/drizzle/0000_init_tenants.sql` و `0001_rls_foundation.sql`.
- Endpointها: فقط Health (`/health/live`، `/health/ready` با پینگ واقعی DB: 200/503).
- فایل‌های طراحی ظاهری: `docs/specs/{carrier,operator,driver}-panel.html` — فقط در فاز UI خوانده شوند؛ PNGها در deny هستند.

## ۳. تصمیمات مهم (ADR خلاصه + لینک)

- قوانین deny خواندن در `.claude/settings.json`. چون deny بر allow غلبه دارد، به‌جای `.env.*` الگوهای مشخص (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`) گذاشته شد تا `.env.example` قابل‌خواندن بماند.
- `.gitattributes` با `eol=lf`: توسعه روی ویندوز، CI و سرور لینوکس.
- ADR-001 نسخه ابزارها + `.npmrc` رجیستری رسمی npm | ADR-002 deny-list | ADR-003 ریپو PUBLIC + داده مصنوعی | ADR-004 استثنای موقت audit برای picomatch (`docs/adr/`).
- ADR-005 دیتابیس/ایزولاسیون Tenant: Drizzle + `pg`، دو نقش DB (owner برای Migration، `bitabar_app` محدود برای Runtime)، RLS + `TenantDb` (D1–D13) — `docs/adr/005-database-drizzle-rls.md`.
- ADR-006 کاربران/نقش‌ها/PII: نقش‌ها داده‌اند (۳ نقش — در T05b از ۶ نقش کاهش یافت، فقط Migration)، `users`/`user_roles` با RLS و FK ترکیبی، رمزنگاری AES-256-GCM با AAD و key_version، Blind Index با HMAC جدا، یکتایی per-tenant، Seed فقط dev — `docs/adr/006-users-roles-pii.md` (+ `docs/security/pii.md`).
- **تصمیم مالک T05b (۱۴۰۵/۰۸/۲۹):** کاتالوگ نقش‌ها به ۳ نقش کاهش یافت (`FACTORY_OPERATOR`، `CARRIER_ADMIN`، `DRIVER`)؛ `PLATFORM_ADMIN`/`CARRIER_OPERATOR`/`AUDITOR` با Migration سفارشی `0004_role_catalog_trim` حذف شدند (forward-only؛ 0002/0003 ویرایش نشدند؛ guard در برابر ارجاع `user_roles`). `CARRIER_ADMIN` تنها نقش باربری است و مسئولیت‌های `CARRIER_OPERATOR` (اعلام بار، تایید لغو، صدور مجوز) را بر عهده گرفت — **OD-37 بسته شد**؛ ماتریس مجوز در F1-05 نوشته می‌شود. اصلاحیه در ADR-006 (تاریخچه بازنویسی نشد).
- **تصمیمات مالک برای F1 (۱۴۰۵/۰۸/۲۷):** ORM = **Drizzle** (طبق برنامه معماری مالک؛ ADR در F1-02 نوشته می‌شود). نقش `CARRIER_ADMIN` فعلاً **فقط ورود، بدون هیچ مجوز عملیاتی** (موقت، در انتظار OD-37). ترتیب رسمی Taskهای F1 طبق برنامه مالک: F1-01 اسکلت API، F1-02 دیتابیس/Drizzle/Migration/Tenant Context، F1-03 کاربران و نقش‌ها (+Seed)، F1-04 احراز هویت، F1-05 RBAC، F1-06 Audit/Idempotency/Outbox، F1-07 داده پایه، F1-08 باربری‌ها، F1-09 اسکلت Web، F1-10 تست ایزولاسیون/IDOR/RLS (+ورود ۳ نقش — پس از کاهش کاتالوگ در T05b)، F1-11 Dockerfile و Build ایمیج در CI. محل UI پنل اپراتور (احتمالاً داخل F1-09) در شروع F1-09 تایید می‌شود.
- `apps/api` به‌صورت **ESM** اجرا می‌شود (هم‌راستا با بقیه ریپو)؛ تست‌های NestJS با `unplugin-swc` (esbuild متادیتای decorator ندارد). `@nestjs/cli` برای build/dev استفاده می‌شود (GUIDELINES §۳.۵-د).

## ۴. انجام‌شده (Changelog) ← جدیدترین بالا

- [۱۴۰۵/۰۸/۲۹ | 3ac43eb | F1-03 T08] جمع‌بندی F1-03: رفع تست flaky (warm-up نمونه ESLint در beforeAll با hookTimeout=60s + maxWorkers=4 + turbo --concurrency=2 — پایداری: ۲۰ اجرای متوالی سبز)؛ پاک‌سازی literalهای U17 (الگوی قدیمی موبایل/کدملی در مستندات و تست‌ها → بازه allowlist + randomNationalId؛ بدون نقل‌قول literal) در mask.ts/normalize.test.ts/users.types.test.ts + توسعه allowlist گیت‌لیکس برای فرم‌های +98/0098 همان بازه مصنوعی؛ gitleaks working-tree تمیز. **معوقه:** بازنویسی تاریخچه محلی برای حذف literalهای قدیمی از Commitهای push‌نشده — منتظر تایید مالک (پیشنهاد در گزارش T08).
- [۱۴۰۵/۰۸/۲۹ | 156a698 | F1-03 T07] Seed توسعه (U16): `src/db/seed/dev-seed.ts` با guard داخل runDevSeed (NODE_ENV=development اجباری — unset هم رد می‌شود — + host محلی برای هر دو URL)؛ tenant به‌عنوان owner، همه نوشتن users از طریق UsersRepository/TenantContext به‌عنوان نقش Runtime؛ idempotent؛ خارج از build/Docker/CI. ۱۰ تست ادغام (رد، idempotency، national_id=NULL، رمزنگاری+AAD، خوانش RLS). بازبینی امنیتی: APPROVE.
- [۱۴۰۵/۰۸/۲۹ | 332ce7f | F1-03 T06] `UsersRepository` (U15): create/findById/findByUsername/findByPhone/assignRole/revokeRole/listRoles/softDelete فقط از طریق TenantDb + PiiService؛ بدون HTTP، بدون نوشتن national_id (Q3)؛ ترجمه SQLSTATE به DomainError (23505→conflict، 23503→badInput، بقیه→internal بدون لو رفتن متن SQL)؛ `src/db/sql.ts` re-export عملگرهای drizzle برای حفظ مرز D11. **+ اصلاح امنیتی فیلتر (تصمیم مالک، گزینه A):** `details` فقط برای خطای <500 در پاسخ HTTP می‌آید؛ برای 5xx فقط لاگ با request id (پیش از این `pgCode` به کلاینت لو می‌رفت). نتیجه: ۱۱۵ واحد + ۵۷ ادغام سبز.
- [۱۴۰۵/۰۸/۲۹ | a93dfc6 | F1-03 T05b] کاهش کاتالوگ نقش‌ها به ۳ نقش (تصمیم مالک): Migration سفارشی 0004 (guard در برابر ارجاع user_roles + حذف PLATFORM_ADMIN/CARRIER_OPERATOR/AUDITOR + توضیح جدید CARRIER_ADMIN)؛ تست‌ها به ۳ نقش به‌روز شدند (سناریوی CHECK پلتفرم همچنان 23514 را اثبات می‌کند)؛ اصلاحیه ADR-006، PRD §۲ و BR-16، rls.md؛ OD-37 بسته شد.
- [۱۴۰۵/۰۸/۲۹ | 1907d3d | F1-03 T05] سوئیت ایزولاسیون `users`/`user_roles` (۱۱ سناریوی جدید به‌عنوان `bitabar_app`: fail-closed، IDOR، 42501، حذف نرم، رد FK/CHECK/scope جعلی، یکتایی phone_hash per-tenant + استفاده مجدد پس از حذف نرم، CHECKهای U12، خالی‌بودن national_id) + guard سخت‌گیرانه U14 با allowlist و کنترل منفی. Fixtureها از مسیر واقعی PII. نتیجه: ۱۰۰ واحد + ۴۴ ادغام سبز.
- [۱۴۰۵/۰۸/۲۹ | 0da92a6 | F1-03 T04] Migration سفارشی 0003: درج ۶ نقش (ON CONFLICT)، لغو INSERT/UPDATE/DELETE روی `roles`، الگوی RLS روی `users`/`user_roles`، لغو DELETE روی `users` (حذف نرم، U13). نام‌های فارسی نقش‌ها با تست بایت‌محور (hex) روی کانتینر تازه تایید شدند. `rls.md`: فهرست U14 + هشدار recreate.
- [۱۴۰۵/۰۸/۲۹ | df4f8b5 | F1-03 T03] schemaهای `roles`/`users`/`user_roles` + Migration تولیدی 0002: FKهای ترکیبی (U4/U5/U6)، CHECKهای U12، indexهای یکتای partial per-tenant؛ اهداف FK به‌صورت UNIQUE constraint داخل CREATE TABLE (نه index) تا ترتیب Migration معتبر باشد.
- [۱۴۰۵/۰۸/۲۹ | 47577a0 | F1-03 T02] سرویس PII: AES-256-GCM با AAD سه‌بخشی `tenant:column:row` (اعتبارسنجی Zod برای UUIDها)، Blind Index با HMAC جدا، نرمال‌سازی موبایل/کدملی (ارقام فارسی/عربی + checksum)، redaction ساختاری pino (مسیر اجدادی، چرخه → `'[Circular]'`)، اعتبارسنجی env برای `PII_ENC_KEY`/`PII_HMAC_KEY`/`PII_KEY_ID`. ۱۰۰ تست واحد؛ حلقه ۱۰ باره سبز.
- [۱۴۰۵/۰۸/۲۹ | F1-03 T01] برنامه F1-03 با تایید مالک و تغییرات الزامی (a)–(g) پچ شد؛ ADR-006 (کاربران/نقش‌ها/PII، U1–U17) و `docs/security/pii.md` نوشته شد؛ تصمیمات Q1–Q3 مالک در §۶ ثبت شد.

- [۱۴۰۵/۰۸/۲۸ | 2275734..0cea632 | F1-02 T01–T10] دیتابیس و ایزولاسیون Tenant: ADR-005؛ env دیتابیس با Zod؛ schema `tenants` (UUID v7، index یکتای partial، checkها) + Migrationهای 0000/0001 (نقش `bitabar_app` محدود: NOLOGIN/NOBYPASSRLS/NOSUPERUSER، DML-only، default privileges؛ توابع context با search_path سنجاق‌شده؛ RLS روی tenants با الگوی subselect)؛ Migration runner جدا (owner) + `infra/scripts/db-app-user.sh`؛ Testcontainers (PostgreSQL 17 واقعی) + CI (test:int + قفل هم‌گامی db:generate)؛ DatabaseModule + `/health/ready` واقعی؛ `TenantContext`/`TenantDb` (ALS، set_config تراکنسی پارامتری، reuse تودرتو، fail-closed، محافظ Proxy برای handle)؛ سوئیت RLS با ۱۴ تست (۱۰ سناریو + اثبات نقش + تست leak + guard «هر جدول tenant_id دارای RLS+policy است» با کنترل منفی)؛ قانون مرزی ESLint D11 + تست اثبات. نتیجه: ۴۱ تست واحد + ۳۰ تست ادغام سبز. بازبینی Opus در T04/T08/T09 انجام شد.
- [۱۴۰۵/۰۸/۲۷ | 0d26f3c | F1-01] اسکلت NestJS API: Config با Zod (fail-fast)، پاسخ/خطای استاندارد، DomainError، ZodValidationPipe، لاگ JSON (nestjs-pino) + request-id، Health endpoints، Swagger، Helmet + CORS محیطی. ۱۹ تست (۵ واحد + ادغام supertest) + smoke test واقعی روی build سبز. وابستگی‌های جدید: NestJS 11، zod 4، nestjs-pino/pino، helmet، supertest، unplugin-swc، @nestjs/cli. `allowBuilds` در pnpm-workspace: swc=true، scarf=false.
- [۱۴۰۵/۰۸/۲۷ | uncommitted | F0-01..09] نصب تمیز از npmjs (رفع binding ویندوز Rolldown/lightningcss)، `.npmrc`، `.gitleaks.toml` + `docs/security/data-handling.md`، اصلاح مسیر Design System و متن Private، Docker Compose dev + `infra/scripts/dev-up.sh`، `packages/ui` توکن‌ها (۵ تست)، CI: job `compose-config`، ADR-001..004، ضمیمه گزارش ممیزی.
- [۱۴۰۵/۰۸/۲۵ | cb3ac5e | F0/قدم صفر] ساختار درختی Monorepo، README، `.nvmrc`(24)، `.editorconfig`، `.gitattributes`، `.env.example`، `.gitignore` کامل.

## ۵. در حال انجام / بعدی

- F1-03 کامل و بسته شد (T01–T08). بعدی: **F1-04 احراز هویت** — با تایید مالک شروع می‌شود؛ الزام §۶ درباره پاسخ/زمان‌بندی یکسان ورود (عدم شمارش کاربر) را در طراحی F1-04 لحاظ کن. **Push/Tag فقط با اجازه مالک.**

## ۶. پرسش‌های باز و فرض‌ها (برای مالک)

- (تصمیم مالک OWN-17، ۱۴۰۵/۰۸/۲۶) ریپو تا پایان پروژه PUBLIC می‌ماند؛ محافظت سبک روی main (منع Force Push و حذف) منتظر تایید جداگانه مالک.
- (OD-37 — **بسته شد در T05b**، ۱۴۰۵/۰۸/۲۹) `CARRIER_ADMIN` تنها نقش باربری است و مسئولیت‌های `CARRIER_OPERATOR` را بر عهده گرفت؛ ماتریس مجوزهایش در F1-05 در `docs/security/permission-matrix.md` نوشته می‌شود.
- (ثبت T05b برنامه F1-03) نقش `CARRIER_ADMIN` برای اتصال واقعی به یک باربری به ستون `carrier_id` روی `users` نیاز دارد؛ این در **F1-08** (باربری‌ها) حل می‌شود. تا آن زمان نقش فقط به‌عنوان داده وجود دارد.
- (تصمیم مالک Q2/Q3 برنامه F1-03، ۱۴۰۵/۰۸/۲۹) موبایل مثل کد ملی رمزنگاری می‌شود. ستون‌های رمزنگاری‌شده کد ملی در F1-03 ساخته می‌شوند ولی **در این فاز هیچ داده‌ای در آن‌ها نوشته نمی‌شود** (مسیر نوشتن در F4 با پروفایل راننده).
- UI صفحات داده پایه پنل اپراتور دقیقاً در کدام Task قرار می‌گیرد؟ فرض: داخل F1-09؛ در شروع F1-09 با مالک تایید می‌شود.
- (ثبت T06، ۱۴۰۵/۰۸/۲۹) عدم‌تقارن عمدی Repository: `findByUsername` برای ورودی بدفرمت `null` برمی‌گرداند ولی `findByPhone` همان ورودی را با `badInput` رد می‌کند. **الزام F1-04:** پاسخ ورود برای «کاربر ناشناخته»، «شناسه بدفرمت» و «رمز اشتباه» باید **یکسان** (کد/پیام/وضعیت) و از نظر زمان‌بندی **مشابه** باشد تا شمارش کاربر (user enumeration) ممکن نشود؛ این ناهم‌خوانی در لایه Auth باید جذب شود، نه در Repository.
- (تصمیم مالک، ۱۴۰۵/۰۸/۲۹) نشت `details` در پاسخ HTTP با گزینه A بسته شد: فیلتر فقط برای خطای <500 فیلد `details` را می‌فرستد؛ برای 5xx فقط در لاگ (همراه request id). پوشش: `http-exception.filter.test.ts`.

## ۷. بدهی فنی و ریسک‌های شناخته‌شده

- نگه‌داری Blind Index پس از حذف نرم (ثبت T05): مقدار `*_enc`/`*_hash` در سطر حذف‌نرم‌شده باقی می‌ماند و index یکتای partial هش را برای استفاده مجدد آزاد می‌کند؛ سیاست purge (مدت نگه‌داری PII رمزنگاری‌شده کاربران حذف‌شده) یک تصمیم باز محصولی/حقوقی است — یادداشت سیاست در `docs/security/pii.md` بخش Retention.
- چرخش کلیدهای PII (چند key_version فعال) هنوز ساخته نشده؛ بایت `key_version` در header امکانش را می‌دهد (ADR-006 U10).
- `pnpm audit` (۱۴۰۵/۰۸/۲۸): ۳ Moderate فقط در ابزار dev — esbuild ≤0.24.2 (از طریق drizzle-kit) و glob ≤14.0.1 (از طریق @nestjs/cli و testcontainers)؛ هیچ‌کدام در Runtime قرار نمی‌گیرند و `--audit-level=high` سبز است. picomatch ≤4.0.7 (High، فقط dev) همچنان با استثنای موقت ADR-004 پوشش داده می‌شود؛ بازبینی تا 2026-12-18.
- دانلود از registry.npmjs.org روی این شبکه کند/ناپایدار است (retry).
- **docker.io برای Pull جدید 403 می‌دهد** (شبکه ایران): راه‌حل = Pull از `docker.arvancloud.ir/<image>` سپس `docker tag` به نام اصلی (برای `testcontainers/ryuk:0.14.0` و `zricethezav/gitleaks:v8.28.0` انجام و کش شد).
- ریسک بسته‌شده در T09: handle تراکنشِ نگه‌داری‌شده پس از پایان `TenantDb.run` می‌توانست روی connection استفاده‌مجددشده داخل تراکنش Tenant دیگر اجرا شود؛ با Proxy محافظ در `tenant-db.ts` بسته شد (تست leak در `test/rls.int.test.ts`).
- **بدهی T08:** یک تست واحد به‌صورت متناوب (۴ مشاهده تا ۱۴۰۵/۰۸/۲۹) Fail می‌شود؛ مظنون‌ها: ساخت نمونه ESLint در `eslint-boundary.test.ts`، رقابت workerهای turbo/vitest، یا timeout. ریشه‌یابی توسط Subagent در T07 انجام و اصلاح در T08 اعمال می‌شود. → **حل شد در T08:** ریشه = بار یک‌باره lazy لود flat-config/pلاگین‌های ESLint داخل اولین lintText تحت رقابت CPU؛ اصلاح: warm-up در beforeAll (۶۰s) + maxWorkers=4 + turbo --concurrency=2؛ ۲۰/۲۰ اجرا سبز.

## ۸. دستورهای مهم (اجرا، تست، Migration، Seed، Deploy)

- `sh infra/scripts/dev-up.sh` | `docker compose -f infra/compose/docker-compose.dev.yml down` (بدون `-v`)
- Migration: `pnpm --filter @bitabar/api db:generate` (ساخت) | `db:check` | `db:migrate` (اجرا با `DATABASE_MIGRATION_URL`) | `db:migrate:prod` (روی build). هرگز خودکار هنگام Start اجرا نمی‌شود.
- فعال‌سازی لاگین نقش Runtime در dev: `sh infra/scripts/db-app-user.sh` (نیازمند `APP_DB_PASSWORD` واقعی در `.env`).
- Seed توسعه (فقط local): `pnpm --filter @bitabar/api db:seed:dev` — فقط با `NODE_ENV=development` و دیتابیس localhost اجرا می‌شود؛ نیازمند `DATABASE_MIGRATION_URL` + `DATABASE_URL` + کلیدهای PII در `.env`. idempotent؛ داده کاملاً مصنوعی (tenant `dev-factory` + ۳ کاربر، بدون کد ملی/رمز). در CI/Build/Docker وجود ندارد.
- Gitleaks: `docker run --rm -v "<repo>:/repo:ro" zricethezav/gitleaks:v8.28.0 git /repo --config /repo/.gitleaks.toml --redact`
- `pnpm install` | `pnpm lint` | `pnpm typecheck` | `pnpm test` (بدون Docker) | `pnpm test:int` (Testcontainers — نیازمند Docker؛ شامل سوئیت ایزولاسیون `test/rls.int.test.ts`) | `pnpm build` | `pnpm format`
- قفل هم‌گامی Schema↔Migration: `pnpm --filter @bitabar/api db:generate` باید «No schema changes» بگوید و `git diff --exit-code -- apps/api/drizzle` تمیز بماند (در CI هم enforce می‌شود).

## ۹. وضعیت امنیت و بنچمارک (آخرین نتیجه + لینک گزارش)

- ایزولاسیون Tenant (F1-02 + F1-03): سوئیت RLS سبز + UsersRepository/Seed از مسیر واقعی RLS+PII — **۱۱۵ تست واحد + ۶۶ تست ادغام سبز** (۱۴۰۵/۰۸/۲۹). gitleaks working-tree: تمیز (T08)؛ تاریخچه git محلی هنوز literalهای قدیمی را دارد تا تایید بازنویسی (§۴/T08). ممیزی امنیتی کامل و بنچمارک در فاز F7.
