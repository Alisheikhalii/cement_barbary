# GUIDELINES – استانداردهای مهندسی پروژه BitaBar

> این سند قوانین فنی ثابت پروژه است. همه کدها، تصمیمات و تغییرات باید با آن سازگار باشند.
> در تعارض: `CLAUDE.md` (فرآیند) > `GUIDELINES.md` (استاندارد فنی) > `PRD.md` (محصول) > سایر اسناد.
> اگر PRD و GUIDELINES در موضوعی ناسازگار بودند، کار را متوقف کن، در `AGENT.md` ثبت کن و از مالک بپرس.

---

## ۱. اصول حاکم

1. **درستی قبل از سرعت.** بخش نوبت‌دهی و مالی باید ثابت‌شده با تست باشد.
2. **ساده‌ترین راه‌حلی که کار می‌کند.** Modular Monolith، بدون Microservice و بدون Over-engineering.
3. **امنیت پیش‌فرض.** دسترسی بسته است مگر صریحاً باز شود (Deny by default).
4. **همه چیز قابل بازگشت.** هر تغییر = یک Commit کوچک و قابل Revert.
5. **همه چیز قابل ردگیری.** تصمیمات نوبت‌دهی و تغییرات حساس در Audit Log.
6. **بدون وابستگی به خارج از ایران در Runtime.** (CDN، فونت، آنالیتیکس خارجی ممنوع).
7. **کاربر مالک پروژه تخصص فنی ندارد:** توضیح‌ها به زبان ساده فارسی.

---

## ۲. ساختار ریپو (Monorepo)

```
bitabar/
├─ CLAUDE.md                 # دستور کار Claude Code
├─ AGENT.md                  # حافظه/لاگ تغییرات (به‌روز)
├─ README.md
├─ docs/
│  ├─ PRD.md
│  ├─ GUIDELINES.md
│  ├─ specs/                 # ۳ فایل مشخصات اولیه
│  ├─ adr/                   # Architecture Decision Records (۰۰۱-xxx.md)
│  ├─ reports/               # گزارش‌های امنیت و بنچمارک
│  └─ runbooks/              # استقرار، Backup، بازیابی
├─ apps/
│  ├─ api/                   # NestJS
│  │  └─ src/
│  │     ├─ modules/         # auth, users, tenants, carriers, destinations, halls,
│  │     │                   # loader-types, announcements, queue-engine, reservations,
│  │     │                   # permits, wallet, payments, notifications, reports,
│  │     │                   # tickets, audit, integrations (adapters)
│  │     ├─ common/          # guards, interceptors, filters, decorators, utils
│  │     └─ config/
│  └─ web/                   # Next.js (۳ پنل با Route Group)
│     └─ src/app/
│        ├─ (auth)/
│        ├─ (operator)/      # پنل اپراتور کارخانه
│        ├─ (carrier)/       # پنل باربری
│        └─ (driver)/        # پنل راننده (PWA)
├─ packages/
│  ├─ ui/                    # Design System (کامپوننت‌ها + توکن‌ها)
│  ├─ shared/                # Zod schemaها، تایپ‌ها، ثوابت مشترک
│  └─ config/                # ESLint, tsconfig, tailwind preset
├─ infra/
│  ├─ docker/                # Dockerfile ها
│  ├─ compose/               # docker-compose.{dev,prod}.yml
│  ├─ nginx/
│  └─ scripts/               # backup, deploy, seed
├─ tests/
│  ├─ e2e/                   # Playwright
│  ├─ load/                  # k6
│  └─ security/
└─ .github/workflows/        # ci.yml, security.yml, deploy.yml
```

مدیریت پکیج: **pnpm workspaces** + **Turborepo**. Node نسخه LTS و در `.nvmrc` قفل شود.

---

## ۳. استانداردهای کدنویسی

- **TypeScript Strict** در همه جا؛ `any` ممنوع مگر با کامنت توجیهی.
- ESLint + Prettier اجباری؛ Husky + lint-staged قبل از Commit.
- **Zod** برای اعتبارسنجی ورودی؛ Schema مشترک بین Front و Back در `packages/shared`.
- نام‌گذاری: فایل‌ها `kebab-case`، کلاس `PascalCase`، متغیر `camelCase`، جدول/ستون دیتابیس `snake_case`.
- هر ماژول Backend: `controller → service → repository`؛ منطق کسب‌وکار فقط در Service/Domain، نه Controller.
- توابع کوچک و تک‌مسئولیتی؛ فایل بیش از ~۳۰۰ خط ممنوع (تقسیم شود).
- **کامنت** برای «چرا»، نه «چه». متون UI و پیام‌های خطا فارسی؛ کد، نام متغیرها و لاگ‌ها انگلیسی.
- بدون Magic Number؛ ثوابت در `shared/constants`.
- مدیریت خطا: کلاس خطای دامنه با `code` ثابت؛ پیام فارسی برای کاربر، جزئیات فنی فقط در لاگ.

### ۳.۱ قالب پاسخ API
```json
{ "data": {}, "meta": { "page": 1, "pageSize": 50, "total": 0 } }
{ "error": { "code": "QUEUE_ALREADY_JOINED", "message": "شما قبلاً در این صف ثبت‌نام کرده‌اید", "details": {} } }
```
نسخه‌بندی: `/api/v1/...`. مستندات OpenAPI (Swagger) خودکار و همیشه به‌روز.

---

## ۴. دیتابیس

- **Migration** برای هر تغییر اسکیما؛ ویرایش دستی دیتابیس ممنوع.
- همه مبالغ **Integer (ریال)**؛ زمان‌ها `timestamptz` (UTC)؛ نمایش شمسی فقط در UI.
- هر جدول: `id (uuid v7 یا bigint)`, `tenant_id`, `created_at`, `updated_at`.
- **ایندکس** برای هر کلید خارجی و ستون فیلتر پرتکرار؛ ایندکس ترکیبی برای صف: `(tenant_id, hall_id, destination_id, status, joined_at)`.
- جداول مالی (`ledger_entries`) و `audit_logs` و `queue_events`: **Append-only** (بدون UPDATE/DELETE؛ با Trigger یا دسترسی محدود).
- Soft-delete (`deleted_at`) برای داده‌های عملیاتی.
- فیلدهای حساس (شبا، شماره حساب، کد ملی در صورت نیاز) رمزنگاری سطح ستون (AES-256-GCM با کلید در Env/Secret) و در لاگ Mask.
- **Row-level isolation:** همه Queryها از طریق لایه‌ای که `tenant_id` را اجبار می‌کند؛ برای باربری‌ها `carrier_id` هم اجباری.
- تراکنش‌ها: هر عملیات چندمرحله‌ای (تخصیص، کسر کیف پول، لغو) در یک Transaction با سطح ایزوله مناسب.

---

## ۵. موتور نوبت‌دهی – قوانین پیاده‌سازی

این مهم‌ترین بخش پروژه است.

1. **Strategy Pattern:** `QueueStrategy` Interface با متدهای `join`, `onLoaded`, `allocate`, `release`, `validate`. هر استراتژی یک کلاس.
2. **Policy داده است، نه کد:** Policy در DB، نسخه‌بندی‌شده، Snapshot روی اعلام بار.
3. **هم‌زمانی:**
   - تخصیص با `SELECT ... FOR UPDATE SKIP LOCKED` روی بار/ظرفیت.
   - قفل Redis (Redlock یا قفل ساده با TTL) برای عملیات صف هر (سالن، مقصد).
   - **Unique Constraint** روی (راننده، اعلام بار) و (بار، تخصیص فعال) برای جلوگیری از دوبار تخصیص حتی در صورت باگ.
4. **Idempotency:** هر درخواست تغییر وضعیت Header `Idempotency-Key` دارد؛ ذخیره نتیجه ۲۴ ساعت.
5. **زمان معتبر فقط سرور:** هرگز زمان کلاینت برای ترتیب استفاده نشود. زمان ثبت با دقت میلی‌ثانیه، ترتیب شکست‌ناپذیر با `sequence` یکتا.
6. **Determinism:** الگوریتم تخصیص زمانی فقط به ورودی ذخیره‌شده وابسته است (نه به `Date.now()` یا ترتیب پردازش). تست «اجرای دوباره = خروجی یکسان».
7. **Event Log:** هر تغییر صف در `queue_events` (نوع، قبل/بعد، عامل، دلیل). تخصیص قابل بازپخش (Replay).
8. **Job تخصیص:** BullMQ، با Retry ایمن و بدون اثر جانبی تکراری.
9. **بدون Overbooking:** مجموع تخصیص‌ها ≤ ظرفیت، با Constraint و تست.
10. **شبیه‌ساز (Dry-run):** هر Policy قبل از فعال‌سازی با داده نمونه قابل اجراست.
11. **تست‌ها:** Unit برای هر استراتژی، Property-based برای بی‌تغییری‌ها (ظرفیت، یکتایی)، Concurrency Test با ≥۲۰۰ درخواست موازی.

---

## ۶. احراز هویت و مجوزدهی (Security by design)

### ۶.۱ Authentication
- راننده: موبایل + OTP (۶ رقم، انقضا ۲ دقیقه، حداکثر ۵ تلاش، Hash در DB، Rate Limit به ازای موبایل و IP).
- اپراتور/باربری: نام‌کاربری + رمز قوی (Argon2id) + قفل موقت پس از تلاش ناموفق + OTP دو‌مرحله‌ای قابل الزام.
- **Access Token** کوتاه (۱۰–۱۵ دقیقه)، **Refresh Token** چرخشی با تشخیص استفاده مجدد (Reuse Detection) در Cookie `HttpOnly; Secure; SameSite=Lax/Strict`.
- یک نشست فعال برای راننده + Device Binding (BR-18)؛ خروج از همه دستگاه‌ها.
- بازیابی رمز با OTP؛ بدون افشای وجود/عدم‌وجود حساب (پیام یکسان).
- رمز پیش‌فرض ممنوع؛ Seed فقط در Dev.

### ۶.۲ Authorization
- **RBAC** + **Policy-based ABAC**: `can(user, action, resource)` در یک لایه مرکزی (Guard) — نه پراکنده در Controllerها.
- هر Endpoint باید صراحتاً نقش/مجوز داشته باشد؛ Endpoint بدون Decorator = رد (Deny by default) و تست خودکار این را بررسی کند.
- **جلوگیری IDOR:** هر Query بر اساس `tenant_id` + مالکیت (`carrier_id`/`driver_id`) فیلتر شود؛ هرگز فقط `WHERE id = ?`.
- عملیات حساس (آزادسازی بار، جابجایی دستی صف، تغییر Policy، مسدودسازی) → نیاز به نقش مناسب + Audit با دلیل.
- جدول ماتریس دسترسی در `docs/security/permission-matrix.md` نگهداری و با تست‌ها همگام شود.

### ۶.۳ امنیت برنامه (OWASP Top 10 / ASVS L2)
- اعتبارسنجی ورودی با Zod در همه Endpoint (Whitelist، رد فیلد اضافی - Mass Assignment).
- Query پارامتری/ORM؛ عدم Raw SQL مگر با Binding.
- Output Encoding در React؛ `dangerouslySetInnerHTML` ممنوع.
- هدرها: CSP سخت‌گیرانه (فقط `self`)، HSTS، X-Content-Type-Options، Referrer-Policy، Permissions-Policy، Frame-Ancestors none.
- CSRF: SameSite + Token برای عملیات تغییر وضعیت با Cookie.
- CORS: فقط دامنه‌های مجاز.
- **Rate Limiting** لایه‌ای (IP، کاربر، Endpoint حساس مثل OTP، ورود، ثبت نوبت).
- آپلود فایل: محدودیت نوع/حجم، بررسی Magic Bytes، ذخیره خارج از Web Root، نام تصادفی، عدم اجرای فایل.
- Secrets فقط در Env/Secret Manager؛ هرگز در Git. اسکن Secret در CI (gitleaks).
- لاگ بدون رمز، OTP، Token و داده کامل شبا.
- وابستگی‌ها: `pnpm audit`، Dependabot/Renovate؛ نسخه‌ها قفل (lockfile).
- SSRF: Adapterهای خروجی فقط به Allowlist.
- پرداخت: تایید سمت سرور (Verify) و Callback امضا/اعتبارسنجی‌شده؛ مبلغ همیشه از سرور.
- پیام‌های خطا اطلاعات داخلی (Stack Trace) نشان ندهند.

### ۶.۴ زیرساخت
- HTTPS اجباری (TLS 1.2+)، فقط پورت‌های 80/443 بیرونی؛ DB و Redis فقط شبکه داخلی Docker.
- کاربر غیر Root در Container، Image حداقلی، `read_only` filesystem در صورت امکان.
- SSH فقط با کلید، Fail2ban، فایروال.
- Backup رمزنگاری‌شده + تست بازیابی.

---

## ۷. فرانت‌اند و UX

- پیروی کامل از `docs/specs/UI-UX-3D-Design-System.md` (توکن‌های رنگ/سایه/فاصله در `packages/ui` به‌صورت CSS Variable + Tailwind preset).
- **RTL اول:** `dir="rtl"`، از Logical Properties (`margin-inline-start`...) استفاده شود.
- **تقویم شمسی** با کتابخانه معتبر (مثلاً `jalaali-js`/`date-fns-jalali`)؛ ورودی/خروجی API به ISO.
- ارقام: نمایش فارسی در UI، ذخیره/ارسال لاتین.
- فونت Vazirmatn **Self-host** (woff2) — بدون Google Fonts.
- **سادگی و خلوتی** (الزام صریح مالک): هر صفحه یک هدف؛ فیلدهای کم‌کاربرد در «پیشرفته» جمع‌شونده؛ فرم‌های بلند (اعلام بار) مرحله‌ای (Stepper)؛ جدول‌ها با «انتخاب ستون‌ها» و پیش‌فرض ۸–۱۰ ستون مهم.
- پنل راننده: Mobile-first، اهداف لمسی ≥ ۴۴px، Bottom Navigation، PWA (Manifest، Service Worker، Offline Shell).
- حالت‌های Loading (Skeleton)، Empty، Error برای هر لیست.
- انیمیشن فقط `transform`/`opacity`؛ احترام به `prefers-reduced-motion`.
- دسترسی‌پذیری: Label برای فیلدها، Focus Ring، کنتراست AA، ناوبری کیبورد.
- Data Fetching با TanStack Query؛ فرم‌ها با React Hook Form + Zod.
- Realtime صف: WebSocket/SSE با Reconnect؛ UI بدون وابستگی به آن (Fallback به Polling).

---

## ۸. تست و کیفیت

| نوع | ابزار | حداقل |
|---|---|---|
| Unit | Vitest/Jest | موتور نوبت‌دهی، کیف پول، RBAC: پوشش ≥ ۹۰٪؛ کل پروژه ≥ ۷۰٪ |
| Integration | Jest + Testcontainers (Postgres/Redis واقعی) | همه ماژول‌های API |
| E2E | Playwright | سناریوهای AC-1..AC-10 |
| Contract | OpenAPI Validation | تطابق Front/Back |
| Load | k6 | طبق CLAUDE.md |
| Security | ZAP، gitleaks، audit، تست‌های IDOR/AuthZ | طبق CLAUDE.md |

- **Definition of Done هر Task:** کد + تست + مستندات (در صورت نیاز) + CI سبز + به‌روزرسانی `AGENT.md` + Commit/Push.
- بدون تست، تغییر در موتور نوبت‌دهی و کیف پول پذیرفته نیست.
- Seed واقعی‌نما برای Dev: ۱۰ مقصد، ۵ باربری، ۲۰۰ راننده، چند اعلام بار.

---

## ۹. Git و CI/CD

- Branch: `main` (پایدار، محافظت‌شده)، `develop` (اختیاری)، `feat/<phase>-<name>`, `fix/...`.
- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `security:`.
- هر Commit کوچک و مستقل؛ هر Task = حداقل یک Commit؛ بعد از هر Task: **Push**.
- Tag برای نقاط بازگشت: `v0.<phase>.<n>` بعد از اتمام هر فاز (`git tag` + Push). برای Rollback آسان.
- Pull Request برای تغییرات بزرگ (ترجیحاً)؛ CI باید سبز باشد.
- **CI (GitHub Actions):** install → lint → typecheck → test → build → `pnpm audit` → gitleaks → ساخت Docker Image.
- **Deploy:** از Tag/Release؛ Migration خودکار با امکان Rollback؛ Health Check پس از استقرار.
- `.env.example` همیشه به‌روز؛ `.env` هرگز Commit نشود.

---

## ۱۰. مشاهده‌پذیری (Observability)

- لاگ JSON ساخت‌یافته با `requestId`, `userId`, `tenantId`.
- Health: `/health/live`, `/health/ready`.
- متریک (Prometheus-compatible): نرخ خطا، تأخیر، طول صف Jobها، تعداد نوبت.
- Alert برای: خطای ۵xx بالا، شکست Job تخصیص، پرداخت‌های ناموفق، شکست Backup.
- Error Tracking self-hosted (مثلاً GlitchTip/Sentry self-hosted) — نه SaaS خارجی.

---

## ۱۱. استقرار در ایران

- سرور VPS داخل ایران (Ubuntu LTS)، Docker + Compose، Nginx Reverse Proxy، Let's Encrypt یا گواهی داخلی.
- **Build در CI** و انتقال Image (یا استفاده از Registry/Mirror داخلی)؛ دسترسی سرور به npm/Docker Hub را فرض نکن.
- همه Assetها Self-host؛ هیچ درخواست Runtime به دامنه خارج از ایران (به‌جز Provider های مجاز در Allowlist).
- Backup روزانه به مقصد دوم (سرور دیگر/ذخیره‌ساز داخلی)، نگهداری ۳۰ روز.
- Runbook استقرار/بازیابی در `docs/runbooks/` بنویس و روی محیط تست امتحان کن.

---

## ۱۲. Adapterهای یکپارچه‌سازی

- هر سرویس بیرونی (پیامک، درگاه، حواله/بارنامه/رگولاتوری، استعلام کرایه) پشت Interface؛ پیاده‌سازی `Mock` و `Real` (Real بعداً).
- Feature Flag برای فعال‌سازی هر Adapter.
- الگوی **Outbox** برای ارسال بیرونی با Retry و بدون اثر تکراری.
- Timeout، Circuit Breaker و ثبت لاگ برای هر فراخوانی.

---

## ۱۳. ممنوعیت‌ها (Don'ts)

- ❌ Commit کردن Secret، رمز یا داده واقعی کاربر.
- ❌ ذخیره مبلغ به‌صورت Float.
- ❌ اتکا به زمان کلاینت برای نوبت.
- ❌ Endpoint بدون کنترل دسترسی.
- ❌ CDN/فونت/اسکریپت خارجی.
- ❌ اضافه‌کردن کتابخانه سنگین بدون ثبت ADR و توجیه.
- ❌ تغییر دستی دیتابیس بدون Migration.
- ❌ ادامه کار با تست‌های شکسته.
- ❌ فرض‌گرفتن پاسخ ابهام‌ها؛ بپرس یا در `AGENT.md` ثبت کن.
- ❌ داده واقعی (موبایل، کد ملی، شبا، پلاک، نام واقعی) در کد، تست، Seed، مستندات یا Issue؛ **فقط داده مصنوعی** (ریپو PUBLIC است؛ جزئیات: `docs/security/data-handling.md`).

---

## ۱۴. فرمت ADR (برای هر تصمیم مهم)

```
# ADR-00X: عنوان
تاریخ | وضعیت (پذیرفته/جایگزین‌شده)
زمینه: ...
تصمیم: ...
جایگزین‌های بررسی‌شده: ...
پیامدها: ...
```

---

## ۱۵. یادداشت‌های افزوده (۱۴۰۵/۰۸/۲۷)

- **نام و وضعیت ریپو:** ریشه درخت بخش ۲ در عمل `cement_barbary/` است (نام محصول BitaBar و Scope پکیج‌ها `@bitabar/*` بدون تغییر). ریپو طبق تصمیم مالک (OWN-17) تا پایان پروژه PUBLIC است؛ کاهش ریسک: Gitleaks با قوانین داده ایرانی (`.gitleaks.toml`) + قاعده داده مصنوعی. ADR-003.
- **زبان گزارش به مالک:** بند ۷ بخش ۱ («فارسی ساده») با `CLAUDE.md` (اولویت بالاتر) جایگزین شده است: گزارش‌ها به **انگلیسی ساده**.
- **Registry:** فایل `.npmrc` پروژه، رجیستری رسمی npm را تنظیم می‌کند (OD-F0a). ADR-001.
