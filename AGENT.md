# AGENT.md – حافظه پروژه (همیشه به‌روز)

## ۱. وضعیت فعلی
- فاز فعلی: F0 (قدم صفر) | آخرین Tag: — | آخرین Commit: (بعد از Push به‌روز می‌شود)
- CI: — | تاریخ آخرین به‌روزرسانی: ۱۴۰۵/۰۸/۲۵
- ریپو: `github.com/Alisheikhalii/cement_barbary` (شاخه `main`)

## ۲. نقشه پروژه (فقط خلاصه)
- Monorepo با pnpm workspaces + Turborepo (ساختار GUIDELINES §۲).
- `packages/config`: tsconfig پایه (strict)، ESLint flat config، Prettier — همه پکیج‌ها از این ارث می‌برند.
- `packages/shared`: ثوابت/تایپ/Schemaهای مشترک Front و Back (فعلاً فقط `constants`).
- `packages/ui`، `apps/api`، `apps/web`: فعلاً فقط اسکلت پوشه (کد ندارند).
- مدل داده: هنوز وجود ندارد.
- Endpointها: هنوز وجود ندارد.
- فایل‌های طراحی ظاهری: `docs/specs/{carrier,operator,driver}-panel.html` — فقط در فاز UI خوانده شوند؛ PNGها در deny هستند.

## ۳. تصمیمات مهم (ADR خلاصه + لینک)
- قوانین deny خواندن در `.claude/settings.json`. چون deny بر allow غلبه دارد، به‌جای `.env.*` الگوهای مشخص (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`) گذاشته شد تا `.env.example` قابل‌خواندن بماند.
- `.gitattributes` با `eol=lf`: توسعه روی ویندوز، CI و سرور لینوکس.

## ۴. انجام‌شده (Changelog)  ← جدیدترین بالا
- [۱۴۰۵/۰۸/۲۵ | cb3ac5e | F0/قدم صفر] ساختار درختی Monorepo، README، `.nvmrc`(24)، `.editorconfig`، `.gitattributes`، `.env.example`، `.gitignore` کامل.

## ۵. در حال انجام / بعدی
- قدم صفر: AGENT.md + deny list → ابزارهای کیفیت → CI → Private کردن ریپو + محافظت سبک main → Tag `v0.0.0`.

## ۶. پرسش‌های باز و فرض‌ها (برای مالک)
- (تصمیم مالک) ریپو Private شود؛ محافظت سبک روی main (فقط منع Force Push و حذف).

## ۷. بدهی فنی و ریسک‌های شناخته‌شده
- Docker Desktop روی سیستم توسعه اجرا نیست؛ برای ادامه F0 (Docker Compose) لازم است.

## ۸. دستورهای مهم (اجرا، تست، Migration، Seed، Deploy)
- `pnpm install` | `pnpm lint` | `pnpm typecheck` | `pnpm test` | `pnpm build` | `pnpm format`

## ۹. وضعیت امنیت و بنچمارک (آخرین نتیجه + لینک گزارش)
- هنوز اجرا نشده (فاز F7).
