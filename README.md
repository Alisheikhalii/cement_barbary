# BitaBar – سامانه اعلام بار و نوبت‌دهی

سامانه مستقل اعلام بار و نوبت‌دهی رانندگان برای کارخانه سیمان، با سه پنل: **راننده** (PWA موبایل)، **باربری** و **اپراتور کارخانه**.

## اسناد

| سند | محتوا |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | فرآیند کار |
| [`AGENT.md`](AGENT.md) | وضعیت فعلی و حافظه پروژه |
| [`docs/PRD.md`](docs/PRD.md) | محصول و قوانین کسب‌وکار |
| [`docs/GUIDELINES.md`](docs/GUIDELINES.md) | استانداردهای فنی |
| [`docs/specs/`](docs/specs) | مشخصات اولیه و طرح‌های ظاهری |
| [`docs/adr/`](docs/adr) | تصمیمات معماری |

## پیش‌نیازها

- Node.js نسخه ۲۴ (LTS) — نسخه در `.nvmrc`
- pnpm نسخه ۱۱ (`corepack enable`)
- Docker (از فازهای بعد)

## دستورها

```bash
pnpm install        # نصب وابستگی‌ها + فعال‌سازی Git hooks
pnpm lint           # بررسی کیفیت کد
pnpm typecheck      # بررسی نوع‌ها (TypeScript)
pnpm test           # اجرای تست‌ها
pnpm build          # ساخت
pnpm format         # مرتب‌سازی خودکار کد
```

## ساختار

```
apps/api        بک‌اند (NestJS)
apps/web        فرانت‌اند ۳ پنل (Next.js)
packages/ui     Design System
packages/shared Schemaها، تایپ‌ها و ثوابت مشترک
packages/config تنظیمات مشترک ESLint/TypeScript/Prettier
infra/          Docker، Compose، Nginx، اسکریپت‌ها
tests/          E2E، تست بار، تست امنیت
```
