# SariBar Neyriz – UI/UX 3D Design System
### سیستم طراحی سه‌بعدی مخصوص سامانه اعلام بار شرکت سریع بار نی ریز

> این سند به عنوان **منبع حقیقت طراحی** برای پروژه تعریف شده است.  
> تمام کامپوننت‌ها، صفحات و تعاملات باید از قوانین این فایل پیروی کنند.

---

## ۱. فلسفه طراحی

**سبک کلی:** Modern Logistics 3D Soft  
ترکیبی از:
- عمق سه‌بعدی ملایم و حرفه‌ای (نه بازی‌گونه)
- حس اعتماد، سرعت و دقت (ویژگی‌های کلیدی حوزه باربری)
- تمیز، خوانا و مناسب کار طولانی‌مدت اپراتور

**اصول کلیدی:**
1. عمق واقعی از طریق Elevation و Shadow
2. بازخورد لمسی قوی در دکمه‌ها و کارت‌ها
3. سلسله‌مراتب بصری واضح
4. کنتراست بالا برای خوانایی در محیط کاری

---

## ۲. پالت رنگی (Logistics Professional Palette)

### ۲.۱ رنگ‌های اصلی (Primary)

| نام                | Hex       | RGB              | کاربرد اصلی                              |
|--------------------|-----------|------------------|------------------------------------------|
| Primary Blue       | `#1E40AF` | 30, 64, 175      | هدر، دکمه‌های اصلی، آیتم فعال منو       |
| Primary Blue Light | `#3B82F6` | 59, 130, 246     | هاور دکمه‌ها، لینک‌ها                    |
| Primary Blue Dark  | `#1E3A8A` | 30, 58, 138      | Active state و سایه‌های دکمه‌های ۳بعدی  |

### ۲.۲ رنگ‌های ثانویه و معنایی

| نام              | Hex       | کاربرد                                      |
|------------------|-----------|---------------------------------------------|
| Success Green    | `#059669` | تایید، مجوز صادر شده، وضعیت موفق           |
| Success Light    | `#10B981` | بج‌های موفقیت، هاور تایید                   |
| Warning Orange   | `#D97706` | هشدار، بدهی، وضعیت در انتظار               |
| Danger Red       | `#DC2626` | عدم تایید، حذف، کنسل، خطا                  |
| Info Cyan        | `#0891B2` | اطلاعات، نوبت‌دهی، وضعیت خنثی              |

### ۲.۳ رنگ‌های سطحی (Surface & Background)

| نام                  | Hex       | کاربرد                              |
|----------------------|-----------|-------------------------------------|
| Background           | `#F1F5F9` | پس‌زمینه اصلی صفحه                 |
| Surface              | `#FFFFFF` | کارت‌ها، جداول، مودال‌ها            |
| Surface Elevated     | `#FFFFFF` | کارت‌های با elevation بالاتر       |
| Border Subtle        | `#E2E8F0` | خطوط جداکننده                       |
| Text Primary         | `#0F172A` | متن اصلی                            |
| Text Secondary       | `#475569` | متن فرعی و لیبل‌ها                  |
| Text Muted           | `#94A3B8` | متن غیرفعال                         |

### ۲.۴ گرادیان‌های پیشنهادی (برای هدر و کارت‌های ویژه)

```css
/* هدر اصلی */
background: linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%);

/* کارت بدهی / آمار مهم */
background: linear-gradient(135deg, #EFF6FF 0%, #DBEAFE 100%);
```

---

## ۳. سیستم عمق سه‌بعدی (Elevation System)

این مهم‌ترین بخش طراحی سه‌بعدی پروژه است.

### ۳.۱ سطوح Elevation

| سطح     | نام              | سایه پیشنهادی                                                                 | کاربرد                              |
|---------|------------------|-------------------------------------------------------------------------------|-------------------------------------|
| 0       | Base             | بدون سایه                                                                     | پس‌زمینه صفحه                       |
| 1       | Raised           | `0 1px 3px rgba(0,0,0,0.06), 0 4px 8px rgba(0,0,0,0.04)`                     | کارت‌های معمولی، ردیف جدول         |
| 2       | Floating         | `0 4px 6px rgba(0,0,0,0.07), 0 10px 20px rgba(0,0,0,0.06)`                   | کارت‌های مهم، بج‌ها                 |
| 3       | Overlay          | `0 10px 25px rgba(0,0,0,0.1), 0 20px 40px rgba(0,0,0,0.08)`                  | مودال‌ها، دراپ‌داون‌ها              |
| 4       | Modal High       | `0 20px 40px rgba(0,0,0,0.12), 0 30px 60px rgba(0,0,0,0.1)`                  | مودال‌های بزرگ (فرم اعلام بار)     |

### ۳.۲ کلاس‌های آماده CSS

```css
/* Elevation 1 */
.elevation-1 {
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06),
              0 4px 8px rgba(15, 23, 42, 0.04);
}

/* Elevation 2 */
.elevation-2 {
  box-shadow: 0 4px 6px rgba(15, 23, 42, 0.07),
              0 10px 20px rgba(15, 23, 42, 0.06);
}

/* Elevation 3 */
.elevation-3 {
  box-shadow: 0 10px 25px rgba(15, 23, 42, 0.1),
              0 20px 40px rgba(15, 23, 42, 0.08);
}

/* Elevation 4 - برای مودال‌های بزرگ */
.elevation-4 {
  box-shadow: 0 20px 40px rgba(15, 23, 42, 0.12),
              0 30px 60px rgba(15, 23, 42, 0.1);
}
```

### ۳.۳ Hover Elevation (افزایش عمق در تعامل)

```css
.card-interactive {
  transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1),
              box-shadow 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

.card-interactive:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 16px rgba(15, 23, 42, 0.08),
              0 16px 32px rgba(15, 23, 42, 0.06);
}
```

---

## ۴. دکمه‌های سه‌بعدی (3D Buttons)

### ۴.۱ دکمه اصلی دایره‌ای (استاندارد پروژه)

```css
.btn-3d-circle {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: #1E40AF;
  color: white;
  border: none;
  box-shadow: 0 4px 0 #1E3A8A,
              0 6px 12px rgba(30, 64, 175, 0.3);
  transition: all 0.15s ease;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-3d-circle:hover {
  background: #3B82F6;
  transform: translateY(-2px);
  box-shadow: 0 6px 0 #1E3A8A,
              0 10px 20px rgba(30, 64, 175, 0.35);
}

.btn-3d-circle:active {
  transform: translateY(2px);
  box-shadow: 0 2px 0 #1E3A8A,
              0 3px 8px rgba(30, 64, 175, 0.25);
}
```

### ۴.۲ دکمه مستطیلی Primary

```css
.btn-3d-primary {
  background: linear-gradient(180deg, #3B82F6 0%, #1E40AF 100%);
  color: white;
  padding: 12px 28px;
  border-radius: 12px;
  border: none;
  font-weight: 600;
  box-shadow: 0 4px 0 #1E3A8A,
              0 8px 16px rgba(30, 64, 175, 0.25);
  transition: all 0.15s ease;
}

.btn-3d-primary:active {
  transform: translateY(3px);
  box-shadow: 0 1px 0 #1E3A8A,
              0 3px 8px rgba(30, 64, 175, 0.2);
}
```

### ۴.۳ انواع دکمه‌های رنگی

| نوع          | رنگ پس‌زمینه | رنگ سایه پایین     |
|--------------|--------------|---------------------|
| Primary      | `#1E40AF`    | `#1E3A8A`           |
| Success      | `#059669`    | `#047857`           |
| Danger       | `#DC2626`    | `#B91C1C`           |
| Warning      | `#D97706`    | `#B45309`           |
| Neutral      | `#64748B`    | `#475569`           |

---

## ۵. کارت‌ها و کانتینرها

### ۵.۱ کارت استاندارد

```css
.card-3d {
  background: #FFFFFF;
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06),
              0 4px 8px rgba(15, 23, 42, 0.04);
  border: 1px solid rgba(226, 232, 240, 0.8);
  transition: all 0.25s ease;
}
```

### ۵.۲ کارت شیشه‌ای ملایم (برای آمار و بدهی)

```css
.card-glass {
  background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(12px) saturate(160%);
  border-radius: 20px;
  border: 1px solid rgba(255, 255, 255, 0.4);
  box-shadow: 0 8px 32px rgba(30, 64, 175, 0.08);
}
```

### ۵.۳ کارت بدهی (ویژه صفحه گزارش برنامه‌ها)

```css
.card-debt {
  background: linear-gradient(135deg, #ECFDF5 0%, #D1FAE5 100%);
  border-radius: 16px;
  border: 1px solid #A7F3D0;
  box-shadow: 0 4px 12px rgba(5, 150, 105, 0.12);
}
```

---

## ۶. جدول‌ها (Data Tables)

- ردیف‌ها دارای hover با elevation ملایم
- هدر جدول کمی تیره‌تر و با سایه داخلی بسیار کم
- فیلترهای ستونی با آیکون قیف و پس‌زمینه روشن
- گوشه‌های جدول `12px` تا `16px`

```css
.table-row {
  transition: background 0.2s ease, box-shadow 0.2s ease;
}

.table-row:hover {
  background: #F8FAFC;
  box-shadow: inset 3px 0 0 #1E40AF; /* خط آبی سمت راست در RTL */
}
```

---

## ۷. مودال‌ها (Dialogs)

- استفاده از Elevation 4
- انیمیشن ورود: `scale(0.92)` → `scale(1)` + `opacity`
- پس‌زمینه Overlay تیره با blur ملایم
- گوشه گرد `20px`

```css
.modal-3d {
  border-radius: 20px;
  box-shadow: 0 25px 50px rgba(15, 23, 42, 0.15),
              0 15px 30px rgba(15, 23, 42, 0.1);
  transform-origin: center;
  animation: modalEnter 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}

@keyframes modalEnter {
  from {
    opacity: 0;
    transform: scale(0.92) translateY(10px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}
```

---

## ۸. تایپوگرافی

| عنصر              | اندازه     | وزن     | رنگ          |
|-------------------|------------|---------|--------------|
| عنوان صفحه        | 24px       | 700     | `#0F172A`    |
| عنوان بخش         | 18px       | 600     | `#1E40AF`    |
| عنوان کارت        | 16px       | 600     | `#0F172A`    |
| متن اصلی          | 14px       | 400     | `#334155`    |
| لیبل فیلد         | 13px       | 500     | `#475569`    |
| متن کمکی          | 12px       | 400     | `#94A3B8`    |

**فونت پیشنهادی:** Vazirmatn یا IRANSansX (وزن‌های 400, 500, 600, 700)

---

## ۹. فاصله‌گذاری (Spacing Scale)

استفاده از مقیاس ۸تایی:

```
4px, 8px, 12px, 16px, 20px, 24px, 32px, 40px, 48px, 64px
```

- فاصله بین کارت‌ها: `24px`
- پدینگ داخلی کارت: `20px` تا `24px`
- فاصله بین فیلدهای فرم: `16px` تا `20px`

---

## ۱۰. آیکون‌ها و بازخورد بصری

- آیکون‌ها ترجیحاً از خانواده Lucide یا Heroicons
- اندازه استاندارد دکمه‌های دایره‌ای: `20px` تا `22px`
- در دکمه‌های ۳بعدی، آیکون باید دقیقاً در مرکز باشد
- وضعیت‌ها با بج رنگی + آیکون کوچک نمایش داده شوند

---

## ۱۱. حالت‌های تعاملی (States)

| حالت     | رفتار                                      |
|----------|--------------------------------------------|
| Default  | Elevation پایه                             |
| Hover    | افزایش elevation + کمی translateY منفی     |
| Active   | کاهش elevation + translateY مثبت (فشردن)   |
| Focus    | حلقه فوکوس آبی با offset                   |
| Disabled | کاهش opacity به 0.5 + حذف سایه             |
| Loading  | اسکلتون با shimmer یا اسپینر داخل دکمه     |

---

## ۱۲. حالت تاریک (اختیاری – فاز ۲)

در صورت نیاز به Dark Mode:

- Background: `#0F172A`
- Surface: `#1E293B`
- Primary ثابت بماند
- سایه‌ها باید روشن‌تر و ملایم‌تر شوند (چون در پس‌زمینه تیره سایه تیره دیده نمی‌شود)

---

## ۱۳. خلاصه قوانین طلایی طراحی این پروژه

1. **همیشه عمق داشته باش** — هیچ کارتی نباید فلت مطلق باشد.
2. **بازخورد لمسی بده** — دکمه‌ها باید حس فشردن واقعی بدهند.
3. **آبی لجستیک را حفظ کن** — رنگ Primary هویت برند است.
4. **سایه نرم، نه تیز** — از سایه‌های پخش‌شده استفاده کن.
5. **RTL را جدی بگیر** — تمام سایه‌ها و خطوط تاکیدی باید با جهت راست‌چین هماهنگ باشند.
6. **عملکرد مهم است** — فقط از `transform` و `opacity` برای انیمیشن استفاده کن.

---

**پایان سند سیستم طراحی UI/UX سه‌بعدی**

این فایل را می‌توانید مستقیماً در کنار `SariBar-Neyriz-System-Specification.md` به Claude Code بدهید تا هم ساختار پروژه و هم ظاهر آن را یکپارچه پیاده‌سازی کند.