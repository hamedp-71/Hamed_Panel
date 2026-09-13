# 🌐 استقرار روی GitHub Pages · Deployment Guide

این سند آموزش می‌دهد چگونه **مستندات** و **صفحه فرود** Hamed Panel را روی **GitHub Pages** میزبانی کنید (کاملاً رایگان).

> ⚠️ **توجه**: خود **Worker** را نمی‌توان روی GitHub Pages اجرا کرد (چون نیاز به V8 Isolate و D1 دارد). فقط **مستندات** و **صفحه فرود** روی Pages قرار می‌گیرند. Worker را باید روی **Cloudflare Workers** مستقر کنید.

---

## 🎯 هدف

پس از این آموزش، شما خواهید داشت:

- ✅ `https://<username>.github.io/Hamed_Panel/` — صفحه فرود
- ✅ `https://<username>.github.io/Hamed_Panel/docs/` — مستندات
- ✅ Deploy خودکار با هر `git push`

---

## 📋 پیش‌نیازها

- حساب GitHub
- پروژه Fork یا Clone شده
- دسترسی به Settings ریپازیتوری

---

## 🚀 روش ۱ — استقرار سریع (توصیه‌شده)

### مرحله ۱ — Fork ریپازیتوری

روی دکمه **Fork** در بالای صفحه گیت‌هاب کلیک کنید.

### مرحله ۲ — فعال‌سازی GitHub Pages

1. به ریپازیتوری Fork شده بروید
2. **Settings** → **Pages** (در منوی چپ)
3. در بخش **Source**، گزینه **GitHub Actions** را انتخاب کنید
4. در بخش **Branch**، مقدار `main` را انتخاب کنید
5. روی **Save** کلیک کنید

### مرحله ۳ — اجرای Workflow

فایل `.github/workflows/pages.yml` به‌صورت خودکار اجرا می‌شود. برای اجرای دستی:

1. به تب **Actions** بروید
2. **Deploy to GitHub Pages** را انتخاب کنید
3. روی **Run workflow** کلیک کنید
4. شاخه `main` را انتخاب کنید و تأیید کنید

### مرحله ۴ — مشاهده سایت

پس از ۱-۲ دقیقه:

```
https://<your-username>.github.io/Hamed_Panel/
```

---

## 🚀 روش ۲ — استقرار با دامنه اختصاصی

### مرحله ۱ — تنظیم CNAME

یک فایل `CNAME` در ریشه پروژه بسازید:

```
panel.yourdomain.com
```

### مرحله ۲ — تنظیمات DNS

در پنل DNS دامنه خود، رکورد زیر را اضافه کنید:

| Type | Name | Value |
|------|------|-------|
| CNAME | panel | `<username>.github.io` |

### مرحله ۳ — فعال‌سازی HTTPS

1. **Settings** → **Pages**
2. گزینه **Enforce HTTPS** را فعال کنید
3. صبر کنید تا SSL صادر شود (تا ۲۴ ساعت)

---

## 🔄 Deploy خودکار

فایل `.github/workflows/pages.yml` هر بار که به `main` پوش می‌کنید، به‌صورت خودکار مستندات را به‌روزرسانی می‌کند.

### ساختار Workflow

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: .
```

---

## 📁 ساختار فایل‌ها برای Pages

```
/
├── index.html              ← صفحه فرود
├── assets/                 ← لوگو، بنر
│   ├── logo.svg
│   ├── banner.svg
│   └── favicon.svg
├── docs/                   ← مستندات
│   ├── index.html
│   ├── installation.html
│   └── ...
└── .github/workflows/
    └── pages.yml
```

---

## 🎨 صفحه فرود

فایل `index.html` را می‌توانید به هر شکلی که خواستید بازنویسی کنید. این فایل به‌طور خودکار در ریشه سایت قرار می‌گیرد و در آدرس اصلی نمایش داده می‌شود.

---

## ✅ بررسی سلامت

پس از استقرار، این موارد را بررسی کنید:

- [ ] صفحه اصلی بارگذاری می‌شود
- [ ] CSS و JS به‌درستی لود می‌شوند
- [ ] لینک‌های مستندات کار می‌کنند
- [ ] HTTPS فعال است
- [ ] موبایل ریسپانسیو است

---

## 🔧 عیب‌یابی

### خطای 404 بعد از Deploy

- مطمئن شوید در **Settings → Pages** گزینه `GitHub Actions` انتخاب شده
- بررسی کنید که `index.html` در ریشه باشد
- Cache مرورگر را پاک کنید

### خطای Workflow

- به تب **Actions** بروید و لاگ را بررسی کنید
- مطمئن شوید `permissions` به‌درستی تنظیم شده

### دامنه اختصاصی کار نمی‌کند

- DNS را با `dig` یا [dnschecker.org](https://dnschecker.org) بررسی کنید
- حداقل ۲۴ ساعت صبر کنید

---

## 📞 پشتیبانی

- 📱 [@the_saz](https://t.me/the_saz)
- 🌐 [zaya.io/thesaz](https://zaya.io/thesaz)
