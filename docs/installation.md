# 🚀 راهنمای نصب و استقرار · Installation Guide

راهنمای گام‌به‌گام نصب **Hamed Panel v1.0.5** روی **Cloudflare Workers**.

> ⏱️ **زمان تقریبی**: ۵ تا ۱۰ دقیقه
> 💰 **هزینه**: رایگان (پلن Free Cloudflare)

---

## 📋 پیش‌نیازها

- حساب [Cloudflare](https://dash.cloudflare.com/sign-up) (رایگان)
- [Node.js](https://nodejs.org/) نسخه ۱۸ یا بالاتر
- [Git](https://git-scm.com/)
- یک حساب [GitHub](https://github.com) (اختیاری)

---

## مرحله ۱ — نصب Node.js و Wrangler

### ویندوز / مک / لینوکس

```bash
# بررسی نسخه Node
node --version  # باید >= 18 باشد

# نصب Wrangler به‌صورت Global
npm install -g wrangler

# بررسی نصب
wrangler --version
```

---

## مرحله ۲ — کلون پروژه

```bash
git clone https://github.com/hamedp-71/Hamed_Panel.git
cd Hamed_Panel
```

---

## مرحله ۳ — ورود به Cloudflare

```bash
wrangler login
```

مرورگر باز می‌شود → اجازه دسترسی بدهید → تأیید کنید.

---

## مرحله ۴ — ساخت D1 Database

```bash
wrangler d1 create hamed-panel-db
```

خروجی چیزی شبیه این خواهد بود:

```
✅ Successfully created DB 'hamed-panel-db'

[[d1_databases]]
binding = "IOT_DB"
database_name = "hamed-panel-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**مقدار `database_id` را کپی کنید.**

---

## مرحله ۵ — ویرایش `wrangler.toml`

فایل `wrangler.toml` را باز کنید و `PASTE_YOUR_DATABASE_ID_HERE` را با مقدار کپی‌شده جایگزین کنید:

```toml
[[d1_databases]]
binding = "IOT_DB"
database_name = "hamed-panel-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### (اختیاری) افزودن KV برای Session سریع‌تر

```bash
wrangler kv:namespace create SESSIONS_KV
```

و در `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SESSIONS_KV"
id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### (اختیاری) افزودن R2 برای پشتیبان‌گیری

```bash
wrangler r2 bucket create hamed-panel-backups
```

و در `wrangler.toml`:

```toml
[[r2_buckets]]
binding = "BACKUP_BUCKET"
bucket_name = "hamed-panel-backups"
```

---

## مرحله ۶ — استقرار

```bash
wrangler deploy
```

پس از چند ثانیه، آدرس Worker شما نمایش داده می‌شود:

```
✨ Uploaded hamed-panel
   https://hamed-panel.<your-subdomain>.workers.dev
```

---

## مرحله ۷ — ورود به پنل

آدرس پنل:

```
https://hamed-panel.<your-subdomain>.workers.dev/panel
```

**اطلاعات ورود پیش‌فرض:**

| فیلد | مقدار |
|------|-------|
| Username | `admin` |
| Password | `admin` |

> ⚠️ **هشدار امنیتی**: بلافاصله پس از ورود، رمز عبور را از بخش **تنظیمات** → **مدیران** تغییر دهید.

---

## مرحله ۸ — افزودن دامنه اختصاصی (اختیاری)

1. وارد [Cloudflare Dashboard](https://dash.cloudflare.com) شوید
2. **Workers & Pages** → پروژه خود → **Settings** → **Triggers**
3. **Custom Domains** → **Add Custom Domain**
4. دامنه خود را وارد کنید
5. ثبت DNS به‌صورت خودکار انجام می‌شود

---

## 🔧 عیب‌یابی

### خطای `database_id not found`

```bash
wrangler d1 list
```

اگر دیتابیس وجود دارد اما مقدار ندارد، از خروجی بالا مقدار را در `wrangler.toml` قرار دهید.

### خطای `Worker exceeded CPU limit`

در `wrangler.toml` این خط را اضافه کنید:

```toml
[limits]
cpu_ms = 50
```

### خطای `compatibility_date`

مطمئن شوید `compatibility_date` در `wrangler.toml` حداقل `2024-03-01` باشد.

### پنل باز نمی‌شود

- بررسی کنید که پنل با `/panel` باز شده باشد
- Ctrl+Shift+R (Hard Reload) کنید
- Cache مرورگر را پاک کنید

---

## 📊 تأیید نصب

پس از ورود، باید ببینید:
- ✅ داشبورد با ۸ کارت آماری
- ✅ منوی کناری با ۲۶ بخش
- ✅ نمودارهای Chart.js

---

## 🔄 به‌روزرسانی

```bash
git pull origin main
wrangler deploy
```

---

## 🗑️ حذف کامل

```bash
wrangler delete
wrangler d1 delete hamed-panel-db
wrangler kv:namespace delete --binding=SESSIONS_KV
wrangler r2 bucket delete hamed-panel-backups
```

---

## 📞 پشتیبانی

- 📱 تلگرام: [@the_saz](https://t.me/the_saz)
- 🌐 وب‌سایت: [zaya.io/thesaz](https://zaya.io/thesaz)
- 🐛 Issues: [GitHub Issues](https://github.com/hamedp-71/Hamed_Panel/issues)
