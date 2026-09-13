# 📚 مستندات Hamed Panel

به مرکز مستندات **Hamed Panel v1.0.5** خوش آمدید.

---

## 📖 فهرست مستندات

| سند | توضیح |
|-----|-------|
| [🚀 نصب و راه‌اندازی](installation.md) | راهنمای گام‌به‌گام استقرار روی Cloudflare Workers |
| [🌐 استقرار روی GitHub Pages](deployment.md) | میزبانی مستندات و صفحه فرود |
| [⚙️ پیکربندی پیشرفته](configuration.md) | تنظیمات، Workflows، Cron، Webhooks، DNS Pool |
| [📡 API Reference](api-reference.md) | تمام endpointها با مثال |
| [🔒 امنیت](security.md) | بهترین شیوه‌های امنیتی |
| [❓ پرسش‌های متداول](faq.md) | پاسخ به سؤالات پرتکرار |

---

## 🎯 شروع سریع

اگر می‌خواهید در ۵ دقیقه شروع کنید:

```bash
git clone https://github.com/THE-SAZ/saz-hamed-panel.git
cd saz-hamed-panel
npm install -g wrangler
wrangler login
wrangler d1 create hamed-panel-db
# ویرایش wrangler.toml → database_id
wrangler deploy
