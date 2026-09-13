# 🔒 امنیت · Security Best Practices

راهنمای امنیتی کامل برای استقرار امن Hamed Panel.

---

## 🔐 رمزنگاری

### فیلدهای رمزنگاری‌شده

پنل به‌طور خودکار این فیلدها را با **AES-GCM (256-bit)** رمز می‌کند:

| فیلد | محل |
|-------|-----|
| `cfApiToken` | تنظیمات Cloudflare |
| `tgToken` | تنظیمات تلگرام |
| `syncApiKey` | همگام‌سازی با Slave |

کلید رمزنگاری از **Master Key** پنل مشتق می‌شود (PBKDF2 با ۵۰٬۰۰۰ تکرار).

---

## 🛡️ احراز هویت

### Session Management

- **TTL**: ۲۴ ساعت
- **Storage**: KV (توصیه‌شده) یا D1
- **Token Format**: `sess_<32bytes-hex>`
- **Revocation**: فوری

### Rate Limiting

- **Login**: ۵ تلاش در ۵ دقیقه
- **Auto-Ban**: پس از ۳۰ تلاش ناموفق، IP برای ۱ ساعت مسدود می‌شود
- **Reset**: خودکار پس از ۵ دقیقه

---

## 🚫 محافظت در برابر حملات

### DDoS Protection

Cloudflare به‌طور خودکار محافظت DDoS را فراهم می‌کند.

### Rate Limit

```javascript
// در Worker
async function checkRateLimit(env, ip, action, maxAttempts, windowMs) {
  // ...
}
```

### IP Ban

- **Auto-Ban** پس از تلاش‌های مکرر Auth
- **Manual Ban** از پنل → IPهای بسته

---

## 🔑 مدیریت رمز عبور

### قوانین

- **حداقل ۴ کاراکتر**
- **توصیه‌شده**: ۱۲+ کاراکتر با اعداد و نمادها

### تغییر رمز

1. **پنل → مدیران**
2. روی ✏️ کنار مدیر
3. رمز جدید
4. **ذخیره**

### Hash Algorithm

- **SHA-256** با Salt اختصاصی هر مدیر
- Salt: ۱۶ بایت تصادفی

---

## 🌐 امنیت شبکه

### HTTPS

تمام ارتباطات از طریق HTTPS (TLS 1.3) انجام می‌شود.

### CORS

- **API Endpoints**: `Access-Control-Allow-Origin: *`
- **Cookie**: HttpOnly (در صورت استفاده)

### Content Security Policy

برای جلوگیری از XSS، از CSP توصیه‌شده استفاده کنید:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com
```

---

## 🔍 Zero Log Principle

پنل هیچ‌گاه:
- ❌ به سرویس ثالث درخواست نمی‌فرستد (مگر فعال کرده باشید)
- ❌ Telemetry به توسعه‌دهنده ارسال نمی‌کند
- ❌ IP کاربران را در جایی غیر از D1 خودتان ذخیره نمی‌کند
- ❌ Session را به اشتراک نمی‌گذارد

---

## 🎯 چک‌لیست امنیتی

پس از نصب:

- [ ] رمز `admin` را تغییر دهید
- [ ] Master Key را به یک مقدار قوی تغییر دهید
- [ ] Auto-Ban را فعال کنید
- [ ] Rate Limit را تنظیم کنید
- [ ] HTTPS را تأیید کنید
- [ ] Backup رمزنگاری‌شده فعال کنید
- [ ] دامنه اختصاصی تنظیم کنید
- [ ] Webhookها را با Secret محافظت کنید
- [ ] IP Allowlist برای پنل تنظیم کنید (اختیاری)

---

## 🚨 در صورت نفوذ

اگر مشکوک به نفوذ هستید:

1. **فوری** Master Key را تغییر دهید
2. تمام Sessions را Revoke کنید (پنل → نشست‌ها → قطع همه)
3. تمام API Keys را حذف کنید
4. تمام مدیران را چک کنید
5. لاگ‌ها را بررسی کنید
6. Issue در [GitHub](https://github.com/hamedp-71/Hamed_Panel/issues) باز کنید

---

## 📞 گزارش آسیب‌پذیری

به [SECURITY.md](../SECURITY.md) مراجعه کنید.

---

## 🏆 تقدیر

از تمام محققان امنیت که در بهبود این پروژه کمک می‌کنند، سپاسگزاریم.

---

## 📞 پشتیبانی

- 📱 [@the_saz](https://t.me/the_saz)

---
