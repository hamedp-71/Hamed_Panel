# 📜 تغییرات نسخه‌ها · Changelog

تمام تغییرات مهم این پروژه در این فایل مستند می‌شود.

قالب بر اساس [Keep a Changelog](https://keepachangelog.com/fa/1.1.0/) و
[Semantic Versioning](https://semver.org/lang/fa/) است.

---

## [1.0.5] — Silent Edition — 2026-02-01

### 🎉 افزوده شد (Added)

- **Workflows Engine** — اتوماسیون شرطی با Trigger و Action
  - ۷ نوع Trigger: `user.created`, `user.disabled`, `user.expired`, `user.traffic80`, `user.traffic95`, `usage.dailyGB`, `cron.custom`
  - ۷ نوع Action: `send.telegram`, `user.pause`, `user.resume`, `user.extend`, `user.resetUsage`, `webhook.trigger`, `user.addTag`
  - تاریخچه ۱۰۰ رکورد اجرا
- **Smart Suggestions** — موتور پیشنهاد هوشمند بر اساس وضعیت پنل
- **Predictive Analytics** — پیش‌بینی مصرف ۷ روزه بر اساس روند تاریخی
- **Network Weather** — نمایش وضعیت کلی (Sunny/Cloudy/Rainy/Storm) با ایموجی
- **Anomaly Detection** — تشخیص خودکار مصرف غیرعادی (۵× انحراف از میانگین)
- **DPI Detection** — تشخیص خودکار شدت DPI بر اساس ASN و Country
- **Multi-Upstream** — پشتیبانی از زنجیره‌سازی سرورهای VLESS
- **DNS Pool** — استخر DNS وزن‌دار با ۵ استراتژی
- **Speed Test** — تست سرعت به چند Host همزمان
- **Latency Map** — نقشه بصری تاخیر مناطق
- **CF Usage Alert** — هشدار مصرف Cloudflare در ۸۰٪
- **Auto Failover** — جایگزینی خودکار نود در صورت خرابی

### 🔧 بهبود یافت (Improved)

- بهینه‌سازی مصرف حافظه تا **۴۰٪ کاهش**
- کاهش Cold Start به **~۵ms**
- بهبود سرعت Query در D1 با ایندکس‌های جدید
- بهبود UI پنل با نمودارهای Chart.js
- بهبود سیستم Polling (هر ۱۵ ثانیه)
- بهبود Command Palette (Ctrl+K)

### 🐛 رفع اشکال (Fixed)

- رفع مشکل Session در حالت Multi-Tab
- رفع مشکل ایجاد کاربر با نام تکراری
- رفع مشکل نمایش تاریخ در مرورگر Safari
- رفع مشکل CORS در Subscription Endpoint

### 🔒 امنیت (Security)

- افزودن Rate Limit سخت‌گیرانه روی Auth
- افزودن Captcha برای ورود
- رمزنگاری AES-GCM فیلدهای حساس در D1
- بهبود HMAC-SHA256 برای Webhooks

### ⚠️ تغییرات ناسازگار (Breaking Changes)

- مسیر `/sync` به `/sub` تغییر یافت (Migration خودکار انجام می‌شود)
- ساختار مدیران از String به Array تغییر کرد

---

## [1.0.0] — Initial Release — 2025-12-15

### 🎉 انتشار اولیه

- نسخه اول با پشتیبانی از V2Ray/Xray
- پنل مدیریت کاربران
- تولید خودکار کانفیگ برای ۶ کلاینت
- پشتیبانی از Telegram Bot
- سیستم Backup روی R2
- مدیریت Clean IP
- History Tracking (۳۰ روز)