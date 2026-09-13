
# ⚙️ پیکربندی پیشرفته · Advanced Configuration

راهنمای کامل تمام تنظیمات Hamed Panel.

---

## 📋 فهرست

- [تنظیمات عمومی](#-تنظیمات-عمومی)
- [مدیران و دسترسی‌ها](#-مدیران-و-دسترسیها)
- [کاربران](#-کاربران)
- [گروه‌ها](#-گروهها)
- [Workflows](#-workflows)
- [Cron Jobs](#-cron-jobs)
- [Webhooks](#-webhooks)
- [DNS Pool](#-dns-pool)
- [Clean IP Regions](#-clean-ip-regions)
- [ISP Templates](#-isp-templates)
- [Telegram Bot](#-telegram-bot)
- [Cloudflare API](#-cloudflare-api)

---

## 🌐 تنظیمات عمومی

مسیر: **پنل → تنظیمات**

| فیلد | توضیح |
|-------|-------|
| **نام پنل** | نام نمایشی در UI و Subscription |
| **مسیر API** | پیش‌فرض `sub` — قابل تغییر برای مخفی‌سازی |
| **کلید اصلی** | Master Key برای دسترسی روت |
| **پروتکل** | `alpha` (VLESS)، `beta` (Trojan)، `both` |
| **پورت‌ها** | پورت‌های خروجی (جدا با کاما): `443,8443,2053` |
| **DNS** | DNS سفارشی برای Resolve اولیه |
| **سایت استتار** | سایت نمایشی در حالت Maintenance |
| **آی‌پی تمیز** | لیست Clean IP دستی (هر خط یک IP) |

---

## 👤 مدیران و دسترسی‌ها

مسیر: **پنل → مدیران**

### ۱۴ دسترسی موجود

| Permission | توضیح |
|------------|-------|
| `users` | مدیریت کاربران |
| `settings` | تنظیمات اصلی |
| `advanced` | تنظیمات پیشرفته |
| `managers` | مدیریت مدیران |
| `apikeys` | مدیریت API Keys |
| `logs` | مشاهده لاگ‌ها |
| `stats` | آمار و تحلیل |
| `subscriptions` | لینک‌های اشتراک |
| `nodes` | مدیریت نودها |
| `backup` | پشتیبان‌گیری |
| `groups` | مدیریت گروه‌ها |
| `cron` | مدیریت Cron |
| `webhooks` | مدیریت Webhooks |
| `regions` | مدیریت مناطق IP |

### ساخت مدیر جدید

1. **مدیران** → **+ مدیر**
2. نام کاربری (حداقل ۳ کاراکتر)
3. رمز عبور (حداقل ۴ کاراکتر)
4. انتخاب دسترسی‌ها با کلیک روی chips
5. **ذخیره**

---

## 👥 کاربران

مسیر: **پنل → کاربران**

### فیلدهای کاربر

| فیلد | توضیح | مثال |
|-------|-------|------|
| نام | نام نمایشی | `Ali_01` |
| گروه | گروه کاربر | `vip` |
| اپراتور | ISP | `mci` |
| ترافیک | محدودیت کل (GB) | `50` |
| روزانه | محدودیت روزانه (GB) | `5` |
| اعتبار | روز | `30` |
| حداکثر کانفیگ | محدودیت تعداد | `3` |
| پهنای باند | Kbps | `1024` |
| بازنشانی | چرخه | `daily`, `weekly`, `monthly` |

### وضعیت‌های کاربر

- 🟢 **active** — فعال
- ⏸️ **paused** — متوقف دستی
- 🔴 **expired** — منقضی
- 🚫 **auto-disabled** — غیرفعال خودکار

---

## 📁 گروه‌ها

مسیر: **پنل → گروه‌ها**

گروه‌ها الگوی پیش‌فرض برای ساخت کاربران هستند.

### گروه‌های پیش‌فرض

| نام | ترافیک | اعتبار | حداکثر کانفیگ |
|-----|--------|---------|---------------|
| default | ∞ | ∞ | ∞ |
| VIP | 100 GB | 30 روز | 5 |
| test | 5 GB | 3 روز | 2 |

---

## 🔄 Workflows

مسیر: **پنل → Workflows**

### Triggerهای موجود

| Trigger | زمان فعال‌سازی |
|---------|-----------------|
| `user.created` | کاربر جدید ساخته شد |
| `user.disabled` | کاربر غیرفعال شد |
| `user.expired` | کاربر منقضی شد |
| `user.traffic80` | کاربر به ۸۰٪ ترافیک رسید |
| `user.traffic95` | کاربر به ۹۵٪ ترافیک رسید |
| `usage.dailyGB` | مصرف روزانه از X GB گذشت |
| `cron.custom` | تسک زمان‌بندی‌شده |

### Actionهای موجود

| Action | پارامتر |
|--------|---------|
| `send.telegram` | `message` |
| `user.pause` | — |
| `user.resume` | — |
| `user.extend` | `days` |
| `user.resetUsage` | — |
| `webhook.trigger` | `event` |
| `user.addTag` | `tag` |

### مثال: اطلاع‌رسانی ۸۰٪ ترافیک

```json
{
  "name": "Traffic Alert 80%",
  "trigger": "user.traffic80",
  "actions": [
    {
      "type": "send.telegram",
      "params": {
        "message": "⚠️ کاربر {name} به ۸۰٪ ترافیک رسید!"
      }
    }
  ]
}
```

---

## ⏰ Cron Jobs

مسیر: **پنل → Cron Jobs**

### تسک‌های موجود

| Action | پارامترها |
|--------|-----------|
| `reset-user-usage` | `userId` |
| `extend-user-expiry` | `userId`, `days` |
| `send-telegram` | `message` |
| `clean-ip-test` | — |
| `node-health-check` | — |
| `auto-backup` | `encrypt` |
| `purge-history` | `keepDays` |
| `broadcast` | `message` |

### مثال: بازنشانی روزانه

```json
{
  "name": "Daily Reset",
  "jobAction": "reset-user-usage",
  "params": { "userId": "u_xxxxx" },
  "intervalMinutes": 1440,
  "enabled": true
}
```

---

## 🔔 Webhooks

مسیر: **پنل → Webhooks**

### رویدادهای موجود

- `user.created`, `user.updated`, `user.deleted`, `user.disabled`
- `panel.updated`
- `anomaly.detected`
- `crisis.sent`
- `auth.success`, `auth.failed`
- `workflow.triggered`

### فرمت Payload

```json
{
  "event": "user.created",
  "timestamp": 1767225600000,
  "version": "1.0.5",
  "data": {
    "userId": "u_xxxxx",
    "name": "Ali",
    "groupId": "vip"
  }
}
```

### Headerها

```
X-Hamed-Event: user.created
X-Hamed-Signature: sha256=<hmac>
Content-Type: application/json
User-Agent: HamedPanel/1.0.5
```

### اعتبارسنجی امضا (Node.js)

```javascript
const crypto = require("crypto");

function verify(secret, body, signature) {
  const hmac = crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");
  return `sha256=${hmac}` === signature;
}
```

---

## 🌐 DNS Pool

مسیر: **پنل → DNS Pool**

### استراتژی‌ها

- `weighted` — وزنی (پیش‌فرض)
- `random` — تصادفی

### DNSهای پیش‌فرض

| سرویس | URL | وزن |
|--------|-----|------|
| Cloudflare | `https://cloudflare-dns.com/dns-query` | 100 |
| Google | `https://dns.google/dns-query` | 100 |
| Quad9 | `https://dns.quad9.net/dns-query` | 50 |
| Shecan | `https://doh.shecan.ir/dns-query` | 80 |
| AdGuard | `https://dns.adguard-dns.com/dns-query` | 50 |

---

## 🌍 Clean IP Regions

مسیر: **پنل → مناطق IP**

### مناطق پیش‌فرض

| کد | نام | تعداد IP |
|----|-----|-----------|
| de | آلمان 🇩🇪 | 16 |
| ae | امارات 🇦🇪 | 9 |
| us | آمریکا 🇺🇸 | 14 |
| sg | سنگاپور 🇸🇬 | 7 |
| fr | فرانسه 🇫🇷 | 4 |
| nl | هلند 🇳🇱 | 4 |
| uk | انگلستان 🇬🇧 | 4 |
| tr | ترکیه 🇹🇷 | 4 |
| in | هند 🇮🇳 | 4 |

### حالت‌های توزیع

- `round-robin` — چرخشی
- `random` — تصادفی

---

## 📱 ISP Templates

مسیر: **پنل → قالب اپراتور**

| اپراتور | Fragment | Ports | Agent |
|---------|----------|-------|-------|
| MCI | `1-3-1-2` | 443 | chrome |
| Irancell | `1-3-1-2` | 443 | chrome |
| Rightel | `1-1-1-1` | 443 | chrome |
| Mokhaberat | `1-2-1-1` | 443 | chrome |
| Default | — | 443 | chrome |

### NAT64 Prefixها

| اپراتور | Prefix |
|---------|--------|
| MCI | `2a00:1a00:1::/96` |
| Irancell | `2a10:cc40::/96` |
| Rightel | `2a03:7b00::/96` |
| Mokhaberat | `2a03:5a00::/96` |

---

## 🤖 Telegram Bot

مسیر: **پنل → پیشرفته**

### راه‌اندازی

1. از [@BotFather](https://t.me/BotFather) یک ربات بسازید
2. **Bot Token** را کپی کنید
3. در پنل → پیشرفته → **Bot Token** قرار دهید
4. **Chat ID** خود را از [@userinfobot](https://t.me/userinfobot) بگیرید
5. **Admin ID** را قرار دهید
6. **ذخیره**

### دستورات ربات

- `/start` — منوی اصلی
- `/stats` — آمار
- `/broadcast <message>` — پیام گروهی

---

## ☁️ Cloudflare API

مسیر: **پنل → پیشرفته**

### راه‌اندازی Auto-Update

1. **Account ID** از [dash.cloudflare.com](https://dash.cloudflare.com) → Workers
2. **API Token** با دسترسی `Workers Scripts: Edit`
3. **Worker Name** نام Worker شما
4. فعال‌سازی **Auto Update**

پس از این، پنل هر ۱۵ دقیقه بررسی می‌کند که نسخه جدید در GitHub منتشر شده یا نه.

---

## 📞 پشتیبانی

- 📱 [@the_saz](https://t.me/the_saz)
- 🌐 [zaya.io/thesaz](https://zaya.io/thesaz)
