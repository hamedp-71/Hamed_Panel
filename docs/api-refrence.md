# 📡 API Reference · مرجع API

مرجع کامل REST APIهای Hamed Panel.

> **Base URL**: `https://<worker>.<subdomain>.workers.dev/<apiRoute>`
> **Authentication**: `Authorization: Bearer <token>`

---

## 🔐 احراز هویت

### POST `/api/auth`

ورود با نام کاربری و رمز عبور.

```bash
curl -X POST https://your-worker.workers.dev/sub/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

**پاسخ:**

```json
{
  "ok": true,
  "success": true,
  "data": {
    "session": {
      "token": "sess_xxxxx",
      "username": "admin",
      "isRoot": true,
      "permissions": ["all"],
      "expiresAt": 1767312000000
    },
    "config": { ... },
    "version": "1.0.5",
    "apiRoute": "sub"
  }
}
```

### POST `/api/logout`

خروج از نشست.

### GET `/api/me`

اطلاعات کاربر جاری.

---

## 👥 کاربران

### GET `/api/users`

لیست تمام کاربران.

**Query Parameters:**
- `q` — جستجو
- `group` — فیلتر گروه
- `isp` — فیلتر اپراتور

### GET `/api/users?id=<userId>`

اطلاعات یک کاربر.

### POST `/api/users`

ساخت کاربر جدید.

```json
{
  "name": "Ali",
  "groupId": "vip",
  "isp": "mci",
  "trafficLimit": 50,
  "dailyLimit": 5,
  "expiryDays": 30,
  "maxConfigs": 3,
  "connLimit": 2,
  "notes": "VIP customer"
}
```

### PUT `/api/users?id=<userId>`

به‌روزرسانی کاربر.

### DELETE `/api/users?id=<userId>`

حذف کاربر.

### POST `/api/users?id=<userId>&action=toggle`

فعال/غیرفعال کردن.

### POST `/api/users?id=<userId>&action=reset`

بازنشانی مصرف.

### GET `/api/users/bulk`

Export CSV از تمام کاربران.

### POST `/api/users/bulk`

Import CSV.

---

## 📊 آمار

### GET `/api/stats`

آمار کلی سیستم.

```json
{
  "ok": true,
  "data": {
    "users": { "total": 100, "active": 85, "paused": 10, "expired": 5 },
    "traffic": { "totalGB": "1024.50", "dailyGB": "42.30" },
    "system": { "uptimeSeconds": 86400, "activeConnections": 42 }
  }
}
```

### GET `/api/history?days=7`

تاریخچه مصرف.

### GET `/api/stats/compare?ids=u_1,u_2&days=14`

مقایسه کاربران.

### GET `/api/anomalies`

تشخیص ناهنجاری.

### GET `/api/predictive`

پیش‌بینی مصرف.

### GET `/api/suggestions`

پیشنهادات هوشمند.

### GET `/api/network-weather`

وضعیت کلی.

---

## 🎛️ مدیران

### GET `/api/managers`

لیست مدیران.

### POST `/api/managers`

```json
{
  "action": "create",
  "username": "operator",
  "password": "secure123",
  "permissions": ["users", "stats"]
}
```

### POST `/api/managers` (update)

```json
{
  "action": "update",
  "id": "m_xxxx",
  "password": "newpass",
  "permissions": ["users"]
}
```

### POST `/api/managers` (delete)

```json
{ "action": "delete", "id": "m_xxxx" }
```

---

## ⏰ Cron

### GET `/api/cron`

لیست Cron Jobs.

### POST `/api/cron`

```json
{
  "action": "create",
  "name": "Daily Reset",
  "jobAction": "reset-user-usage",
  "params": { "userId": "u_xxxx" },
  "intervalMinutes": 1440,
  "enabled": true
}
```

---

## 🔔 Webhooks

### GET `/api/webhooks`

لیست Webhooks.

### POST `/api/webhooks`

```json
{
  "action": "create",
  "url": "https://hooks.slack.com/...",
  "events": ["user.created", "user.disabled"]
}
```

### POST `/api/webhooks` (test)

```json
{ "action": "test", "id": "wh_xxxx" }
```

---

## 📱 Subscription

### GET `/?sub=<username>`

دریافت کانفیگ Base64.

**Query Parameters:**
- `flag=clash` — YAML
- `flag=singbox` — Sing-Box JSON
- `flag=vjson` — V2Ray JSON
- `flag=surge` — Surge
- `flag=loon` — Loon
- `flag=a` — Base64 خام

---

## 🛡️ Error Codes

| Code | توضیح |
|------|-------|
| 200 | موفق |
| 400 | داده نامعتبر |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Server Error |

---

## 📞 پشتیبانی

- 📱 [@the_saz](https://t.me/the_saz)
