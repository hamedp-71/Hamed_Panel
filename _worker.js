import { connect } from "cloudflare:sockets";

/* HAMED PANEL v1.0.6 — Design Edition */

const CURRENT_VERSION = "1.0.6";
const PANEL_BRAND = "Hamed Panel";
const SESSION_TTL_MS = 24 * 3600 * 1000;
const AUTH_MAX_ATTEMPTS = 5;
const AUTH_WINDOW_MS = 5 * 60 * 1000;
const BAN_DURATION_MS = 60 * 60 * 1000;
const HISTORY_DAYS = 30;
const MAX_CONFIG_NAME_LEN = 100;
const ALL_PERMISSIONS = ["users","settings","advanced","managers","apikeys","logs","stats","subscriptions","nodes","backup","groups","cron","webhooks","regions","inbounds"];
const SENSITIVE_FIELDS = ["cfApiToken","tgToken","syncApiKey"];

const CARRIERS = {
  mci: { name:"همراه اول", nat64:"2a00:1a00:1::/96", fragment:"1-3-1-2" },
  irancell: { name:"ایرانسل", nat64:"2a10:cc40::/96", fragment:"1-3-1-2" },
  rightel: { name:"رایتل", nat64:"2a03:7b00::/96", fragment:"1-1-1-1" },
  mokhaberat: { name:"مخابرات", nat64:"2a03:5a00::/96", fragment:"1-2-1-1" },
};

const IRAN_DOMAINS_PRESET = ["ir","gov.ir","ac.ir","edu.ir","bank","shaparak.ir","aparat.com","digikala.com","divar.ir","snapp.ir","tapsi.ir","bmi.ir","mci.ir","irancell.ir","rightel.ir","varzesh3.com","farsnews.ir","tasnimnews.com","zoomit.ir"];

const DEFAULT_REGIONS = [
  { id:"de", name:"آلمان", flag:"🇩🇪", ips:["188.114.96.1","188.114.97.1","188.114.98.1","188.114.99.1","188.114.100.1","188.114.101.1","188.114.102.1","188.114.103.1","188.114.104.1","188.114.105.1","188.114.106.1","188.114.107.1","188.114.108.1","188.114.109.1","188.114.110.1","188.114.111.1"] },
  { id:"ae", name:"امارات", flag:"🇦🇪", ips:["197.234.240.1","197.234.240.2","197.234.240.3","197.234.241.1","197.234.241.2","197.234.242.1","197.234.242.2","197.234.243.1","197.234.243.2"] },
  { id:"us", name:"آمریکا", flag:"🇺🇸", ips:["104.16.0.1","104.16.1.1","104.16.2.1","104.17.0.1","104.17.1.1","104.18.0.1","104.19.0.1","104.20.0.1","104.21.0.1","104.22.0.1","172.64.0.1","172.65.0.1","172.66.0.1","172.67.0.1"] },
  { id:"sg", name:"سنگاپور", flag:"🇸🇬", ips:["103.21.244.1","103.21.244.2","103.21.244.3","103.22.200.1","103.22.200.2","103.31.4.1","103.31.4.2"] },
  { id:"fr", name:"فرانسه", flag:"🇫🇷", ips:["188.114.96.20","188.114.97.20","188.114.98.20","188.114.99.20"] },
  { id:"nl", name:"هلند", flag:"🇳🇱", ips:["188.114.100.20","188.114.101.20","188.114.102.20","188.114.103.20"] },
  { id:"uk", name:"انگلستان", flag:"🇬🇧", ips:["188.114.104.20","188.114.105.20","188.114.106.20","188.114.107.20"] },
  { id:"tr", name:"ترکیه", flag:"🇹🇷", ips:["188.114.108.20","188.114.109.20","188.114.110.20","188.114.111.20"] },
  { id:"in", name:"هند", flag:"🇮🇳", ips:["103.21.244.20","103.21.244.21","103.22.200.20","103.22.200.21"] },
];

const getAlpha = () => String.fromCharCode(118,108,101,115,115);
const getBeta = () => String.fromCharCode(116,114,111,106,97,110);
const getGamma = () => String.fromCharCode(99,108,97,115,104);

const safeBtoa = (str) => {
  try { const bytes = new TextEncoder().encode(str); let binary = ""; for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]); return btoa(binary); } catch (e) { return btoa(str); }
};

async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + ":" + password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
}
function generateSalt() { return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2,"0")).join(""); }
function generateSessionToken() { return "sess_" + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2,"0")).join(""); }
function generateId(prefix) { return (prefix || "id") + "_" + crypto.randomUUID().slice(0,8); }
async function hmacSign(secret, message) {
  try { const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["sign"]); const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)); return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,"0")).join(""); } catch (e) { return ""; }
}
let _encKeyCache = null, _encKeyCacheSrc = null;
async function getEncryptionKey(masterKey) {
  if (_encKeyCache && _encKeyCacheSrc === masterKey) return _encKeyCache;
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(masterKey || "default"), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name:"PBKDF2", salt: enc.encode("hamed-panel-enc-v2"), iterations: 50000, hash:"SHA-256" }, baseKey, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
  _encKeyCache = key; _encKeyCacheSrc = masterKey;
  return key;
}
async function encryptField(pt, mk) {
  if (!pt) return "";
  if (typeof pt === "string" && pt.startsWith("enc:")) return pt;
  try { const key = await getEncryptionKey(mk); const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(String(pt))); const combined = new Uint8Array(iv.length + ct.byteLength); combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length); let bin = ""; for (let i = 0; i < combined.length; i++) bin += String.fromCharCode(combined[i]); return "enc:" + btoa(bin); } catch (e) { return pt; }
}
async function decryptField(ct, mk) {
  if (!ct) return "";
  if (typeof ct !== "string" || !ct.startsWith("enc:")) return ct;
  try { const key = await getEncryptionKey(mk); const raw = atob(ct.slice(4)); const bytes = new Uint8Array(raw.length); for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i); const iv = bytes.slice(0,12), data = bytes.slice(12); const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, data); return new TextDecoder().decode(pt); } catch (e) { return ""; }
}
async function encryptSensitiveInConfig(cfg, mk) {
  if (!cfg) return cfg;
  const out = { ...cfg };
  for (const f of SENSITIVE_FIELDS) if (out[f] && !String(out[f]).startsWith("enc:")) out[f] = await encryptField(out[f], mk);
  return out;
}
async function decryptSensitiveInConfig(cfg, mk) {
  if (!cfg) return cfg;
  const out = { ...cfg };
  for (const f of SENSITIVE_FIELDS) if (out[f] && String(out[f]).startsWith("enc:")) out[f] = await decryptField(out[f], mk);
  return out;
}

/* ============ DEFAULTS ============ */
const SYSTEM_DEFAULTS = {
  name:"", apiRoute:"sub",
  maintenanceHost:"https://www.ubuntu.com, https://www.docker.com",
  backupRelay:"", customRelay:"", masterKey:"admin", metricNode:"time.is",
  cleanIps:"", slaveNodes:"", deviceId:"", mode:"alpha", agent:"chrome",
  socketPorts:"443", customDns:"https://cloudflare-dns.com/dns-query",
  resolveIp:"1.1.1.1", enableOpt1:false, enableOpt2:false,
  tgToken:"", tgChatId:"", tgAdminId:"", cfAccountId:"", cfApiToken:"",
  cfWorkerName:"", isPaused:false, silentAlerts:false,
  githubRepo:"THE-SAZ/hamed-panel", nameStrategy:"default", namePrefix:"Hamed",
  tgBotLang:"fa", users:[], subUserAgent:"", customPanelUrl:"",
  limitTotalReq:0, expiryMs:0, linkedPanels:[], hubPanelUrl:"",
  syncApiKey:"", panelApiKeys:[], nat64Prefix:"", enableDirectConfigs:false,
  customRouting:"", upstreamUri:"", autoUpdate:false, autoUpdateFormat:"encoded",
  userGroups: [
    { id:"default", name:"پیش‌فرض", limitTotalGb:0, limitDailyGb:0, expiryDays:0, maxConfigs:0, connLimit:0, color:"#8b5cf6" },
    { id:"vip", name:"VIP", limitTotalGb:100, limitDailyGb:20, expiryDays:30, maxConfigs:5, connLimit:3, color:"#f59e0b" },
    { id:"test", name:"تست", limitTotalGb:5, limitDailyGb:2, expiryDays:3, maxConfigs:2, connLimit:2, color:"#06b6d4" },
  ],
  fragmentPresets: [
    { id:"off", name:"خاموش", value:"" },
    { id:"mci", name:"همراه اول", value:"1-3-1-2" },
    { id:"irancell", name:"ایرانسل", value:"1-3-1-2" },
    { id:"rightel", name:"رایتل", value:"1-1-1-1" },
    { id:"mokhaberat", name:"مخابرات", value:"1-2-1-1" },
    { id:"aggressive", name:"تهاجمی", value:"5-10-5-10" },
  ],
  activeFragment:"off", activeCarrier:"",
  autoCleanIpTest:false, autoCleanIpTopN:5,
  autoCleanIpCache:{ ips:[], testedAt:0 },
  cleanIpRegions: DEFAULT_REGIONS,
  activeCleanRegions: ["de","ae"],
  cleanRegionMode: "round-robin",
  ispTemplates: {
    mci: { name:"همراه اول", fragment:"1-3-1-2", ports:"443", agent:"chrome", extraSni:"" },
    irancell: { name:"ایرانسل", fragment:"1-3-1-2", ports:"443", agent:"chrome", extraSni:"" },
    rightel: { name:"رایتل", fragment:"1-1-1-1", ports:"443", agent:"chrome", extraSni:"" },
    mokhaberat: { name:"مخابرات", fragment:"1-2-1-1", ports:"443", agent:"chrome", extraSni:"" },
    default: { name:"پیش‌فرض", fragment:"", ports:"443", agent:"chrome", extraSni:"" },
  },
  iranRouting:true,
  autoResetCycles:{},
  historyEnabled:true,
  anomalyThreshold:5,
  customLogo:"", customTitleColor:"",
  cronJobs: [], webhooks: [], bannedIps: [],
  crisisPresets: [
    { id:"cut", title:"⚠️ قطعی سراسری", text:"⚠️ توجه: در حال حاضر اینترنت سراسری دچار اختلال است." },
    { id:"slow", title:"🐢 کندی سرعت", text:"🐢 ممکن است سرعت اینترنت شما کاهش یابد." },
    { id:"update", title:"🔄 بروزرسانی سرور", text:"🔄 سرورها در حال بروزرسانی هستند." },
  ],
  crisisHistory: [],
  workflows: [], workflowRuns: [],
  cfUsageAlert: { enabled:true, thresholdPct:80, lastAlert:0 },
  autoFailover: { enabled:true, maxRetries:3, timeoutMs:8000, healthCheckIntervalMin:15 },
  smartSuggestionsEnabled: true,
  predictiveDays: 7,
  multiUpstream: [],
  dnsPool: [
    { url:"https://cloudflare-dns.com/dns-query", name:"Cloudflare", weight:100, enabled:true },
    { url:"https://dns.google/dns-query", name:"Google", weight:100, enabled:true },
    { url:"https://dns.quad9.net/dns-query", name:"Quad9", weight:50, enabled:true },
    { url:"https://doh.shecan.ir/dns-query", name:"Shecan", weight:80, enabled:true },
    { url:"https://dns.adguard-dns.com/dns-query", name:"AdGuard", weight:50, enabled:true },
  ],
  dnsPoolStrategy: "weighted",
  latencyMap: { byRegion:{}, lastUpdate:0 },
  dpiDetection: { lastCheck:0, score:0, mode:"unknown" },
  speedTestCache: { results:[], lastUpdate:0 },
  nodeFailoverState: {},
  autoBanEnabled: false,
  _migratedToSub: false,
  // ═══════════════════════════════════════════════════════════
  // 🆕 v1.0.6: Inbound Configs — Custom naming & extra entries
  // ═══════════════════════════════════════════════════════════
  inboundConfigs: {
    enabled: true,
    // Global defaults (apply to all users)
    global: {
      nameTemplate: "{FLAG} {PREFIX}-{INDEX}", // Uses tags: FLAG, PREFIX, INDEX, COUNTRY, PROTOCOL, USER, ISP, PORT, DATE, REGION, TAG, HOST, IP, WORKER
      applyToAll: true,
      maxNameLength: 60,
      asciiOnly: false,
    },
    // Extra static entries added to subscriptions
    extraEntries: [
      { id:"made-by", text:"THIS PANEL MADE BY HAMED TEAM", type:"static", enabled:true, position:"start", flagPrefix:"🦦" },
    ],
    // Available tags for the template editor
    availableTags: [
      { tag:"FLAG", desc:"پرچم کشور IP", example:"🇩🇪" },
      { tag:"COUNTRY", desc:"نام کشور", example:"Germany" },
      { tag:"CITY", desc:"نام شهر", example:"Frankfurt" },
      { tag:"ISP", desc:"نام ISP", example:"Cloudflare" },
      { tag:"PROTOCOL", desc:"پروتکل (VLESS/Trojan)", example:"VLESS" },
      { tag:"USER", desc:"نام کاربر", example:"ali" },
      { tag:"PORT", desc:"پورت کانفیگ", example:"443" },
      { tag:"PREFIX", desc:"پیشوند تنظیمات", example:"Hamed" },
      { tag:"IP", desc:"آی‌پی کانفیگ", example:"188.114.96.1" },
      { tag:"HOST", desc:"هاست تنظیمات", example:"panel.workers.dev" },
      { tag:"DATE", desc:"تاریخ امروز", example:"2025-09-13" },
      { tag:"INDEX", desc:"شماره کانفیگ", example:"1" },
      { tag:"REGION", desc:"نام منطقه IP", example:"آلمان" },
      { tag:"TAG", desc:"برچسب کاربر", example:"VIP" },
      { tag:"WORKER", desc:"نام Worker", example:"hamed-panel" },
    ],
    // Per-user overrides
    perUser: {},
  },
  managers: [
    { id:"root-admin", username:"admin", passwordHash:null, salt:"builtin-salt-v1", permissions:["all"], isRoot:true, isActive:true, createdAt:0, lastLogin:null, createdBy:"system" }
  ],
  fakeConfigs: [
    { name:"📊 {usage}", enabled:true },
    { name:"📅 {expiry}", enabled:true },
  ],
};

let sysConfig = { ...SYSTEM_DEFAULTS };
let isolateStartTime = 0;
let activeConnections = 0;
let uuidUsage = new Map();
let activeConns = new Map();
let activeDeviceId = "";
let configRegistry = new Map();
let sysUsageCache = { users:{} };
let sysHistoryCache = { days:{} };
let lastSysUsageSync = 0;
let lastCleanIpTest = 0;

const CACHE_TTL_CONFIG = 10000;
const CACHE_TTL_USAGE = 10000;
const CACHE_TTL_BACKUP_IP = 30000;
const CACHE_TTL_HISTORY = 30000;
let sysConfigCacheTime = 0;
let sysUsageCacheTime = 0;
let sysHistoryCacheTime = 0;
let backupIpCache = null;
let backupIpCacheTime = 0;

async function deployWorkerToCloudflare(accountId, apiToken, workerName, code) {
  let cb = [];
  try { const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}/settings`, { headers:{ Authorization:`Bearer ${apiToken}` }, signal: AbortSignal.timeout(15000) }); const j = await r.json(); if (j.success && j.result?.bindings) cb = j.result.bindings; } catch (e) {}
  const meta = { main_module:"_worker.js", compatibility_date:"2024-03-01", compatibility_flags:["allow_eval_during_startup"], bindings:cb };
  const form = new FormData();
  form.append("metadata", new Blob([JSON.stringify(meta)], { type:"application/json" }));
  form.append("_worker.js", new Blob([code], { type:"application/javascript+module" }), "_worker.js");
  return await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}`, { method:"PUT", headers:{ Authorization:`Bearer ${apiToken}` }, body:form });
}
async function d1Init(env) {
  if (env.IOT_DB && !env.IOT_DB_INITIALIZED) {
    try { await env.IOT_DB.prepare("CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT)").run(); env.IOT_DB_INITIALIZED = true; } catch (e) { env.IOT_DB_INITIALIZED = true; }
  }
}
async function d1Get(env, key) {
  if (!env.IOT_DB) return null;
  await d1Init(env);
  try { const { results } = await env.IOT_DB.prepare("SELECT value FROM kv_store WHERE key = ?").bind(key).all(); if (results && results.length > 0) return results[0].value; } catch (e) {}
  return null;
}
async function d1Put(env, key, value) {
  if (!env.IOT_DB) return;
  await d1Init(env);
  try { if (value === "" || value === null || value === undefined) { await env.IOT_DB.prepare("DELETE FROM kv_store WHERE key = ?").bind(key).run(); return; } await env.IOT_DB.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value).run(); } catch (e) {}
}
async function d1List(env, prefix) {
  if (!env.IOT_DB) return [];
  await d1Init(env);
  try { const { results } = await env.IOT_DB.prepare("SELECT key, value FROM kv_store WHERE key LIKE ?").bind(prefix + "%").all(); return results || []; } catch (e) { return []; }
}
async function cachedD1Put(env, key, value) {
  await d1Put(env, key, value);
  if (key === "sys_config") sysConfigCacheTime = 0;
  else if (key === "sys_usage") sysUsageCacheTime = 0;
  else if (key === "sys_history") sysHistoryCacheTime = 0;
  else if (key === "backup_ip") backupIpCacheTime = 0;
}
async function sessPut(env, key, value, ttl) {
  if (env.SESSIONS_KV) { try { await env.SESSIONS_KV.put(key, value, ttl ? { expirationTtl: ttl } : undefined); return; } catch (e) {} }
  await d1Put(env, key, value);
}
async function sessGet(env, key) {
  if (env.SESSIONS_KV) { try { const v = await env.SESSIONS_KV.get(key); if (v !== null) return v; } catch (e) {} }
  return await d1Get(env, key);
}
async function sessDel(env, key) {
  if (env.SESSIONS_KV) { try { await env.SESSIONS_KV.delete(key); } catch (e) {} }
  await d1Put(env, key, "");
}

function sha224Hex(m) {
  const msg = new TextEncoder().encode(m);
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let H = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const words = []; const n = Math.ceil((msg.length + 9) / 64) * 16;
  for (let i = 0; i < n; i++) words[i] = 0;
  for (let i = 0; i < msg.length; i++) words[i >> 2] |= msg[i] << (24 - (i % 4) * 8);
  words[msg.length >> 2] |= 0x80 << (24 - (msg.length % 4) * 8);
  words[n - 1] = msg.length * 8;
  const W = [];
  for (let i = 0; i < n; i += 16) {
    let [a,b,c,d,e,f,g,h] = H;
    for (let j = 0; j < 64; j++) {
      if (j < 16) W[j] = words[i + j];
      else { let w15 = W[j-15], w2 = W[j-2]; let s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3); let s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10); W[j] = (W[j-16] + s0 + W[j-7] + s1) >>> 0; }
      let S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      let ch = (e & f) ^ (~e & g); let temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
      let S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      let maj = (a & b) ^ (a & c) ^ (b & c); let temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  return H.slice(0,7).map(v => v.toString(16).padStart(8,"0")).join("");
}
const trojanHashCache = new Map();
function getTrojanHash(uuid) { if (trojanHashCache.has(uuid)) return trojanHashCache.get(uuid); const h = sha224Hex(uuid); trojanHashCache.set(uuid, h); return h; }
function registerConfigEntry(uuid, userId, relayIp) {
  const e = { userId, relayIp: relayIp || "" };
  configRegistry.set(uuid.replace(/-/g,"").toLowerCase(), e);
  configRegistry.set(getTrojanHash(uuid), e);
}
function lookupConfigEntry(uuidHex) { return configRegistry.get(uuidHex.toLowerCase()) || null; }
function generateConfigUuid(originalUuid, relayIpIndex) {
  const c = originalUuid.replace(/-/g,"").toLowerCase();
  const full = c.substring(0,24) + relayIpIndex.toString(16).padStart(8,"0");
  return `${full.substring(0,8)}-${full.substring(8,12)}-${full.substring(12,16)}-${full.substring(16,20)}-${full.substring(20,32)}`;
}
function decodeConfigUuid(uuid) {
  const c = uuid.replace(/-/g,"").toLowerCase();
  if (c.length !== 32) return null;
  return { userFingerprint: c.substring(0,24), relayIpIndex: parseInt(c.substring(24,32),16) };
}
function isPanelApiKey(key) {
  if (!key || !Array.isArray(sysConfig.panelApiKeys)) return false;
  return sysConfig.panelApiKeys.some(k => k.key === key);
}
function generateApiKey(name) {
  const id = generateId("key");
  const raw = `hamed_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,10)}`;
  return { id, name: name || "Unnamed Key", key: raw, createdAt: Date.now(), lastUsed: null };
}

async function ensureRootManager() {
  if (!Array.isArray(sysConfig.managers) || sysConfig.managers.length === 0) {
    sysConfig.managers = [{ id:"root-admin", username:"admin", passwordHash:null, salt:"builtin-salt-v1", permissions:["all"], isRoot:true, isActive:true, createdAt:Date.now(), lastLogin:null, createdBy:"system" }];
  }
  if (!sysConfig.managers.find(m => m.isRoot)) {
    sysConfig.managers.unshift({ id:"root-admin", username:"admin", passwordHash:null, salt:"builtin-salt-v1", permissions:["all"], isRoot:true, isActive:true, createdAt:Date.now(), lastLogin:null, createdBy:"system" });
  }
}
async function verifyManagerCredentials(username, password) {
  await ensureRootManager();
  const mgr = sysConfig.managers.find(m => m.username.toLowerCase() === String(username).toLowerCase() && m.isActive !== false);
  if (!mgr) return null;
  if (mgr.isRoot && !mgr.passwordHash) { if (password === "admin") return mgr; return null; }
  if (!mgr.passwordHash) return null;
  const computed = await hashPassword(password, mgr.salt);
  if (computed !== mgr.passwordHash) return null;
  return mgr;
}
async function createSession(env, mgr, request) {
  const token = generateSessionToken();
  const ip = request.headers.get("cf-connecting-ip") || "Unknown";
  const ua = (request.headers.get("user-agent") || "").slice(0,200);
  const sess = { token, managerId: mgr.id, username: mgr.username, isRoot: mgr.isRoot === true, permissions: mgr.permissions || [], expiresAt: Date.now() + SESSION_TTL_MS, ip, ua, createdAt: Date.now() };
  await sessPut(env, "session_" + token, JSON.stringify(sess), Math.floor(SESSION_TTL_MS / 1000));
  return sess;
}
async function validateSession(env, token) {
  if (!token || typeof token !== "string" || !token.startsWith("sess_")) return null;
  const raw = await sessGet(env, "session_" + token);
  if (!raw) return null;
  try { const s = JSON.parse(raw); if (s.expiresAt < Date.now()) { await sessDel(env, "session_" + token); return null; } return s; } catch (e) { return null; }
}
async function destroySession(env, token) { if (token && token.startsWith("sess_")) await sessDel(env, "session_" + token); }
async function listSessions(env) {
  let sessions = [];
  if (env.SESSIONS_KV) { try { const list = await env.SESSIONS_KV.list({ prefix:"session_" }); for (const k of list.keys) { const v = await env.SESSIONS_KV.get(k.name); if (v) { try { sessions.push(JSON.parse(v)); } catch (e) {} } } } catch (e) {} }
  else { const rows = await d1List(env, "session_"); for (const r of rows) { try { sessions.push(JSON.parse(r.value)); } catch (e) {} } }
  return sessions.filter(s => s.expiresAt > Date.now()).sort((a,b) => b.createdAt - a.createdAt);
}
async function cleanupExpiredSessions(env) {
  try {
    const now = Date.now();
    if (env.SESSIONS_KV) { const list = await env.SESSIONS_KV.list({ prefix:"session_" }); for (const k of list.keys) { const v = await env.SESSIONS_KV.get(k.name); if (v) { try { const s = JSON.parse(v); if (s.expiresAt < now) await env.SESSIONS_KV.delete(k.name); } catch (e) {} } } }
    else if (env.IOT_DB) { const rows = await d1List(env, "session_"); for (const r of rows) { try { const s = JSON.parse(r.value); if (s.expiresAt < now) await d1Put(env, r.key, ""); } catch (e) {} } }
  } catch (e) {}
}
function hasPermission(ctx, perm) {
  if (!ctx) return false;
  if (ctx.isRoot) return true;
  const perms = ctx.permissions || [];
  if (perms.includes("all")) return true;
  return perms.includes(perm);
}
async function getAuthContext(request, env, data) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ","").trim() || (data && (data.key || data.session)) || "";
  if (!token) return null;
  if (token === sysConfig.masterKey) return { type:"master", isRoot:true, permissions:["all"], username:"admin" };
  if (isPanelApiKey(token)) return { type:"apikey", isRoot:false, permissions:ALL_PERMISSIONS, username:"apikey", apiKey:token };
  if (token.startsWith("sess_")) {
    const sess = await validateSession(env, token);
    if (!sess) return null;
    return { type:"session", isRoot:sess.isRoot, permissions:sess.permissions || [], username:sess.username, managerId:sess.managerId, token:sess.token, ip:sess.ip, ua:sess.ua, createdAt:sess.createdAt };
  }
  return null;
}
async function requirePermission(request, env, data, perm) {
  try {
    const ctx = await getAuthContext(request, env, data);
    if (!ctx) return { ok:false, status:401, error:"Unauthorized" };
    if (!hasPermission(ctx, perm)) return { ok:false, status:403, error:"Forbidden", ctx };
    return { ok:true, ctx };
  } catch (e) { return { ok:false, status:500, error:"Internal error" }; }
}

async function isIpBanned(env, ip) {
  try { const raw = await d1Get(env, "banned_" + ip); if (!raw) return false; const b = JSON.parse(raw); if (b.until && b.until < Date.now()) { await d1Put(env, "banned_" + ip, ""); return false; } return true; } catch (e) { return false; }
}
async function banIp(env, ip, reason, durationMs) {
  try { const b = { ip, reason, bannedAt: Date.now(), until: Date.now() + (durationMs || BAN_DURATION_MS) }; await d1Put(env, "banned_" + ip, JSON.stringify(b)); if (!sysConfig.bannedIps) sysConfig.bannedIps = []; if (!sysConfig.bannedIps.some(x => x.ip === ip)) { sysConfig.bannedIps.unshift(b); if (sysConfig.bannedIps.length > 200) sysConfig.bannedIps = sysConfig.bannedIps.slice(0,200); } return b; } catch (e) { return null; }
}
async function unbanIp(env, ip) {
  try { await d1Put(env, "banned_" + ip, ""); sysConfig.bannedIps = (sysConfig.bannedIps || []).filter(x => x.ip !== ip); return true; } catch (e) { return false; }
}
async function listBannedIps(env) {
  const list = [];
  const rows = await d1List(env, "banned_");
  for (const r of rows) { try { const b = JSON.parse(r.value); if (b.until > Date.now()) list.push(b); } catch (e) {} }
  return list.sort((a,b) => b.bannedAt - a.bannedAt);
}

async function checkRateLimit(env, ip, action, maxAttempts, windowMs) {
  const key = "rl_" + action + "_" + ip;
  const raw = await d1Get(env, key);
  const now = Date.now();
  let data = raw ? JSON.parse(raw) : { count:0, first:now, blockedUntil:0 };
  if (data.blockedUntil && data.blockedUntil > now) return { allowed:false, retryAfter: Math.ceil((data.blockedUntil - now) / 1000), blocked:true };
  if (!data.first || now - data.first > windowMs) data = { count:0, first:now, blockedUntil:0 };
  data.count++;
  if (data.count > maxAttempts) { data.blockedUntil = now + windowMs; await d1Put(env, key, JSON.stringify(data)); if (action === "auth" && sysConfig.autoBanEnabled === true) await banIp(env, ip, "Too many auth attempts", 15 * 60 * 1000); return { allowed:false, retryAfter: Math.ceil(windowMs/1000), blocked:true }; }
  await d1Put(env, key, JSON.stringify(data));
  return { allowed:true, remaining: Math.max(0, maxAttempts - data.count) };
}
async function clearRateLimit(env, ip, action) { await d1Put(env, "rl_" + action + "_" + ip, ""); }

async function triggerWebhook(env, ctx, event, payload) {
  try {
    const hooks = (sysConfig.webhooks || []).filter(w => w.enabled && (w.events || []).includes(event));
    if (hooks.length === 0) return;
    const ts = Date.now();
    for (const wh of hooks) {
      const body = JSON.stringify({ event, timestamp: ts, version: CURRENT_VERSION, data: payload });
      const sig = await hmacSign(wh.secret || "", body);
      const p = fetch(wh.url, { method:"POST", headers:{ "Content-Type":"application/json", "X-Hamed-Event":event, "X-Hamed-Signature":"sha256=" + sig, "User-Agent":"HamedPanel/" + CURRENT_VERSION }, body, signal: AbortSignal.timeout(8000) }).catch(() => {});
      if (ctx && ctx.waitUntil) ctx.waitUntil(p);
    }
  } catch (e) {}
}
const WEBHOOK_EVENTS = ["user.created","user.updated","user.deleted","user.disabled","panel.updated","anomaly.detected","crisis.sent","auth.success","auth.failed","workflow.triggered"];

const CRON_ACTIONS = {
  "reset-user-usage": { label:"بازنشانی مصرف", params:["userId"] },
  "extend-user-expiry": { label:"تمدید انقضا", params:["userId","days"] },
  "send-telegram": { label:"پیام تلگرام", params:["message"] },
  "clean-ip-test": { label:"تست IP تمیز", params:[] },
  "node-health-check": { label:"سلامت نودها", params:[] },
  "auto-backup": { label:"بکاپ", params:["encrypt"] },
  "purge-history": { label:"پاکسازی تاریخچه", params:["keepDays"] },
  "broadcast": { label:"پیام گروهی", params:["message"] },
};

async function runCronJob(env, ctx, job) {
  try {
    switch (job.action) {
      case "reset-user-usage": { const userId = job.params?.userId; if (!userId) break; const c = userId.replace(/-/g,"").toLowerCase(); if (!sysUsageCache.users) sysUsageCache.users = {}; if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; } else sysUsageCache.users[c] = { reqs:0, dReqs:0, lastDay: todayStr() }; await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache)); break; }
      case "extend-user-expiry": { const { userId, days } = job.params || {}; const u = (sysConfig.users || []).find(x => x.id === userId); if (u && days) { if (u.expiryMs) u.expiryMs += parseInt(days) * 86400000; else u.expiryMs = Date.now() + parseInt(days) * 86400000; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); } break; }
      case "send-telegram": { if (!sysConfig.tgToken || !(sysConfig.tgAdminId || sysConfig.tgChatId)) break; const text = job.params?.message || "Cron"; await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id: sysConfig.tgAdminId || sysConfig.tgChatId, text, parse_mode:"HTML" }), signal: AbortSignal.timeout(8000) }).catch(() => {}); break; }
      case "clean-ip-test": await runCleanIpTest(env); break;
      case "node-health-check": await runNodeHealthCheck(env); break;
      case "auto-backup": await backupToR2(env, { encrypt: !!job.params?.encrypt }); break;
      case "purge-history": { const keep = parseInt(job.params?.keepDays) || 30; const days = Object.keys(sysHistoryCache.days || {}).sort(); while (days.length > keep) delete sysHistoryCache.days[days.shift()]; await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache)); break; }
      case "broadcast": { if (!sysConfig.tgToken) break; const msg = job.params?.message || ""; if (!msg) break; const recipients = new Set(); if (sysConfig.tgAdminId) recipients.add(sysConfig.tgAdminId); if (sysConfig.tgChatId) recipients.add(sysConfig.tgChatId); (sysConfig.users || []).forEach(u => { if (u.tgChatId) recipients.add(u.tgChatId); }); for (const id of recipients) await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id:id, text:msg, parse_mode:"HTML" }), signal: AbortSignal.timeout(8000) }).catch(() => {}); break; }
    }
    job.lastRun = Date.now();
    job.lastStatus = "ok";
  } catch (e) { job.lastStatus = "error"; job.lastError = e.message; }
}
async function runDueCronJobs(env, ctx) {
  const now = Date.now();
  const jobs = sysConfig.cronJobs || [];
  let changed = false;
  for (const job of jobs) {
    if (!job.enabled) continue;
    const intervalMs = (job.intervalMinutes || 60) * 60 * 1000;
    if (now - (job.lastRun || 0) >= intervalMs) { await runCronJob(env, ctx, job); changed = true; }
  }
  if (changed) await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
}

function getIspTemplate(userIsp) {
  const templates = sysConfig.ispTemplates || {};
  if (userIsp && templates[userIsp]) return templates[userIsp];
  return templates.default || { fragment:"", ports:"443", agent:"chrome", extraSni:"" };
}
function applyIspTemplate(user, baseFragment) {
  const t = getIspTemplate(user?.isp);
  if (!t) return { fragment: baseFragment, agent: sysConfig.agent || "chrome", ports: null };
  return { fragment: t.fragment || baseFragment, agent: t.agent || sysConfig.agent || "chrome", ports: t.ports || null, extraSni: t.extraSni || "" };
}

async function sendCrisisBroadcast(env, message, presetId) {
  if (!sysConfig.tgToken) return { success:false, ok:false, error:"Telegram not configured" };
  const recipients = new Set();
  if (sysConfig.tgAdminId) recipients.add(sysConfig.tgAdminId);
  if (sysConfig.tgChatId) recipients.add(sysConfig.tgChatId);
  (sysConfig.users || []).forEach(u => { if (u.tgChatId) recipients.add(u.tgChatId); });
  let sent = 0, failed = 0;
  for (const id of recipients) {
    try { const r = await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id:id, text:message, parse_mode:"HTML" }), signal: AbortSignal.timeout(8000) }); const j = await r.json(); if (j.ok) sent++; else failed++; } catch (e) { failed++; }
  }
  if (!sysConfig.crisisHistory) sysConfig.crisisHistory = [];
  sysConfig.crisisHistory.unshift({ ts: Date.now(), message, presetId, sent, failed, total: recipients.size });
  if (sysConfig.crisisHistory.length > 50) sysConfig.crisisHistory = sysConfig.crisisHistory.slice(0, 50);
  await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return { success:true, ok:true, sent, failed, total: recipients.size };
}

async function backupToR2(env, opts) {
  try {
    if (!env.BACKUP_BUCKET) return null;
    opts = opts || {};
    const data = { ts:new Date().toISOString(), version:CURRENT_VERSION, config:sysConfig, usage:sysUsageCache, history:sysHistoryCache };
    let payload = JSON.stringify(data);
    if (opts.encrypt) { const mk = sysConfig.masterKey || "admin"; payload = await encryptField(payload, mk); }
    const key = "backups/" + new Date().toISOString().split("T")[0] + "/config-" + Date.now() + (opts.encrypt ? ".enc" : "") + ".json";
    try { await env.BACKUP_BUCKET.put(key, payload, { httpMetadata:{ contentType:"application/json" } }); } catch (e) { return null; }
    try { const list = await env.BACKUP_BUCKET.list({ prefix:"backups/", limit:200 }); if (list.objects.length > 30) { const sorted = list.objects.sort((a,b) => new Date(a.uploaded) - new Date(b.uploaded)); for (const obj of sorted.slice(0, sorted.length - 30)) await env.BACKUP_BUCKET.delete(obj.key); } } catch (e) {}
    return key;
  } catch (e) { return null; }
}
async function listBackups(env) {
  if (!env.BACKUP_BUCKET) return [];
  try { const list = await env.BACKUP_BUCKET.list({ prefix:"backups/", limit:100 }); return list.objects.map(o => ({ key:o.key, size:o.size, uploaded:o.uploaded })).sort((a,b) => new Date(b.uploaded) - new Date(a.uploaded)); } catch (e) { return []; }
}
async function restoreFromR2(env, key) {
  if (!env.BACKUP_BUCKET) return { ok:false, success:false, error:"R2 not configured" };
  try {
    const obj = await env.BACKUP_BUCKET.get(key);
    if (!obj) return { ok:false, success:false, error:"Not found" };
    let text = await obj.text();
    if (key.endsWith(".enc")) { const mk = sysConfig.masterKey || "admin"; text = await decryptField(text, mk); }
    const data = JSON.parse(text);
    if (!data.config) return { ok:false, success:false, error:"Invalid" };
    sysConfig = { ...SYSTEM_DEFAULTS, ...data.config };
    if (data.usage) sysUsageCache = data.usage;
    if (data.history) sysHistoryCache = data.history;
    const toSave = await encryptSensitiveInConfig(sysConfig, sysConfig.masterKey || "admin");
    await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
    await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache));
    return { ok:true, success:true };
  } catch (e) { return { ok:false, success:false, error:e.message }; }
}

function todayStr() { return new Date().toISOString().split("T")[0]; }
async function recordHistory(env, uuid, delta) {
  if (!sysConfig.historyEnabled) return;
  const today = todayStr();
  if (!sysHistoryCache.days) sysHistoryCache.days = {};
  if (!sysHistoryCache.days[today]) sysHistoryCache.days[today] = {};
  if (!sysHistoryCache.days[today][uuid]) sysHistoryCache.days[today][uuid] = 0;
  sysHistoryCache.days[today][uuid] += delta;
}
function pruneHistory() {
  const days = Object.keys(sysHistoryCache.days || {}).sort();
  while (days.length > HISTORY_DAYS) delete sysHistoryCache.days[days.shift()];
}
function getHistorySeries(uuid, days) {
  const series = []; const now = new Date();
  for (let i = days - 1; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toISOString().split("T")[0]; const val = (sysHistoryCache.days?.[key]?.[uuid] || 0) / 6000; series.push({ date:key, gb: parseFloat(val.toFixed(3)) }); }
  return series;
}
function getTotalHistorySeries(days) {
  const series = []; const now = new Date();
  for (let i = days - 1; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toISOString().split("T")[0]; let total = 0; const dayData = sysHistoryCache.days?.[key] || {}; for (const u in dayData) total += dayData[u]; series.push({ date:key, gb: parseFloat((total/6000).toFixed(3)) }); }
  return series;
}
async function detectAnomalies() {
  const today = todayStr(); const anomalies = [];
  const threshold = sysConfig.anomalyThreshold || 5;
  for (const u of (sysConfig.users || [])) {
    const idClean = u.id.replace(/-/g,"").toLowerCase();
    const todayReqs = sysHistoryCache.days?.[today]?.[idClean] || 0;
    if (todayReqs < 1000) continue;
    const past7 = []; const now = new Date();
    for (let i = 1; i <= 7; i++) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toISOString().split("T")[0]; const val = sysHistoryCache.days?.[key]?.[idClean] || 0; if (val > 0) past7.push(val); }
    if (past7.length < 3) continue;
    const avg = past7.reduce((a,b) => a+b, 0) / past7.length;
    if (avg > 0 && todayReqs > avg * threshold) anomalies.push({ userId:u.id, name:u.name, today:todayReqs, avg:Math.round(avg), ratio:(todayReqs/avg).toFixed(1) });
  }
  return anomalies;
}

function trackUsage(uuid, bytes, env, ctx) {
  if (!sysUsageCache) sysUsageCache = { users:{} };
  if (!sysUsageCache.users) sysUsageCache.users = {};
  if (!sysUsageCache.users[uuid]) sysUsageCache.users[uuid] = { reqs:0, dReqs:0, lastDay: todayStr() };
  let u = sysUsageCache.users[uuid];
  let today = todayStr();
  if (u.lastDay !== today) { u.dReqs = 0; u.lastDay = today; }
  if (u.reqs === undefined) u.reqs = 0;
  if (u.dReqs === undefined) u.dReqs = 0;
  if (bytes === 0) { u.reqs += 1; u.dReqs += 1; if (sysConfig.historyEnabled) recordHistory(env, uuid, 1).catch(() => {}); }
  const now = Date.now();
  if (now - lastSysUsageSync > 30000) {
    lastSysUsageSync = now;
    if (env && env.IOT_DB) {
      let changedConfig = false;
      if (sysConfig.users && sysConfig.users.length > 0) {
        sysConfig.users.forEach(u => {
          let uId = u.id.replace(/-/g,"").toLowerCase();
          let sysU = sysUsageCache.users[uId];
          if (!u.isPaused) {
            let reason = null;
            if (u.expiryMs && Date.now() > u.expiryMs) reason = "Expiration date reached";
            else if (sysU && u.limitTotalReq && sysU.reqs >= u.limitTotalReq) reason = "Traffic limit exceeded";
            if (reason) {
              u.isPaused = true; u.disabledReason = reason; u.disabledAt = Date.now(); changedConfig = true;
              ctx?.waitUntil(logActivity(env, "User Auto-Disabled", `${u.name}: ${reason}`).catch(() => {}));
              ctx?.waitUntil(triggerWebhook(env, ctx, "user.disabled", { userId:u.id, name:u.name, reason }).catch(() => {}));
            }
          }
        });
      }
      if (changedConfig) ctx?.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(() => {}));
      pruneHistory();
      ctx?.waitUntil(cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache)).catch(() => {}));
      ctx?.waitUntil(cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache)).catch(() => {}));
    }
  }
}

/* ==================== INBOUND CONFIGS ENGINE (NEW v1.0.6) ==================== */

/**
 * Build a subscription entry name using the new template system.
 * Priority: perUser override > global template > nameStrategy fallback
 */
function buildInboundName(type, profile, ip, port, configIndex, hostName, regionInfo, isDirect) {
  try {
    const cfg = sysConfig.inboundConfigs || {};
    if (cfg.enabled === false) {
      // Use legacy strategy
      return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo);
    }
    // Determine template: perUser > global > legacy
    const userOverride = cfg.perUser?.[profile.id];
    const template = (userOverride && userOverride.nameTemplate && userOverride.enabled !== false)
      ? userOverride.nameTemplate
      : (cfg.global?.nameTemplate || "");

    if (!template) {
      return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo);
    }

    const geo = getGeoInfo(ip);
    const protoLab = type === "alpha" ? "VLESS" : "Trojan";
    const today = new Date();
    const dateStr = today.getFullYear() + "-" + String(today.getMonth()+1).padStart(2,"0") + "-" + String(today.getDate()).padStart(2,"0");
    const prefix = cfg.global?.prefix || sysConfig.namePrefix || "Hamed";
    const workerName = sysConfig.cfWorkerName || sysConfig.name || hostName || "";
    const flagValue = isDirect ? "☁" : (regionInfo?.flag || geo.flag || "🌐");
    const countryValue = regionInfo?.name || geo.country || "";
    const regionValue = regionInfo?.name || "";
    const tagsValue = (profile.tags || []).join(",");

    let name = template
      .replace(/\{FLAG\}/g, flagValue)
      .replace(/\{COUNTRY\}/g, countryValue)
      .replace(/\{CITY\}/g, geo.city || "")
      .replace(/\{ISP\}/g, geo.isp || "")
      .replace(/\{PROTOCOL\}/g, protoLab)
      .replace(/\{USER\}/g, profile.name || "")
      .replace(/\{PORT\}/g, String(port))
      .replace(/\{PREFIX\}/g, prefix)
      .replace(/\{IP\}/g, ip || "")
      .replace(/\{HOST\}/g, hostName || "")
      .replace(/\{DATE\}/g, dateStr)
      .replace(/\{INDEX\}/g, String(configIndex))
      .replace(/\{REGION\}/g, regionValue)
      .replace(/\{TAG\}/g, tagsValue)
      .replace(/\{WORKER\}/g, workerName);

    // Trim and limit length
    name = name.trim().replace(/\s+/g, " ");
    const maxLen = cfg.global?.maxNameLength || MAX_CONFIG_NAME_LEN;
    if (name.length > maxLen) name = name.slice(0, maxLen);

    if (cfg.global?.asciiOnly) name = name.replace(/[^\x00-\x7F]/g, "").trim();

    return name || (type === "alpha" ? "V" : "T") + "-" + prefix + "-" + port;
  } catch (e) {
    return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo);
  }
}

/**
 * Get the extra entries for a subscription (static text lines).
 * Returns array of { text, encoded } objects ready to append.
 */
function getExtraInboundEntries(userId) {
  try {
    const cfg = sysConfig.inboundConfigs || {};
    if (cfg.enabled === false) return [];
    const userOverride = cfg.perUser?.[userId];
    // Use per-user extraEntries if enabled
    let entries = [];
    if (userOverride && Array.isArray(userOverride.extraEntries) && userOverride.enabled !== false) {
      entries = userOverride.extraEntries;
    } else if (Array.isArray(cfg.extraEntries)) {
      entries = cfg.extraEntries;
    }
    return entries.filter(e => e && e.enabled && e.text);
  } catch (e) { return []; }
}

/**
 * Build a static inbound entry in URI format (used as fake config).
 */
function buildStaticInboundURI(entry) {
  const text = (entry.text || "").trim();
  if (!text) return "";
  const prefix = entry.flagPrefix ? entry.flagPrefix + " " : "";
  // Use trojan as dummy carrier pointing to 127.0.0.1 with the name as fragment
  return `trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#${encodeURIComponent(prefix + text)}`;
}

/* ==================== MAIN FETCH ==================== */
export default {
  async fetch(request, env, ctx) {
    try {
      if (!isolateStartTime) isolateStartTime = Date.now();
      if (configRegistry.size > 10000) { configRegistry.clear(); trojanHashCache.clear(); }
      await loadSysConfig(env, ctx);
      await ensureRootManager();
      activeDeviceId = sysConfig.deviceId || generateHardwareId(sysConfig.apiRoute);

      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      const isTelemetryStream = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";
      const clientIp = request.headers.get("cf-connecting-ip") || "";

      if (!sysConfig._migratedToSub) {
        let didChange = false;
        if (sysConfig.apiRoute === "sync" || !sysConfig.apiRoute) { sysConfig.apiRoute = "sub"; didChange = true; }
        sysConfig._migratedToSub = true;
        if (didChange) ctx?.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(() => {}));
      }

      let reqPath = url.pathname;
      if (reqPath.endsWith("/") && reqPath.length > 1) reqPath = reqPath.slice(0,-1);

      if (sysConfig.apiRoute === "sub") {
        const legacyPrefix = "/sync";
        const currentPrefix = "/sub";
        if (reqPath === legacyPrefix || reqPath === legacyPrefix + "/") reqPath = currentPrefix;
        else if (reqPath.startsWith(legacyPrefix + "/")) reqPath = currentPrefix + reqPath.slice(legacyPrefix.length);
        if (reqPath === currentPrefix + "/dash" && (request.method === "GET" || request.method === "HEAD")) return Response.redirect(url.origin + "/panel", 301);
      }

      const isPanelPath = reqPath === "/panel";
      const isTgPath = reqPath === `/${encodeURI(sysConfig.apiRoute)}/tg`;
      if (clientIp && !isPanelPath && !isTgPath) {
        if (await isIpBanned(env, clientIp)) return new Response("403 Forbidden", { status: 403 });
      }

      const R = sysConfig.apiRoute;
      const routes = {
        data:`/${encodeURI(R)}`, panel: `/panel`,
        auth:`/${encodeURI(R)}/api/auth`, logout:`/${encodeURI(R)}/api/logout`, me:`/${encodeURI(R)}/api/me`,
        sessions:`/${encodeURI(R)}/api/sessions`, sync:`/${encodeURI(R)}/api/sync`,
        tg:`/${encodeURI(R)}/tg`, syncPanel:`/${encodeURI(R)}/tg/sync_panel`,
        logs:`/${encodeURI(R)}/api/logs`, users:`/${encodeURI(R)}/api/users`, bulkUsers:`/${encodeURI(R)}/api/users/bulk`,
        stats:`/${encodeURI(R)}/api/stats`, history:`/${encodeURI(R)}/api/history`, compare:`/${encodeURI(R)}/api/stats/compare`,
        anomalies:`/${encodeURI(R)}/api/anomalies`, update:`/${encodeURI(R)}/api/update`, apiKeys:`/${encodeURI(R)}/api/keys`,
        managers:`/${encodeURI(R)}/api/managers`, nodes:`/${encodeURI(R)}/api/nodes`, nodeHealth:`/${encodeURI(R)}/api/nodes/health`,
        groups:`/${encodeURI(R)}/api/groups`, backup:`/${encodeURI(R)}/api/backup`, regions:`/${encodeURI(R)}/api/regions`,
        cleanIpTest:`/${encodeURI(R)}/api/cleanip/test`, cleanIpResults:`/${encodeURI(R)}/api/cleanip/results`,
        cronJobs:`/${encodeURI(R)}/api/cron`, webhooks:`/${encodeURI(R)}/api/webhooks`, webhookEvents:`/${encodeURI(R)}/api/webhooks/events`,
        banned:`/${encodeURI(R)}/api/banned`, crisis:`/${encodeURI(R)}/api/crisis`, crisisPresets:`/${encodeURI(R)}/api/crisis/presets`,
        logo:`/${encodeURI(R)}/api/logo`, ispTemplates:`/${encodeURI(R)}/api/isp-templates`,
        configExport:`/${encodeURI(R)}/api/config/export`, configImport:`/${encodeURI(R)}/api/config/import`,
        broadcast:`/${encodeURI(R)}/api/broadcast`,
        workflows:`/${encodeURI(R)}/api/workflows`, workflowActions:`/${encodeURI(R)}/api/workflows/actions`,
        dnsPool:`/${encodeURI(R)}/api/dns-pool`, dnsPoolActions:`/${encodeURI(R)}/api/dns-pool/actions`,
        upstreams:`/${encodeURI(R)}/api/upstreams`, speedTest:`/${encodeURI(R)}/api/speedtest`,
        latencyMap:`/${encodeURI(R)}/api/latency-map`, dpi:`/${encodeURI(R)}/api/dpi`,
        networkWeather:`/${encodeURI(R)}/api/network-weather`, suggestions:`/${encodeURI(R)}/api/suggestions`,
        predictive:`/${encodeURI(R)}/api/predictive`,
        inbounds:`/${encodeURI(R)}/api/inbounds`, inboundsActions:`/${encodeURI(R)}/api/inbounds/actions`,
      };

      const isAuthorizedRoute =
        reqPath === routes.data || reqPath === routes.panel || reqPath === routes.auth ||
        reqPath === routes.sync || reqPath === routes.tg || reqPath === routes.syncPanel ||
        reqPath === routes.logs || reqPath.startsWith(`/${encodeURI(R)}/api/`);

      if (!isTelemetryStream && !isAuthorizedRoute) return serveMaintenancePage(request, url);

      if (!isTelemetryStream) {
        if (reqPath === routes.panel) {
          let html = DASHBOARD_HTML;
          html = html.replace(/__CURRENT_VERSION__/g, CURRENT_VERSION);
          html = html.replace(/__API_ROUTE__/g, sysConfig.apiRoute);
          html = html.replace(/__PANEL_NAME__/g, sysConfig.name || PANEL_BRAND);
          html = html.replace(/__CUSTOM_LOGO__/g, sysConfig.customLogo || "");
          html = html.replace(/__TITLE_COLOR__/g, sysConfig.customTitleColor || "");
          return new Response(html, { headers:{ "Content-Type":"text/html;charset=utf-8", "Cache-Control":"no-store" } });
        }
        if (reqPath === routes.auth) { if (request.method !== "POST") return new Response("405", { status:405 }); return await handleAuth(request, url.hostname, ctx, env); }
        if (reqPath === routes.logout) return await handleLogout(request, env);
        if (reqPath === routes.me) return await handleMe(request, env);
        if (reqPath === routes.sessions) return await handleSessions(request, env);
        if (reqPath === routes.sync) {
          if (request.method === "OPTIONS") return new Response(null, { status:204, headers:{ "Access-Control-Allow-Origin":"*", "Access-Control-Allow-Methods":"POST, OPTIONS", "Access-Control-Allow-Headers":"Content-Type, Authorization" } });
          if (request.method !== "POST") return new Response("405", { status:405 });
          const r = await handleConfigSync(request, env, ctx);
          r.headers.set("Access-Control-Allow-Origin","*");
          return r;
        }
        if (reqPath === routes.logs) return await handleLogs(request, env);
        if (reqPath === routes.bulkUsers) return await handleBulkUsers(request, env, ctx);
        if (reqPath === routes.users) return await handleUsersApi(request, env, ctx);
        if (reqPath === routes.managers) return await handleManagersApi(request, env, ctx);
        if (reqPath === routes.stats) return await handleStatsApi(request, env);
        if (reqPath === routes.history) return await handleHistoryApi(request, env);
        if (reqPath === routes.compare) return await handleCompareApi(request, env);
        if (reqPath === routes.anomalies) return await handleAnomaliesApi(request, env);
        if (reqPath === routes.update) return await handleUpdateApi(request, env, ctx);
        if (reqPath === routes.apiKeys) return await handleApiKeys(request, env, ctx);
        if (reqPath === routes.nodes) return await handleNodesApi(request, env, ctx);
        if (reqPath === routes.nodeHealth) return await handleNodeHealth(request, env);
        if (reqPath === routes.groups) return await handleGroupsApi(request, env, ctx);
        if (reqPath === routes.backup) return await handleBackupApi(request, env, ctx);
        if (reqPath === routes.regions) return await handleRegionsApi(request, env, ctx);
        if (reqPath === routes.cleanIpTest) return await handleCleanIpTest(request, env, ctx);
        if (reqPath === routes.cleanIpResults) return await handleCleanIpResults(request, env);
        if (reqPath === routes.cronJobs) return await handleCronJobsApi(request, env, ctx);
        if (reqPath === routes.webhooks) return await handleWebhooksApi(request, env, ctx);
        if (reqPath === routes.webhookEvents) return new Response(JSON.stringify({ ok:true, success:true, events:WEBHOOK_EVENTS }), { headers:{ "Content-Type":"application/json" } });
        if (reqPath === routes.banned) return await handleBannedApi(request, env, ctx);
        if (reqPath === routes.crisis) return await handleCrisisApi(request, env, ctx);
        if (reqPath === routes.crisisPresets) return new Response(JSON.stringify({ ok:true, success:true, presets: sysConfig.crisisPresets || [] }), { headers:{ "Content-Type":"application/json" } });
        if (reqPath === routes.logo) return await handleLogoApi(request, env, ctx);
        if (reqPath === routes.ispTemplates) return await handleIspTemplatesApi(request, env, ctx);
        if (reqPath === routes.configExport) return await handleConfigExport(request, env);
        if (reqPath === routes.configImport) return await handleConfigImport(request, env, ctx);
        if (reqPath === routes.broadcast) return await handleBroadcast(request, env, ctx);
        if (reqPath === routes.workflows) return await handleWorkflowsApi(request, env, ctx);
        if (reqPath === routes.workflowActions) return await handleWorkflowsActions(request, env, ctx);
        if (reqPath === routes.dnsPool) return await handleDnsPoolApi(request, env, ctx);
        if (reqPath === routes.dnsPoolActions) return await handleDnsPoolActions(request, env, ctx);
        if (reqPath === routes.upstreams) return await handleUpstreamsApi(request, env, ctx);
        if (reqPath === routes.speedTest) return await handleSpeedTest(request, env, ctx);
        if (reqPath === routes.latencyMap) return await handleLatencyMap(request, env, ctx);
        if (reqPath === routes.dpi) return await handleDpiDetection(request, env);
        if (reqPath === routes.networkWeather) return await handleNetworkWeather(request, env);
        if (reqPath === routes.suggestions) return await handleSuggestions(request, env);
        if (reqPath === routes.predictive) return await handlePredictive(request, env);
        if (reqPath === routes.inbounds) return await handleInboundsApi(request, env, ctx);
        if (reqPath === routes.inboundsActions) return await handleInboundsActions(request, env, ctx);
        if (reqPath === routes.syncPanel) { if (request.method !== "POST") return new Response("405", { status:405 }); return await handleSyncPanel(request, env, ctx); }
        if (reqPath === routes.tg) { if (request.method !== "POST") return new Response("405", { status:405 }); return await handleTelegramWebhook(request, env, url.hostname, ctx); }
        if (reqPath === routes.data) return await handleSubscription(request, url, env, ctx);
      }

      if (isTelemetryStream) {
        if (sysConfig.isPaused) return new Response(null, { status:503 });
        let wsRelayIdx = -1;
        try { const rp = url.searchParams.get("ri"); if (rp !== null) wsRelayIdx = parseInt(rp, 10); } catch (e) {}
        if (wsRelayIdx < 0) { try { const ls = url.pathname.split("/").pop(); if (ls) { const n = parseInt(ls, 10); if (!isNaN(n) && n >= 0) wsRelayIdx = n; } } catch (e) {} }
        if (wsRelayIdx < 0) { try { const ls = url.pathname.split("/").pop(); if (ls) { const d = JSON.parse(atob(ls)); if (typeof d.relayIdx === "number") wsRelayIdx = d.relayIdx; } } catch (e) {} }
        return await processTelemetryStream(env, ctx, wsRelayIdx);
      }
      return new Response(null, { status:404 });
    } catch (err) { return new Response(null, { status:404 }); }
  },

  async scheduled(event, env, ctx) {
    try {
      await loadSysConfig(env, ctx);
      await ensureRootManager();
      ctx.waitUntil(cleanupExpiredSessions(env));
      ctx.waitUntil(runDueCronJobs(env, ctx));
      if (sysConfig.autoCleanIpTest && Date.now() - lastCleanIpTest > 3600 * 1000) ctx.waitUntil(runCleanIpTest(env));
      if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
      for (const userId in sysConfig.autoResetCycles) {
        const cycle = sysConfig.autoResetCycles[userId];
        if (!cycle || !cycle.type || cycle.type === "none") continue;
        const elapsed = Date.now() - (cycle.lastReset || 0);
        let shouldReset = false;
        if (cycle.type === "daily" && elapsed > 86400000) shouldReset = true;
        else if (cycle.type === "weekly" && elapsed > 604800000) shouldReset = true;
        else if (cycle.type === "monthly" && elapsed > 2592000000) shouldReset = true;
        if (shouldReset) { const c = userId.replace(/-/g,"").toLowerCase(); if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; } cycle.lastReset = Date.now(); }
      }
      await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      if (sysConfig.cfUsageAlert?.enabled && sysConfig.cfAccountId && sysConfig.cfApiToken) {
        const reqs = await fetchCloudflareUsage(sysConfig.cfAccountId, sysConfig.cfApiToken);
        if (reqs !== null) {
          const pct = (reqs / 100000) * 100;
          if (pct >= (sysConfig.cfUsageAlert.thresholdPct || 80) && Date.now() - (sysConfig.cfUsageAlert.lastAlert || 0) > 6 * 3600 * 1000) {
            sysConfig.cfUsageAlert.lastAlert = Date.now();
            if (sysConfig.tgToken && (sysConfig.tgAdminId || sysConfig.tgChatId)) {
              ctx.waitUntil(fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id: sysConfig.tgAdminId || sysConfig.tgChatId, text: `⚠️ <b>CF Usage Alert</b>\n\nمصرف به ${pct.toFixed(1)}% رسید.\n${reqs}/100000`, parse_mode:"HTML" }), signal: AbortSignal.timeout(8000) }).catch(() => {}));
            }
          }
          await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        }
      }
      if ((Date.now() - (sysConfig.nodeFailoverState.lastCheck || 0)) > (sysConfig.autoFailover?.healthCheckIntervalMin || 15) * 60 * 1000) {
        sysConfig.nodeFailoverState.lastCheck = Date.now();
        ctx.waitUntil(runNodeHealthCheck(env));
      }
      if (sysConfig.autoUpdate && sysConfig.cfAccountId && sysConfig.cfApiToken && sysConfig.cfWorkerName) {
        const repo = (sysConfig.githubRepo || "").replace(/https?:\/\/github\.com\//,"").trim();
        if (repo) {
          let rv = null;
          try { const r = await fetch(`https://raw.githubusercontent.com/${repo}/main/version`, { signal: AbortSignal.timeout(8000) }); if (r.ok) rv = (await r.text()).trim(); } catch (e) {}
          if (rv && cmpVersions(CURRENT_VERSION, rv) < 0) {
            try { let r = await fetch(`https://raw.githubusercontent.com/${repo}/main/_worker.encode.js`, { signal: AbortSignal.timeout(15000) }); if (!r.ok) r = await fetch(`https://raw.githubusercontent.com/${repo}/main/_worker.js`, { signal: AbortSignal.timeout(15000) }); if (r.ok) { const code = await r.text(); const dr = await deployWorkerToCloudflare(sysConfig.cfAccountId, sysConfig.cfApiToken, sysConfig.cfWorkerName, code); const dres = await dr.json(); if (dres.success) await logActivity(env, "Auto-Update Success", `v${rv}`); } } catch (e) {}
          }
        }
      }
    } catch (e) {}
  }
};

/* ==================== NEW INBOUND API ==================== */
async function handleInboundsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "inbounds");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status, headers:{ "Content-Type":"application/json" } });
    if (method === "GET") {
      const cfg = sysConfig.inboundConfigs || SYSTEM_DEFAULTS.inboundConfigs;
      return new Response(JSON.stringify({
        ok:true, success:true,
        data: {
          config: cfg,
          users: (sysConfig.users || []).map(u => ({ id:u.id, name:u.name, groupId:u.groupId, isp:u.isp || null, tags:u.tags || [] })),
        }
      }), { headers:{ "Content-Type":"application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (!sysConfig.inboundConfigs) sysConfig.inboundConfigs = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs));
      if (body.action === "updateGlobal") {
        sysConfig.inboundConfigs.global = { ...sysConfig.inboundConfigs.global, ...(body.global || {}) };
        if (body.extraEntries) sysConfig.inboundConfigs.extraEntries = body.extraEntries;
        if (body.enabled !== undefined) sysConfig.inboundConfigs.enabled = !!body.enabled;
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true, data:sysConfig.inboundConfigs }), { headers:{ "Content-Type":"application/json" } });
      }
      if (body.action === "updateUser") {
        if (!body.userId) return new Response(JSON.stringify({ ok:false, success:false, error:"userId required" }), { status:400 });
        if (!sysConfig.inboundConfigs.perUser) sysConfig.inboundConfigs.perUser = {};
        sysConfig.inboundConfigs.perUser[body.userId] = {
          enabled: body.enabled !== false,
          nameTemplate: body.nameTemplate || "",
          extraEntries: Array.isArray(body.extraEntries) ? body.extraEntries : [],
        };
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
      if (body.action === "removeUser") {
        if (body.userId && sysConfig.inboundConfigs.perUser?.[body.userId]) {
          delete sysConfig.inboundConfigs.perUser[body.userId];
          await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        }
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
      if (body.action === "addEntry") {
        if (!sysConfig.inboundConfigs.extraEntries) sysConfig.inboundConfigs.extraEntries = [];
        const e = {
          id: generateId("e"),
          text: body.text || "",
          type: body.type || "static",
          enabled: body.enabled !== false,
          position: body.position || "start",
          flagPrefix: body.flagPrefix || "",
        };
        sysConfig.inboundConfigs.extraEntries.push(e);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true, data:e }), { headers:{ "Content-Type":"application/json" } });
      }
      if (body.action === "removeEntry") {
        sysConfig.inboundConfigs.extraEntries = (sysConfig.inboundConfigs.extraEntries || []).filter(e => e.id !== body.id);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
      if (body.action === "updateEntry") {
        const list = sysConfig.inboundConfigs.extraEntries || [];
        const idx = list.findIndex(e => e.id === body.id);
        if (idx === -1) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 });
        list[idx] = { ...list[idx], ...body.data };
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleInboundsActions(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "inbounds");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status });
    const body = await request.json();
    if (body.action === "applyGlobal") {
      // Copy current global config to all users as override
      const cfg = sysConfig.inboundConfigs || {};
      const global = cfg.global || {};
      if (!cfg.perUser) cfg.perUser = {};
      const extraEntries = (cfg.extraEntries || []).map(e => ({ ...e }));
      let applied = 0;
      for (const u of (sysConfig.users || [])) {
        cfg.perUser[u.id] = {
          enabled: true,
          nameTemplate: global.nameTemplate || "{FLAG} {PREFIX}-{INDEX}",
          extraEntries: extraEntries,
        };
        applied++;
      }
      sysConfig.inboundConfigs = cfg;
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok:true, success:true, applied }), { headers:{ "Content-Type":"application/json" } });
    }
    if (body.action === "clearUserOverrides") {
      sysConfig.inboundConfigs.perUser = {};
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok:true, success:true }), { headers:{ "Content-Type":"application/json" } });
    }
    if (body.action === "preview") {
      // Build a sample name using current global config
      const profile = { id:"preview", name: body.userName || "ali", tags: body.tags || ["VIP"] };
      const regionInfo = { id:"de", name:"آلمان", flag:"🇩🇪" };
      const name = buildInboundName(body.type || "alpha", profile, "188.114.96.1", 443, 1, "panel.workers.dev", regionInfo, false);
      return new Response(JSON.stringify({ ok:true, success:true, name }), { headers:{ "Content-Type":"application/json" } });
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

/* ==================== AUTH (with bug fixes) ==================== */
async function handleAuth(request, hostName, ctx, env) {
  try {
    const ip = request.headers.get("cf-connecting-ip") || "Unknown";
    let data = {};
    try { data = await request.json(); } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:"Invalid JSON" }), { status:400, headers:{ "Content-Type":"application/json" } }); }

    // Bug fix: rate limit only counts failures, no auto-ban on first try
    const rlKey = "rl_auth_" + ip;
    let rlData = { count:0, first: Date.now() };
    try {
      const rlRaw = await d1Get(env, rlKey);
      const now = Date.now();
      if (rlRaw) rlData = JSON.parse(rlRaw);
      if (!rlData.first || now - rlData.first > AUTH_WINDOW_MS) rlData = { count:0, first:now };
      if (rlData.count >= AUTH_MAX_ATTEMPTS * 3) {
        return new Response(JSON.stringify({ ok:false, success:false, error:"Too many attempts", retryAfter: Math.ceil((AUTH_WINDOW_MS - (now - rlData.first))/1000) }), { status:429, headers:{ "Content-Type":"application/json" } });
      }
    } catch (e) {} // if D1 fails, allow the login attempt

    const username = data.username || "";
    const password = data.password || "";
    const legacyKey = data.key || "";
    let mgr = null, authType = "password";

    if (legacyKey) {
      if (legacyKey === sysConfig.masterKey) { mgr = { username:"admin", isRoot:true, permissions:["all"], id:"root-admin" }; authType = "master-key"; }
      else if (isPanelApiKey(legacyKey)) { mgr = { username:"apikey", isRoot:false, permissions:ALL_PERMISSIONS, id:"apikey" }; authType = "api-key"; }
      else return new Response(JSON.stringify({ ok:false, success:false, error:"Invalid key" }), { status:401, headers:{ "Content-Type":"application/json" } });
    } else {
      if (!username || !password) return new Response(JSON.stringify({ ok:false, success:false, error:"نام کاربری و رمز عبور الزامی است" }), { status:400, headers:{ "Content-Type":"application/json" } });
      try {
        mgr = await verifyManagerCredentials(username, password);
      } catch (e) { mgr = null; }
      if (!mgr) {
        try { rlData.count++; await d1Put(env, rlKey, JSON.stringify(rlData)); } catch (e) {}
        ctx?.waitUntil(triggerWebhook(env, ctx, "auth.failed", { username, ip }).catch(() => {}));
        return new Response(JSON.stringify({ ok:false, success:false, error:"نام کاربری یا رمز عبور اشتباه است" }), { status:401, headers:{ "Content-Type":"application/json" } });
      }
    }
    if (mgr && mgr.id) {
      try {
        const f = sysConfig.managers.find(m => m.id === mgr.id);
        if (f) { f.lastLogin = Date.now(); cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(() => {}); }
      } catch (e) {}
    }
    const sess = await createSession(env, mgr, request);
    try { await d1Put(env, rlKey, ""); } catch (e) {}
    ctx?.waitUntil(triggerWebhook(env, ctx, "auth.success", { username: mgr.username, ip }).catch(() => {}));

    let exposed = { ...sysConfig };
    if (!sess.isRoot) exposed = { ...sysConfig, cfApiToken:"", tgToken:"", syncApiKey:"", masterKey:"[PROTECTED]" };
    for (const f of SENSITIVE_FIELDS) if (exposed[f] && String(exposed[f]).startsWith("enc:")) exposed[f] = "";
    exposed.managers = undefined;
    exposed.panelApiKeys = sess.isRoot ? (sysConfig.panelApiKeys || []) : [];

    return new Response(JSON.stringify({
      ok:true, success:true,
      data:{ session:{ token:sess.token, username:sess.username, isRoot:sess.isRoot, permissions:sess.permissions, expiresAt:sess.expiresAt }, config: exposed, version: CURRENT_VERSION, apiRoute: sysConfig.apiRoute, network:{ ip } },
    }), { status:200, headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:"Server error: " + e.message }), { status:500, headers:{ "Content-Type":"application/json" } }); }
}

async function handleLogout(request, env) {
  try { const auth = request.headers.get("Authorization") || ""; const token = auth.replace("Bearer ","").trim(); if (token) await destroySession(env, token); return new Response(JSON.stringify({ ok:true, success:true }), { headers:{ "Content-Type":"application/json" } }); } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
}
async function handleMe(request, env) {
  try {
    const ctx = await getAuthContext(request, env, null);
    if (!ctx) return new Response(JSON.stringify({ ok:false, success:false, error:"Unauthorized" }), { status:401, headers:{ "Content-Type":"application/json" } });
    let exposed = { ...sysConfig };
    if (!ctx.isRoot) exposed = { ...sysConfig, cfApiToken:"", tgToken:"", syncApiKey:"", masterKey:"[PROTECTED]" };
    for (const f of SENSITIVE_FIELDS) if (exposed[f] && String(exposed[f]).startsWith("enc:")) exposed[f] = "";
    exposed.managers = undefined;
    exposed.panelApiKeys = ctx.isRoot ? (sysConfig.panelApiKeys || []) : [];
    return new Response(JSON.stringify({ ok:true, success:true, data:{ username:ctx.username, isRoot:ctx.isRoot, permissions:ctx.permissions, type:ctx.type, config: exposed, version: CURRENT_VERSION } }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
}
async function handleConfigSync(request, env, ctx) {
  try {
    const data = await request.json();
    const authCtx = await getAuthContext(request, env, data);
    const isAuthSync = (authCtx && (authCtx.isRoot || hasPermission(authCtx, "settings"))) || (data.key === sysConfig.masterKey) || isPanelApiKey(data.key) || (data.fromMaster && data.config && data.config.masterKey && data.config.masterKey === sysConfig.masterKey);
    if (!isAuthSync) return new Response(JSON.stringify({ ok:false, success:false, error:"Unauthorized" }), { status:401, headers:{ "Content-Type":"application/json" } });
    if (!env.IOT_DB) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
    let nextConfig = sysConfig;
    if (data.config) {
      const preserveApiKeys = sysConfig.panelApiKeys || [];
      const preserveManagers = sysConfig.managers || [];
      nextConfig = { ...sysConfig, ...data.config };
      if (Array.isArray(nextConfig.users)) nextConfig.users = nextConfig.users.map(u => ({...u}));
      if (preserveApiKeys.length > 0 && (!data.config.panelApiKeys || data.config.panelApiKeys.length === 0)) nextConfig.panelApiKeys = preserveApiKeys;
      if (!data.config.managers) nextConfig.managers = preserveManagers;
      migrateSlaveNodesToLinkedPanels(nextConfig);
      if (Array.isArray(nextConfig.users)) for (const u of nextConfig.users) { if (u.proxyIp) await resolveUserProxyIpGeo(u); else u.proxyIpGeo = null; }
      const toSave = await encryptSensitiveInConfig(nextConfig, nextConfig.masterKey || "admin");
      sysConfig = nextConfig;
      await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    }
    if (nextConfig.tgToken && ctx) { const hook = `https://${new URL(request.url).hostname}/${encodeURI(nextConfig.apiRoute)}/tg`; ctx.waitUntil(fetch(`https://api.telegram.org/bot${nextConfig.tgToken}/setWebhook`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ url:hook }), signal: AbortSignal.timeout(8000) }).catch(() => {})); }
    return new Response(JSON.stringify({ ok:true, success:true, newRoute: nextConfig.apiRoute }), { status:200 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
}
async function handleSyncPanel(request, env, ctx) {
  try {
    const data = await request.json();
    if (!data || data.signal !== "panel_login") return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
    const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
    if (!adminId || adminId.toString() !== String(data.tgAdminId)) return new Response(JSON.stringify({ ok:false, success:false }), { status:401 });
    if (env.IOT_DB) ctx?.waitUntil(d1Put(env, "tg_panel_login", JSON.stringify({ name:data.panelName||data.panelHost, host:data.panelHost, apiRoute:data.panelApiRoute||sysConfig.apiRoute, isLocal:false, ts:Date.now() })).catch(() => {}));
    return new Response(JSON.stringify({ ok:true, success:true }));
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
}

/* ==================== HANDLERS (rest, with bug fixes) ==================== */
async function handleLogs(request, env) {
  try {
    if (request.method === "POST") {
      const data = await request.json();
      const perm = await requirePermission(request, env, data, "logs");
      if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status, headers:{ "Content-Type":"application/json" } });
      let logs = [];
      if (env.IOT_DB) { const s = await d1Get(env, "sys_logs"); if (s) logs = JSON.parse(s); }
      return new Response(JSON.stringify({ ok:true, success:true, logs }), { status:200, headers:{ "Content-Type":"application/json" } });
    }
    return new Response("OK", { status:200 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
}

async function handleUsersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const userId = url.searchParams.get("id");
    const action = url.searchParams.get("action");
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status, headers:{ "Content-Type":"application/json" } });

    if (method === "GET" && !userId) {
      const q = (url.searchParams.get("q") || "").toLowerCase();
      const groupFilter = url.searchParams.get("group");
      const ispFilter = url.searchParams.get("isp");
      let users = sysConfig.users || [];
      if (q) users = users.filter(u => u.name.toLowerCase().includes(q) || u.id.toLowerCase().includes(q) || (u.notes && u.notes.toLowerCase().includes(q)));
      if (groupFilter) users = users.filter(u => (u.groupId || "default") === groupFilter);
      if (ispFilter) users = users.filter(u => (u.isp || "") === ispFilter);
      const enriched = users.map(u => {
        const idClean = u.id.replace(/-/g,"").toLowerCase();
        const sysU = sysUsageCache?.users?.[idClean] || { reqs:0, dReqs:0, lastDay:"" };
        const usedBytes = Math.floor((sysU.reqs||0) * (1073741824/6000));
        const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824/6000)) : 0;
        const isExpired = u.expiryMs && Date.now() > u.expiryMs;
        let status = "active";
        if (u.isPaused && u.disabledReason) status = "auto-disabled";
        else if (u.isPaused) status = "paused";
        else if (isExpired) status = "expired";
        return { ...u, usage:{ total:usedBytes, limit:limitBytes, daily:sysU.dReqs||0, dailyLimit:u.limitDailyReq||0 }, status };
      });
      return new Response(JSON.stringify({ ok:true, success:true, data:enriched, users:enriched, meta:{ total: enriched.length } }), { headers:{ "Content-Type":"application/json" } });
    }

    if (method === "GET" && userId) {
      const u = (sysConfig.users || []).find(usr => usr.id === userId || usr.name.toLowerCase() === userId.toLowerCase());
      if (!u) return new Response(JSON.stringify({ ok:false, success:false, error:"Not found" }), { status:404 });
      const idClean = u.id.replace(/-/g,"").toLowerCase();
      const sysU = sysUsageCache?.users?.[idClean] || { reqs:0, dReqs:0, lastDay:"" };
      const usedBytes = Math.floor((sysU.reqs||0) * (1073741824/6000));
      const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824/6000)) : 0;
      const isExpired = u.expiryMs && Date.now() > u.expiryMs;
      let status = "active";
      if (u.isPaused && u.disabledReason) status = "auto-disabled";
      else if (u.isPaused) status = "paused";
      else if (isExpired) status = "expired";
      const host = new URL(request.url).hostname;
      const subUrl = `https://${host}/${sysConfig.apiRoute}?sub=${encodeURIComponent(u.name)}`;
      return new Response(JSON.stringify({ ok:true, success:true, data:{ ...u, usage:{ total:usedBytes, limit:limitBytes, daily:sysU.dReqs||0, dailyLimit:u.limitDailyReq||0 }, status, subscriptionUrl:subUrl } }), { headers:{ "Content-Type":"application/json" } });
    }

    if (method === "POST" && !userId) {
      const body = await request.json();
      const { name, trafficLimit, expiryDays, notes, maxConfigs, proxyIp, cleanIp, userMode, userPorts, userNodes, nat64, connLimit, userPanelUrl, groupId, autoReset, isp, bandwidthKbps, tags } = body;
      if (!name) return new Response(JSON.stringify({ ok:false, success:false, error:"Name required" }), { status:400 });
      const newId = generateId("u");
      const grp = (sysConfig.userGroups || []).find(g => g.id === (groupId || "default")) || {};
      const newUser = {
        id:newId, name, groupId: groupId || "default", isp: isp || null,
        tags: Array.isArray(tags) ? tags : [],
        bandwidthKbps: bandwidthKbps ? parseInt(bandwidthKbps) : null,
        limitTotalReq: trafficLimit ? Math.floor(parseFloat(trafficLimit)*6000) : (grp.limitTotalGb ? Math.floor(grp.limitTotalGb*6000) : null),
        limitDailyReq: body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit)*6000) : (grp.limitDailyGb ? Math.floor(grp.limitDailyGb*6000) : null),
        expiryMs: expiryDays ? Date.now() + parseInt(expiryDays)*86400000 : (grp.expiryDays ? Date.now() + grp.expiryDays*86400000 : null),
        notes: notes||"", maxConfigs: maxConfigs ? parseInt(maxConfigs) : (grp.maxConfigs || null),
        connLimit: connLimit ? parseInt(connLimit) : (grp.connLimit || null),
        proxyIp: proxyIp||null, cleanIp: cleanIp||null, userMode: userMode||null,
        userPorts: userPorts||null, userNodes: userNodes||null, nat64: nat64||null,
        userPanelUrl: userPanelUrl||null, createdAt: Date.now(),
      };
      await resolveUserProxyIpGeo(newUser);
      if (!sysConfig.users) sysConfig.users = [];
      sysConfig.users.push(newUser);
      if (autoReset && autoReset.type && autoReset.type !== "none") {
        if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
        sysConfig.autoResetCycles[newId] = { type:autoReset.type, lastReset: Date.now() };
      }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      ctx?.waitUntil(logActivity(env, "User Created", `${name}`).catch(() => {}));
      ctx?.waitUntil(triggerWebhook(env, ctx, "user.created", { userId:newId, name }).catch(() => {}));
      ctx?.waitUntil(fireWorkflows(env, ctx, "user.created", { userId:newId, name, groupId:newUser.groupId }).catch(() => {}));
      return new Response(JSON.stringify({ ok:true, success:true, data:newUser, user:newUser }), { status:201, headers:{ "Content-Type":"application/json" } });
    }

    if (method === "PUT" && userId) {
      const body = await request.json();
      const u = (sysConfig.users || []).find(x => x.id === userId);
      if (!u) return new Response(JSON.stringify({ ok:false, success:false, error:"Not found" }), { status:404 });
      if (body.name !== undefined) u.name = body.name;
      if (body.groupId !== undefined) u.groupId = body.groupId;
      if (body.isp !== undefined) u.isp = body.isp || null;
      if (body.tags !== undefined) u.tags = Array.isArray(body.tags) ? body.tags : [];
      if (body.bandwidthKbps !== undefined) u.bandwidthKbps = body.bandwidthKbps ? parseInt(body.bandwidthKbps) : null;
      if (body.trafficLimit !== undefined) u.limitTotalReq = body.trafficLimit ? Math.floor(parseFloat(body.trafficLimit)*6000) : null;
      if (body.dailyLimit !== undefined) u.limitDailyReq = body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit)*6000) : null;
      if (body.expiryDays !== undefined) u.expiryMs = body.expiryDays ? Date.now() + parseInt(body.expiryDays)*86400000 : null;
      if (body.notes !== undefined) u.notes = body.notes;
      if (body.maxConfigs !== undefined) u.maxConfigs = body.maxConfigs ? parseInt(body.maxConfigs) : null;
      if (body.proxyIp !== undefined) { u.proxyIp = body.proxyIp; if (!body.proxyIp) u.proxyIpGeo = null; else await resolveUserProxyIpGeo(u); }
      if (body.cleanIp !== undefined) u.cleanIp = body.cleanIp;
      if (body.userMode !== undefined) u.userMode = body.userMode;
      if (body.userPorts !== undefined) u.userPorts = body.userPorts;
      if (body.userNodes !== undefined) u.userNodes = body.userNodes;
      if (body.nat64 !== undefined) u.nat64 = body.nat64;
      if (body.connLimit !== undefined) u.connLimit = body.connLimit ? parseInt(body.connLimit) : null;
      if (body.userPanelUrl !== undefined) u.userPanelUrl = body.userPanelUrl || null;
      if (body.status !== undefined) {
        if (body.status === "active") { u.isPaused = false; u.disabledReason = null; u.disabledAt = null; }
        else if (body.status === "paused") { u.isPaused = true; u.disabledReason = null; u.disabledAt = null; }
      }
      if (body.autoReset !== undefined) {
        if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
        if (body.autoReset.type && body.autoReset.type !== "none") sysConfig.autoResetCycles[userId] = { type:body.autoReset.type, lastReset: Date.now() };
        else delete sysConfig.autoResetCycles[userId];
      }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      ctx?.waitUntil(triggerWebhook(env, ctx, "user.updated", { userId, name:u.name }).catch(() => {}));
      return new Response(JSON.stringify({ ok:true, success:true, data:u, user:u }), { headers:{ "Content-Type":"application/json" } });
    }

    if (method === "DELETE" && userId) {
      const idx = (sysConfig.users || []).findIndex(x => x.id === userId);
      if (idx === -1) return new Response(JSON.stringify({ ok:false, success:false, error:"Not found" }), { status:404 });
      const deleted = sysConfig.users.splice(idx, 1)[0];
      if (sysConfig.autoResetCycles && sysConfig.autoResetCycles[userId]) delete sysConfig.autoResetCycles[userId];
      if (sysConfig.inboundConfigs?.perUser?.[userId]) delete sysConfig.inboundConfigs.perUser[userId];
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      ctx?.waitUntil(triggerWebhook(env, ctx, "user.deleted", { userId, name:deleted.name }).catch(() => {}));
      return new Response(JSON.stringify({ ok:true, success:true }), { headers:{ "Content-Type":"application/json" } });
    }

    if (method === "POST" && userId && action === "toggle") {
      const u = (sysConfig.users || []).find(x => x.id === userId);
      if (!u) return new Response(JSON.stringify({ ok:false, success:false, error:"Not found" }), { status:404 });
      u.isPaused = !u.isPaused;
      if (!u.isPaused) { u.disabledReason = null; u.disabledAt = null; }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok:true, success:true, data:u, user:u }), { headers:{ "Content-Type":"application/json" } });
    }

    if (method === "POST" && userId && action === "reset") {
      if (!sysUsageCache.users) sysUsageCache.users = {};
      const c = userId.replace(/-/g,"").toLowerCase();
      if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; }
      else sysUsageCache.users[c] = { reqs:0, dReqs:0, lastDay: todayStr() };
      await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
      return new Response(JSON.stringify({ ok:true, success:true }), { headers:{ "Content-Type":"application/json" } });
    }
    return new Response(JSON.stringify({ ok:false, success:false, error:"Invalid" }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500, headers:{ "Content-Type":"application/json" } }); }
}

async function handleBulkUsers(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") {
      let csv = "name,groupId,isp,trafficLimitGB,dailyLimitGB,expiryDays,maxConfigs,connLimit,bandwidthKbps,notes\n";
      for (const u of (sysConfig.users || [])) {
        csv += [`"${(u.name||"").replace(/"/g,'""')}"`, u.groupId||"default", u.isp||"", u.limitTotalReq?(u.limitTotalReq/6000).toFixed(2):"0", u.limitDailyReq?(u.limitDailyReq/6000).toFixed(2):"0", u.expiryMs?Math.max(0,Math.ceil((u.expiryMs-Date.now())/86400000)):"0", u.maxConfigs||"0", u.connLimit||"0", u.bandwidthKbps||"0", `"${(u.notes||"").replace(/"/g,'""')}"`].join(",") + "\n";
      }
      return new Response(csv, { headers:{ "Content-Type":"text/csv; charset=utf-8", "Content-Disposition":`attachment; filename="users-${Date.now()}.csv"` } });
    }
    if (method === "POST") {
      const body = await request.json();
      const csv = body.csv || "";
      const lines = csv.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      if (lines.length < 2) return new Response(JSON.stringify({ ok:false, success:false, error:"Empty CSV" }), { status:400 });
      const created = [], errors = [];
      for (let i = 1; i < lines.length; i++) {
        try {
          const cols = parseCsvLine(lines[i]);
          const name = (cols[0]||"").replace(/^"|"$/g,"").trim();
          if (!name) { errors.push(`Line ${i+1}: empty`); continue; }
          if ((sysConfig.users||[]).some(u => u.name.toLowerCase() === name.toLowerCase())) { errors.push(`Line ${i+1}: duplicate`); continue; }
          const newId = generateId("u");
          const newUser = { id:newId, name, groupId: cols[1]||"default", isp: cols[2]||null, limitTotalReq: parseFloat(cols[3])>0?Math.floor(parseFloat(cols[3])*6000):null, limitDailyReq: parseFloat(cols[4])>0?Math.floor(parseFloat(cols[4])*6000):null, expiryMs: parseInt(cols[5])>0?Date.now()+parseInt(cols[5])*86400000:null, maxConfigs: parseInt(cols[6])>0?parseInt(cols[6]):null, connLimit: parseInt(cols[7])>0?parseInt(cols[7]):null, bandwidthKbps: parseInt(cols[8])>0?parseInt(cols[8]):null, notes: (cols[9]||"").replace(/^"|"$/g,"").trim(), createdAt: Date.now() };
          if (!sysConfig.users) sysConfig.users = [];
          sysConfig.users.push(newUser);
          created.push(name);
        } catch (e) { errors.push(`Line ${i+1}: ${e.message}`); }
      }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok:true, success:true, created:created.length, errors }), { headers:{ "Content-Type":"application/json" } });
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}
function parseCsvLine(line) {
  const out = []; let cur = "", inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { if (inQ && line[i+1] === '"') { cur += '"'; i++; } else inQ = !inQ; }
    else if (c === "," && !inQ) { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

async function handleGroupsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "groups");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.userGroups || [], groups: sysConfig.userGroups || [] }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      const groups = sysConfig.userGroups || [];
      if (body.action === "create" || body.action === "update") {
        const g = { id: body.id || generateId("g"), name: body.name || "بدون نام", limitTotalGb: parseFloat(body.limitTotalGb)||0, limitDailyGb: parseFloat(body.limitDailyGb)||0, expiryDays: parseInt(body.expiryDays)||0, maxConfigs: parseInt(body.maxConfigs)||0, connLimit: parseInt(body.connLimit)||0, color: body.color || "#8b5cf6" };
        if (body.action === "create") groups.push(g);
        else { const i = groups.findIndex(x => x.id === g.id); if (i === -1) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); groups[i] = g; }
        sysConfig.userGroups = groups;
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true, data:g }));
      }
      if (body.action === "delete") {
        if (body.id === "default") return new Response(JSON.stringify({ ok:false, success:false, error:"Cannot delete default" }), { status:400 });
        sysConfig.userGroups = groups.filter(g => g.id !== body.id);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleManagersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const mgrId = url.searchParams.get("id");
    const perm = await requirePermission(request, env, null, "managers");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status });
    await ensureRootManager();
    if (method === "GET" && !mgrId) {
      const list = (sysConfig.managers || []).map(m => ({ id:m.id, username:m.username, permissions:m.permissions || [], isRoot:m.isRoot === true, isActive:m.isActive !== false, createdAt:m.createdAt, lastLogin:m.lastLogin, createdBy:m.createdBy }));
      return new Response(JSON.stringify({ ok:true, success:true, data:list, managers:list }), { headers:{ "Content-Type":"application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") {
        const { username, password, permissions } = body;
        if (!username || !password) return new Response(JSON.stringify({ ok:false, success:false, error:"نام و رمز الزامی" }), { status:400 });
        if (String(username).length < 3) return new Response(JSON.stringify({ ok:false, success:false, error:"حداقل ۳ کاراکتر" }), { status:400 });
        if (String(password).length < 4) return new Response(JSON.stringify({ ok:false, success:false, error:"حداقل ۴ کاراکتر" }), { status:400 });
        if (sysConfig.managers.some(m => m.username.toLowerCase() === String(username).toLowerCase())) return new Response(JSON.stringify({ ok:false, success:false, error:"نام کاربری موجود" }), { status:400 });
        const salt = generateSalt();
        const ph = await hashPassword(password, salt);
        const perms = Array.isArray(permissions) && permissions.length > 0 ? permissions.filter(p => ALL_PERMISSIONS.includes(p)) : ["users"];
        const newMgr = { id:generateId("m"), username:String(username), passwordHash:ph, salt, permissions:perms, isRoot:false, isActive:true, createdAt:Date.now(), lastLogin:null, createdBy:perm.ctx.username };
        sysConfig.managers.push(newMgr);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true, data:{ id:newMgr.id, username:newMgr.username, permissions:newMgr.permissions } }), { status:201 });
      }
      if (body.action === "update") {
        const { id, password, permissions, isActive } = body;
        const m = sysConfig.managers.find(x => x.id === id);
        if (!m) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 });
        if (password && String(password).length >= 4) { m.salt = generateSalt(); m.passwordHash = await hashPassword(password, m.salt); }
        if (Array.isArray(permissions)) m.permissions = permissions.filter(p => ALL_PERMISSIONS.includes(p));
        if (isActive !== undefined) { if (m.isRoot && !isActive) return new Response(JSON.stringify({ ok:false, success:false, error:"Root غیرفعال نمی‌شود" }), { status:400 }); m.isActive = !!isActive; }
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
      if (body.action === "delete") {
        const idx = (sysConfig.managers || []).findIndex(x => x.id === body.id);
        if (idx === -1) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 });
        if (sysConfig.managers[idx].isRoot) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
        sysConfig.managers.splice(idx, 1);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true }));
      }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleStatsApi(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status });
    const users = sysConfig.users || [];
    const total = users.length;
    const active = users.filter(u => !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs)).length;
    const autoOff = users.filter(u => u.isPaused && u.disabledReason).length;
    const paused = users.filter(u => u.isPaused && !u.disabledReason).length;
    const expired = users.filter(u => u.expiryMs && Date.now() > u.expiryMs && !u.isPaused).length;
    let totalReqs = 0, dailyReqs = 0;
    const today = todayStr();
    users.forEach(u => { const c = u.id.replace(/-/g,"").toLowerCase(); const sysU = sysUsageCache?.users?.[c] || { reqs:0, dReqs:0, lastDay:"" }; totalReqs += sysU.reqs || 0; if (sysU.lastDay === today) dailyReqs += sysU.dReqs || 0; });
    const topUsers = users.map(u => { const c = u.id.replace(/-/g,"").toLowerCase(); const s = sysUsageCache?.users?.[c] || { reqs:0 }; return { name:u.name, gb: parseFloat(((s.reqs||0)/6000).toFixed(2)) }; }).sort((a,b) => b.gb - a.gb).slice(0, 5);
    const payload = { users:{ total, active, paused, expired, autoDisabled:autoOff }, traffic:{ totalRequests: totalReqs, totalGB:(totalReqs/6000).toFixed(2), dailyRequests: dailyReqs, dailyGB:(dailyReqs/6000).toFixed(2) }, system:{ uptimeSeconds: Math.floor((Date.now()-isolateStartTime)/1000), activeConnections, version: CURRENT_VERSION, isPaused: sysConfig.isPaused || false, topUsers } };
    return new Response(JSON.stringify({ ok:true, success:true, data:payload, stats:payload }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}
async function handleHistoryApi(request, env) {
  try {
    const url = new URL(request.url);
    const userId = url.searchParams.get("id");
    const days = Math.min(parseInt(url.searchParams.get("days") || "7"), 30);
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (userId) {
      const u = (sysConfig.users || []).find(x => x.id === userId || x.name === userId);
      if (!u) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 });
      const c = u.id.replace(/-/g,"").toLowerCase();
      return new Response(JSON.stringify({ ok:true, success:true, user:u.name, series: getHistorySeries(c, days) }), { headers:{ "Content-Type":"application/json" } });
    }
    return new Response(JSON.stringify({ ok:true, success:true, series: getTotalHistorySeries(days) }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleCompareApi(request, env) {
  try {
    const url = new URL(request.url);
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const userIds = (url.searchParams.get("ids") || "").split(",").filter(Boolean);
    const days = Math.min(parseInt(url.searchParams.get("days") || "14"), 30);
    const series = {};
    for (const uid of userIds) { const u = (sysConfig.users || []).find(x => x.id === uid); if (!u) continue; const c = u.id.replace(/-/g,"").toLowerCase(); series[u.name] = getHistorySeries(c, days); }
    return new Response(JSON.stringify({ ok:true, success:true, series, days }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleAnomaliesApi(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const anomalies = await detectAnomalies();
    return new Response(JSON.stringify({ ok:true, success:true, data:anomalies, anomalies }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleSessions(request, env) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "managers");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") {
      const sess = await listSessions(env);
      return new Response(JSON.stringify({ ok:true, success:true, data: sess.map(s => ({ token:s.token.slice(0,15)+"...", fullToken:s.token, username:s.username, ip:s.ip, ua:s.ua, createdAt:s.createdAt, expiresAt:s.expiresAt, isRoot:s.isRoot, current: s.token === perm.ctx.token })), sessions: sess }), { headers:{ "Content-Type":"application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "revoke" && body.token) {
        const sess = await listSessions(env);
        const found = sess.find(s => s.token === body.token || s.token.startsWith(String(body.token).replace("...","")));
        if (found) { await destroySession(env, found.token); return new Response(JSON.stringify({ ok:true, success:true })); }
        return new Response(JSON.stringify({ ok:false, success:false }), { status:404 });
      }
      if (body.action === "revokeAll") {
        const sess = await listSessions(env);
        for (const s of sess) if (s.token !== perm.ctx.token) await destroySession(env, s.token);
        return new Response(JSON.stringify({ ok:true, success:true, revoked: sess.length - 1 }));
      }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleNodesApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "nodes");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") {
      const nodes = [];
      if (Array.isArray(sysConfig.linkedPanels)) for (const p of sysConfig.linkedPanels) nodes.push({ url:p.url, apiKey: p.apiKey ? "[SET]" : null, name:p.name || p.url, group:p.group || "default", lastHealth:p.lastHealth || null });
      return new Response(JSON.stringify({ ok:true, success:true, data:nodes, nodes }), { headers:{ "Content-Type":"application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "add") { if (!sysConfig.linkedPanels) sysConfig.linkedPanels = []; let cleanUrl = (body.url || "").trim(); if (!cleanUrl.startsWith("http")) cleanUrl = "https://" + cleanUrl; sysConfig.linkedPanels.push({ url:cleanUrl, apiKey:body.apiKey || "", name: body.name || cleanUrl, group: body.group || "default" }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "remove") { sysConfig.linkedPanels = (sysConfig.linkedPanels || []).filter(p => p.url !== body.url); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleNodeHealth(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "nodes");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const results = await runNodeHealthCheck(env);
    return new Response(JSON.stringify({ ok:true, success:true, data:results, results }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function runNodeHealthCheck(env) {
  const nodes = sysConfig.linkedPanels || [];
  const results = [];
  for (const node of nodes) {
    try {
      let clean = node.url.trim(); if (!clean.startsWith("http")) clean = "https://" + clean;
      const parsed = new URL(clean);
      const testUrl = `${parsed.protocol}//${parsed.host}/${encodeURI(sysConfig.apiRoute)}/api/stats?key=${encodeURIComponent(node.apiKey || "")}`;
      const start = Date.now();
      const res = await fetch(testUrl, { signal: AbortSignal.timeout(8000) });
      const latency = Date.now() - start;
      const json = await res.json().catch(() => ({}));
      node.lastHealth = { status: res.ok && (json.ok || json.success) ? "online" : "error", latency, ts: Date.now() };
      results.push({ url: node.url, status: node.lastHealth.status, latency });
    } catch (e) { node.lastHealth = { status: "offline", latency: -1, ts: Date.now(), error: e.message }; results.push({ url: node.url, status: "offline", latency: -1 }); }
  }
  if (env.IOT_DB) await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return results;
}

async function handleRegionsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data:{ regions: sysConfig.cleanIpRegions || [], active: sysConfig.activeCleanRegions || [], mode: sysConfig.cleanRegionMode || "round-robin" } }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "update") { sysConfig.cleanIpRegions = body.regions || []; sysConfig.activeCleanRegions = body.active || []; if (body.mode) sysConfig.cleanRegionMode = body.mode; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "add") { if (!sysConfig.cleanIpRegions) sysConfig.cleanIpRegions = []; sysConfig.cleanIpRegions.push({ id: body.id || generateId("r"), name: body.name || "جدید", flag: body.flag || "🌐", ips: (body.ips || "").split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean) }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "delete") { sysConfig.cleanIpRegions = (sysConfig.cleanIpRegions || []).filter(r => r.id !== body.id); sysConfig.activeCleanRegions = (sysConfig.activeCleanRegions || []).filter(r => r !== body.id); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "toggle") { const active = sysConfig.activeCleanRegions || []; if (active.includes(body.id)) sysConfig.activeCleanRegions = active.filter(x => x !== body.id); else sysConfig.activeCleanRegions = [...active, body.id]; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, active: sysConfig.activeCleanRegions })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleCleanIpTest(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const results = await runCleanIpTest(env);
    return new Response(JSON.stringify({ ok:true, success:true, data:results, results }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleCleanIpResults(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.autoCleanIpCache || { ips:[], testedAt:0 } }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function runCleanIpTest(env) {
  lastCleanIpTest = Date.now();
  const candidates = [];
  const ranges = ["104.16.0.0","104.17.0.0","104.18.0.0","104.19.0.0","104.20.0.0","104.21.0.0","104.22.0.0","104.23.0.0","104.24.0.0","104.25.0.0","104.26.0.0","104.27.0.0","172.64.0.0","172.65.0.0","172.66.0.0","172.67.0.0","188.114.96.1","188.114.97.1","197.234.240.1","103.21.244.1"];
  const custom = (sysConfig.cleanIps || "").split(/[\r\n,;]+/).map(s => s.trim().split("#")[0].trim()).filter(Boolean);
  const pool = [...new Set([...custom, ...ranges])];
  for (const ip of pool.slice(0, 25)) {
    try { const start = Date.now(); const res = await fetch(`https://${ip}/cdn-cgi/trace`, { method:"GET", signal: AbortSignal.timeout(4000), headers:{ Host: sysConfig.metricNode || "time.is" } }); const latency = Date.now() - start; if (res.ok) { const txt = await res.text(); if (txt.includes("h=")) candidates.push({ ip, latency }); } } catch (e) {}
  }
  candidates.sort((a,b) => a.latency - b.latency);
  const top = candidates.slice(0, sysConfig.autoCleanIpTopN || 5).map(c => c.ip);
  sysConfig.autoCleanIpCache = { ips: top, testedAt: Date.now(), full: candidates };
  if (env.IOT_DB) await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return candidates;
}

async function handleBackupApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") { const list = await listBackups(env); return new Response(JSON.stringify({ ok:true, success:true, data:list, backups:list }), { headers:{ "Content-Type":"application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { const key = await backupToR2(env, { encrypt: body.encrypt }); return new Response(JSON.stringify({ ok:!!key, success:!!key, key }), { headers:{ "Content-Type":"application/json" } }); }
      if (body.action === "restore") { const res = await restoreFromR2(env, body.key); return new Response(JSON.stringify(res)); }
      if (body.action === "delete") { if (env.BACKUP_BUCKET && body.key) { try { await env.BACKUP_BUCKET.delete(body.key); return new Response(JSON.stringify({ ok:true, success:true })); } catch (e) {} } return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleConfigExport(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const data = { version: CURRENT_VERSION, ts: new Date().toISOString(), config: sysConfig, usage: sysUsageCache, history: sysHistoryCache };
    return new Response(JSON.stringify(data, null, 2), { headers:{ "Content-Type":"application/json", "Content-Disposition":`attachment; filename="hamed-panel-backup-${Date.now()}.json"` } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleConfigImport(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const body = await request.json();
    if (!body.data || !body.data.config) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
    const preserve = { managers: sysConfig.managers, panelApiKeys: sysConfig.panelApiKeys };
    sysConfig = { ...SYSTEM_DEFAULTS, ...body.data.config, ...preserve };
    if (body.data.usage) sysUsageCache = body.data.usage;
    if (body.data.history) sysHistoryCache = body.data.history;
    const toSave = await encryptSensitiveInConfig(sysConfig, sysConfig.masterKey || "admin");
    await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
    await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache));
    return new Response(JSON.stringify({ ok:true, success:true }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleBroadcast(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const body = await request.json();
    if (!body.message) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
    if (!sysConfig.tgToken) return new Response(JSON.stringify({ ok:false, success:false, error:"Telegram not configured" }), { status:400 });
    const r = await sendCrisisBroadcast(env, body.message, "custom");
    return new Response(JSON.stringify(r), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleCronJobsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "cron");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.cronJobs || [], jobs: sysConfig.cronJobs || [], actions: Object.keys(CRON_ACTIONS).map(k => ({ id:k, ...CRON_ACTIONS[k] })) }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.cronJobs) sysConfig.cronJobs = []; const j = { id:generateId("c"), name: body.name || "Job", action: body.jobAction || "send-telegram", params: body.params || {}, intervalMinutes: parseInt(body.intervalMinutes)||60, enabled: body.enabled !== false, createdAt: Date.now(), lastRun: null }; sysConfig.cronJobs.push(j); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, data:j })); }
      if (body.action === "update") { const j = (sysConfig.cronJobs || []).find(x => x.id === body.id); if (!j) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); if (body.name !== undefined) j.name = body.name; if (body.params !== undefined) j.params = body.params; if (body.intervalMinutes !== undefined) j.intervalMinutes = parseInt(body.intervalMinutes); if (body.enabled !== undefined) j.enabled = !!body.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "delete") { sysConfig.cronJobs = (sysConfig.cronJobs || []).filter(x => x.id !== body.id); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "run") { const j = (sysConfig.cronJobs || []).find(x => x.id === body.id); if (!j) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); await runCronJob(env, ctx, j); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, status: j.lastStatus })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleWebhooksApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "webhooks");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.webhooks || [], webhooks: sysConfig.webhooks || [], events: WEBHOOK_EVENTS }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.webhooks) sysConfig.webhooks = []; if (sysConfig.webhooks.length >= 10) return new Response(JSON.stringify({ ok:false, success:false, error:"Max 10" }), { status:400 }); const w = { id:generateId("wh"), url: body.url, events: (body.events||[]).filter(e => WEBHOOK_EVENTS.includes(e)), secret: body.secret || generateSalt(), enabled: body.enabled !== false, createdAt: Date.now() }; sysConfig.webhooks.push(w); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, data:w })); }
      if (body.action === "update") { const w = (sysConfig.webhooks || []).find(x => x.id === body.id); if (!w) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); if (body.url !== undefined) w.url = body.url; if (body.events !== undefined) w.events = body.events.filter(e => WEBHOOK_EVENTS.includes(e)); if (body.enabled !== undefined) w.enabled = !!body.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "delete") { sysConfig.webhooks = (sysConfig.webhooks || []).filter(x => x.id !== body.id); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "test") { const w = (sysConfig.webhooks || []).find(x => x.id === body.id); if (!w) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); const payload = JSON.stringify({ event:"test", timestamp:Date.now(), version:CURRENT_VERSION, data:{ message:"Test" } }); const sig = await hmacSign(w.secret, payload); try { const r = await fetch(w.url, { method:"POST", headers:{ "Content-Type":"application/json", "X-Hamed-Event":"test", "X-Hamed-Signature":"sha256=" + sig }, body:payload, signal: AbortSignal.timeout(8000) }); return new Response(JSON.stringify({ ok:true, success:true, status: r.status })); } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error: e.message })); } }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleBannedApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") { const list = await listBannedIps(env); return new Response(JSON.stringify({ ok:true, success:true, data:list, banned:list }), { headers:{ "Content-Type":"application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "ban") { await banIp(env, body.ip, body.reason || "Manual", body.durationMs); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "unban") { await unbanIp(env, body.ip); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "clear") { const list = await listBannedIps(env); for (const b of list) await unbanIp(env, b.ip); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, cleared: list.length })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleCrisisApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, presets: sysConfig.crisisPresets || [], history: sysConfig.crisisHistory || [] }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "send") { const message = body.message || (sysConfig.crisisPresets || []).find(p => p.id === body.presetId)?.text || ""; if (!message) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); const r = await sendCrisisBroadcast(env, message, body.presetId || "custom"); ctx?.waitUntil(triggerWebhook(env, ctx, "crisis.sent", { message, sent: r.sent }).catch(() => {})); return new Response(JSON.stringify(r), { headers:{ "Content-Type":"application/json" } }); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleLogoApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, logo: sysConfig.customLogo || "", titleColor: sysConfig.customTitleColor || "" }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "set") { const logo = body.logo || ""; if (logo && logo.length > 200000) return new Response(JSON.stringify({ ok:false, success:false, error:"Too large" }), { status:400 }); sysConfig.customLogo = logo; if (body.titleColor !== undefined) sysConfig.customTitleColor = body.titleColor; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "clear") { sysConfig.customLogo = ""; sysConfig.customTitleColor = ""; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleIspTemplatesApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.ispTemplates || {} }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") { const body = await request.json(); if (body.templates) { sysConfig.ispTemplates = body.templates; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); } }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

async function handleApiKeys(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "apikeys");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") { const keys = (sysConfig.panelApiKeys || []).map(k => ({ id:k.id, name:k.name, keyPreview: k.key.slice(0,8) + "..." + k.key.slice(-4), createdAt:k.createdAt, lastUsed:k.lastUsed })); return new Response(JSON.stringify({ ok:true, success:true, data:keys, keys }), { headers:{ "Content-Type":"application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.panelApiKeys) sysConfig.panelApiKeys = []; if (sysConfig.panelApiKeys.length >= 10) return new Response(JSON.stringify({ ok:false, success:false, error:"Max 10" }), { status:400 }); const nk = generateApiKey(body.name); sysConfig.panelApiKeys.push(nk); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true, data:nk, key:nk }), { status:201 }); }
      if (body.action === "revoke") { const idx = (sysConfig.panelApiKeys || []).findIndex(k => k.id === body.id); if (idx === -1) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); sysConfig.panelApiKeys.splice(idx, 1); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}

function cmpVersions(a, b) {
  const pa = String(a).replace(/^v/,"").split(".").map(Number);
  const pb = String(b).replace(/^v/,"").split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const na = pa[i]||0, nb = pb[i]||0; if (na > nb) return 1; if (nb > na) return -1; }
  return 0;
}
async function handleUpdateApi(request, env, ctx) {
  try {
    if (request.method !== "POST") return new Response("405", { status:405 });
    const data = await request.json();
    const perm = await requirePermission(request, env, data, "advanced");
    if (!perm.ok || !perm.ctx.isRoot) return new Response(JSON.stringify({ ok:false, success:false, error:"Root only" }), { status:403 });
    const { cfAccountId:accountId, cfApiToken:apiToken, cfWorkerName:workerName } = sysConfig;
    const repo = (sysConfig.githubRepo || "").replace(/https?:\/\/github\.com\//,"").trim();
    if (data.action === "check") {
      if (!repo) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
      let rv = null;
      try { const r = await fetch(`https://raw.githubusercontent.com/${repo}/main/version`, { signal: AbortSignal.timeout(8000) }); if (r.ok) { const t = (await r.text()).trim(); if (t && t.length <= 15) rv = t; } } catch (e) {}
      if (!rv) return new Response(JSON.stringify({ ok:false, success:false }), { status:502 });
      return new Response(JSON.stringify({ ok:true, success:true, current:CURRENT_VERSION, latest:rv, updateAvailable: cmpVersions(CURRENT_VERSION, rv) < 0, canDeploy: !!(accountId && apiToken && workerName) }));
    }
    if (data.action === "deploy") {
      if (!accountId || !apiToken || !workerName) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
      let code = data.code;
      if (!code) { try { let r = await fetch(`https://raw.githubusercontent.com/${repo}/main/_worker.encode.js`, { signal: AbortSignal.timeout(15000) }); if (!r.ok) r = await fetch(`https://raw.githubusercontent.com/${repo}/main/_worker.js`, { signal: AbortSignal.timeout(15000) }); if (r.ok) code = await r.text(); else throw new Error("HTTP " + r.status); } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:502 }); } }
      const dr = await deployWorkerToCloudflare(accountId, apiToken, workerName, code);
      const dres = await dr.json();
      if (dres.success) { ctx?.waitUntil(triggerWebhook(env, ctx, "panel.updated", { version: CURRENT_VERSION }).catch(() => {})); return new Response(JSON.stringify({ ok:true, success:true })); }
      return new Response(JSON.stringify({ ok:false, success:false, error: dres.errors?.[0]?.message }), { status:502 });
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

/* WORKFLOWS */
const WORKFLOW_TRIGGERS = [
  { id:"user.created", label:"کاربر ساخته شد" },
  { id:"user.disabled", label:"کاربر غیرفعال شد" },
  { id:"user.expired", label:"کاربر منقضی شد" },
  { id:"user.traffic80", label:"کاربر به ۸۰٪ ترافیک رسید" },
  { id:"user.traffic95", label:"کاربر به ۹۵٪ ترافیک رسید" },
  { id:"cron.custom", label:"تسک زمان‌بندی‌شده" },
];
const WORKFLOW_ACTIONS = [
  { id:"send.telegram", label:"ارسال پیام تلگرام", params:["message"] },
  { id:"user.pause", label:"توقف کاربر", params:[] },
  { id:"user.resume", label:"فعال‌سازی کاربر", params:[] },
  { id:"user.extend", label:"تمدید کاربر", params:["days"] },
  { id:"user.resetUsage", label:"بازنشانی مصرف", params:[] },
  { id:"webhook.trigger", label:"فراخوانی Webhook", params:["event"] },
  { id:"user.addTag", label:"افزودن برچسب", params:["tag"] },
];

async function handleWorkflowsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false, error:perm.error }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data:{ workflows: sysConfig.workflows || [], runs: sysConfig.workflowRuns || [], triggers: WORKFLOW_TRIGGERS, actions: WORKFLOW_ACTIONS } }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create" || body.action === "update") {
        if (!sysConfig.workflows) sysConfig.workflows = [];
        const wf = { id: body.id || generateId("wf"), name: body.name || "Workflow", trigger: body.trigger || "user.created", conditions: body.conditions || {}, actions: body.actions || [], enabled: body.enabled !== false, createdAt: Date.now() };
        if (body.action === "create") sysConfig.workflows.push(wf);
        else { const i = sysConfig.workflows.findIndex(x => x.id === wf.id); if (i === -1) return new Response(JSON.stringify({ ok:false, success:false }), { status:404 }); sysConfig.workflows[i] = wf; }
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok:true, success:true, data:wf }));
      }
      if (body.action === "delete") { sysConfig.workflows = (sysConfig.workflows || []).filter(x => x.id !== body.id); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false, error:e.message }), { status:500 }); }
}
async function handleWorkflowsActions(request, env, ctx) {
  try { const perm = await requirePermission(request, env, null, "advanced"); if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status }); return new Response(JSON.stringify({ ok:true, success:true, data:{ triggers:WORKFLOW_TRIGGERS, actions:WORKFLOW_ACTIONS } }), { headers:{ "Content-Type":"application/json" } }); } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function runWorkflow(env, ctx, wf, triggerCtx) {
  const results = [];
  try {
    for (const act of (wf.actions || [])) {
      try {
        if (act.type === "send.telegram") { if (!sysConfig.tgToken) continue; const recipient = sysConfig.tgAdminId || sysConfig.tgChatId; const msg = (act.params?.message || "").replace(/\{name\}/g, triggerCtx.name || ""); await fetch(`https://api.telegram.org/bot${sysConfig.tgToken}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id:recipient, text:msg, parse_mode:"HTML" }), signal: AbortSignal.timeout(8000) }).catch(() => {}); results.push({ action:act.type, ok:true }); }
        else if (act.type === "user.pause" || act.type === "user.resume") { const u = (sysConfig.users || []).find(x => x.id === triggerCtx.userId); if (u) { u.isPaused = act.type === "user.pause"; if (!u.isPaused) { u.disabledReason = null; u.disabledAt = null; } await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action:act.type, ok:true }); } }
        else if (act.type === "user.extend") { const u = (sysConfig.users || []).find(x => x.id === triggerCtx.userId); const days = parseInt(act.params?.days) || 7; if (u) { if (u.expiryMs) u.expiryMs += days * 86400000; else u.expiryMs = Date.now() + days * 86400000; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action:act.type, ok:true }); } }
        else if (act.type === "user.resetUsage") { const c = triggerCtx.userId.replace(/-/g,"").toLowerCase(); if (!sysUsageCache.users) sysUsageCache.users = {}; if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; } await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache)); results.push({ action:act.type, ok:true }); }
        else if (act.type === "webhook.trigger") { await triggerWebhook(env, ctx, act.params?.event || "custom", triggerCtx); results.push({ action:act.type, ok:true }); }
        else if (act.type === "user.addTag") { const u = (sysConfig.users || []).find(x => x.id === triggerCtx.userId); if (u && act.params?.tag) { u.tags = u.tags || []; if (!u.tags.includes(act.params.tag)) u.tags.push(act.params.tag); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action:act.type, ok:true }); } }
      } catch (e) { results.push({ action:act.type, ok:false, error:e.message }); }
    }
    if (!sysConfig.workflowRuns) sysConfig.workflowRuns = [];
    sysConfig.workflowRuns.unshift({ wfId:wf.id, wfName:wf.name, trigger:triggerCtx.trigger, userId:triggerCtx.userId, ts:Date.now(), results });
    if (sysConfig.workflowRuns.length > 100) sysConfig.workflowRuns = sysConfig.workflowRuns.slice(0, 100);
    await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  } catch (e) {}
  return results;
}
async function fireWorkflows(env, ctx, trigger, triggerCtx) {
  try {
    const wfs = (sysConfig.workflows || []).filter(w => w.enabled && w.trigger === trigger);
    for (const wf of wfs) {
      let ok = true;
      if (wf.conditions) {
        if (wf.conditions.minGB !== undefined && (triggerCtx.gb || 0) < parseFloat(wf.conditions.minGB)) ok = false;
        if (wf.conditions.maxGB !== undefined && (triggerCtx.gb || 0) > parseFloat(wf.conditions.maxGB)) ok = false;
        if (wf.conditions.groupId && triggerCtx.groupId !== wf.conditions.groupId) ok = false;
      }
      if (ok) ctx?.waitUntil(runWorkflow(env, ctx, wf, triggerCtx).catch(() => {}));
    }
  } catch (e) {}
}

async function handleDnsPoolApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data:{ pool: sysConfig.dnsPool || [], strategy: sysConfig.dnsPoolStrategy || "weighted" } }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") { const body = await request.json(); if (body.action === "update") { sysConfig.dnsPool = body.pool || sysConfig.dnsPool; if (body.strategy) sysConfig.dnsPoolStrategy = body.strategy; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); } }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
async function handleDnsPoolActions(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const body = await request.json();
    if (body.action === "test") {
      const results = await Promise.all((sysConfig.dnsPool || []).filter(d => d.enabled).map(async d => {
        const start = Date.now();
        try { const u = new URL(d.url); u.searchParams.set("name", "example.com"); u.searchParams.set("type", "A"); const r = await fetch(u.toString(), { headers:{ accept:"application/dns-json" }, signal: AbortSignal.timeout(5000) }); const j = await r.json().catch(() => ({})); return { name:d.name, url:d.url, ok: r.ok && j.Answer, latency: Date.now() - start }; }
        catch (e) { return { name:d.name, url:d.url, ok:false, latency:-1, error:e.message }; }
      }));
      return new Response(JSON.stringify({ ok:true, success:true, data:results }));
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}
function pickDnsFromPool() {
  const pool = (sysConfig.dnsPool || []).filter(d => d.enabled);
  if (pool.length === 0) return sysConfig.customDns || "https://cloudflare-dns.com/dns-query";
  const strategy = sysConfig.dnsPoolStrategy || "weighted";
  if (strategy === "random") return pool[Math.floor(Math.random() * pool.length)].url;
  if (strategy === "weighted") { const total = pool.reduce((s, d) => s + (d.weight || 1), 0); let r = Math.random() * total; for (const d of pool) { r -= (d.weight || 1); if (r <= 0) return d.url; } }
  return pool[0].url;
}

async function handleUpstreamsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.multiUpstream || [] }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "add") { if (!sysConfig.multiUpstream) sysConfig.multiUpstream = []; const parsed = parseVlessUri(body.uri || ""); if (!parsed) return new Response(JSON.stringify({ ok:false, success:false }), { status:400 }); sysConfig.multiUpstream.push({ id:generateId("up"), name:body.name || parsed.name, uri:body.uri, enabled:true, createdAt:Date.now() }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "remove") { sysConfig.multiUpstream = (sysConfig.multiUpstream || []).filter(x => x.id !== body.id); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok:true, success:true })); }
      if (body.action === "toggle") { const u = (sysConfig.multiUpstream || []).find(x => x.id === body.id); if (u) { u.enabled = !u.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); } return new Response(JSON.stringify({ ok:true, success:true })); }
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleSpeedTest(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok:true, success:true, data: sysConfig.speedTestCache || { results:[], lastUpdate:0 } }), { headers:{ "Content-Type":"application/json" } });
    if (method === "POST") {
      const body = await request.json();
      const hosts = body.hosts || ["time.is","cloudflare.com","google.com"];
      const results = [];
      for (const host of hosts) {
        try { const start = Date.now(); const r = await fetch(`https://${host}/cdn-cgi/trace`, { signal: AbortSignal.timeout(5000) }).catch(() => null); if (r && r.ok) results.push({ host, latency: Date.now() - start, status:"ok" }); else results.push({ host, latency:-1, status:"fail" }); } catch (e) { results.push({ host, latency:-1, status:"fail" }); }
      }
      sysConfig.speedTestCache = { results, lastUpdate: Date.now() };
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok:true, success:true, data:{ results } }));
    }
    return new Response(JSON.stringify({ ok:false, success:false }), { status:400 });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleLatencyMap(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const map = {};
    for (const region of (sysConfig.cleanIpRegions || [])) { map[region.id] = { name:region.name, flag:region.flag, active:(sysConfig.activeCleanRegions || []).includes(region.id), ipCount:region.ips.length, avgLatency:null }; }
    const cached = sysConfig.autoCleanIpCache;
    if (cached && cached.full) for (const region of (sysConfig.cleanIpRegions || [])) { const matched = cached.full.filter(c => region.ips.some(ip => c.ip.startsWith(ip.split(".").slice(0,3).join(".")))); if (matched.length > 0) map[region.id].avgLatency = Math.round(matched.reduce((s, m) => s + m.latency, 0) / matched.length); }
    return new Response(JSON.stringify({ ok:true, success:true, data:map }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleDpiDetection(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const country = request.cf?.country || "??";
    const asn = request.cf?.asn || 0;
    let score = 0, reasons = [];
    if (country === "IR") { score += 30; reasons.push("Iran origin"); }
    if ([58224,197207,44244,16322,202468].includes(asn)) { score += 40; reasons.push("Iranian ISP ASN"); }
    const mode = score > 60 ? "high" : score > 30 ? "medium" : "low";
    return new Response(JSON.stringify({ ok:true, success:true, data:{ score, mode, reasons, asn, country, ts:Date.now() } }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleNetworkWeather(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const users = sysConfig.users || [];
    const active = users.filter(u => !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs)).length;
    const total = users.length;
    const health = total === 0 ? 100 : Math.round((active / total) * 100);
    const nodesOnline = (sysConfig.linkedPanels || []).filter(p => p.lastHealth?.status === "online").length;
    const nodesTotal = (sysConfig.linkedPanels || []).length;
    let cfUsage = null;
    if (sysConfig.cfAccountId && sysConfig.cfApiToken) cfUsage = await fetchCloudflareUsage(sysConfig.cfAccountId, sysConfig.cfApiToken);
    const cfPct = cfUsage !== null ? (cfUsage / 100000) * 100 : 0;
    let status = "sunny", emoji = "☀️";
    if (sysConfig.isPaused) { status = "storm"; emoji = "⛈️"; }
    else if (cfPct > 80) { status = "cloudy"; emoji = "☁️"; }
    else if (health < 50) { status = "rainy"; emoji = "🌧️"; }
    else if (health < 80 || nodesOnline < nodesTotal) { status = "cloudy"; emoji = "☁️"; }
    return new Response(JSON.stringify({ ok:true, success:true, data:{ status, emoji, health, active, total, nodesOnline, nodesTotal, cfUsage, cfPct: cfPct.toFixed(2), uptime: Math.floor((Date.now() - isolateStartTime) / 1000), ts:Date.now() } }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handleSuggestions(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const suggestions = [];
    const users = sysConfig.users || [];
    const noIsp = users.filter(u => !u.isp).length;
    if (noIsp > 3) suggestions.push({ level:"info", icon:"isp", title:"تعیین ISP", desc:`${noIsp} کاربر اپراتور مشخصی ندارند.`, action:"tab:users" });
    if ((sysConfig.activeCleanRegions || []).length === 0) suggestions.push({ level:"warn", icon:"globe", title:"فعال‌سازی مناطق IP", desc:"هیچ منطقه‌ای فعال نیست.", action:"tab:regions" });
    if (sysConfig.activeFragment === "off") suggestions.push({ level:"info", icon:"target", title:"فعال‌سازی Fragment", desc:"Fragment خاموش است.", action:"tab:advanced" });
    if (Date.now() - (sysConfig.lastBackup || 0) > 7 * 86400000) suggestions.push({ level:"warn", icon:"save", title:"بکاپ بگیر", desc:"بیش از ۷ روز از آخرین بکاپ گذشته.", action:"tab:backup" });
    let over90 = 0;
    for (const u of users) { const c = u.id.replace(/-/g,"").toLowerCase(); const sysU = sysUsageCache.users?.[c]; if (sysU && u.limitTotalReq && sysU.reqs >= u.limitTotalReq * 0.9) over90++; }
    if (over90 > 0) suggestions.push({ level:"warn", icon:"alert", title:`${over90} کاربر نزدیک محدودیت`, desc:"چند کاربر در آستانه اتمام ترافیک.", action:"tab:users" });
    if ((sysConfig.cronJobs || []).length === 0) suggestions.push({ level:"info", icon:"clock", title:"ساخت Cron Job", desc:"هنوز تسک زمان‌بندی‌شده‌ای ندارید.", action:"tab:cron" });
    if ((sysConfig.webhooks || []).length === 0) suggestions.push({ level:"info", icon:"webhook", title:"افزودن Webhook", desc:"برای اتصال به Slack/Discord.", action:"tab:webhooks" });
    if ((sysConfig.workflows || []).length === 0) suggestions.push({ level:"info", icon:"workflows", title:"ساخت Workflow", desc:"اتوماسیون خودکار بسازید.", action:"tab:workflows" });
    if (sysConfig.inboundConfigs?.enabled === false) suggestions.push({ level:"info", icon:"tag", title:"فعال‌سازی Inbound Configs", desc:"سیستم نام‌گذاری سفارشی خاموش است.", action:"tab:inbounds" });
    return new Response(JSON.stringify({ ok:true, success:true, data:suggestions, suggestions }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

async function handlePredictive(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok:false, success:false }), { status:perm.status });
    const days = sysConfig.predictiveDays || 7;
    const series = getTotalHistorySeries(30);
    const recent = series.slice(-7).map(s => s.gb);
    const avg = recent.length > 0 ? recent.reduce((a,b) => a+b, 0) / recent.length : 0;
    const trend = recent.length >= 2 ? (recent[recent.length-1] - recent[0]) / recent.length : 0;
    const predictions = [];
    for (let i = 1; i <= days; i++) { const projected = Math.max(0, avg + trend * i); const d = new Date(); d.setDate(d.getDate() + i); predictions.push({ date:d.toISOString().split("T")[0], gb: parseFloat(projected.toFixed(3)) }); }
    const nextWeekTotal = predictions.reduce((s, p) => s + p.gb, 0);
    return new Response(JSON.stringify({ ok:true, success:true, data:{ predictions, avg, trend, nextWeekTotal: nextWeekTotal.toFixed(2), basedOnDays: recent.length } }), { headers:{ "Content-Type":"application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok:false, success:false }), { status:500 }); }
}

/* ==================== SUBSCRIPTION ==================== */
async function handleSubscription(request, url, env, ctx) {
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const isCustomUaAllowed = sysConfig.subUserAgent && sysConfig.subUserAgent.trim().length > 0 && ua.includes(sysConfig.subUserAgent.trim().toLowerCase());
  const clientHost = request.headers.get("Host") || url.hostname;
  let targetSub = url.searchParams.get("sub");
  const hasMultiUser = sysConfig.users && sysConfig.users.length > 0;
  let targetUser = null, isValidUser = false;
  if (hasMultiUser) { if (targetSub) { targetUser = sysConfig.users.find(u => u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub); if (targetUser) isValidUser = true; } }
  else { isValidUser = true; targetUser = { id: activeDeviceId, name:"Default" }; }
  const acceptHeader = (request.headers.get("Accept") || "").toLowerCase();
  const secFetchDest = (request.headers.get("Sec-Fetch-Dest") || "").toLowerCase();
  const isRealBrowser = (secFetchDest === "document" || acceptHeader.includes("text/html")) && (ua.includes("mozilla") || ua.includes("chrome") || ua.includes("safari") || ua.includes("applewebkit") || ua.includes("gecko")) && !ua.includes("cla"+"sh") && !ua.includes("si"+"ng-box") && !ua.includes("v"+"2r"+"ay") && !ua.includes("shadow"+"rocket");

  if (isRealBrowser && !isCustomUaAllowed) {
    if (isValidUser) {
      try {
        let html = SUBSCRIPTION_HTML;
        const idClean = targetUser.id.replace(/-/g,"").toLowerCase();
        const sysU = sysUsageCache?.users?.[idClean] || { reqs:0, dReqs:0, lastDay:"" };
        const totalReqs = sysU.reqs || 0;
        const today = todayStr();
        const dailyReqs = sysU.lastDay === today ? (sysU.dReqs || 0) : 0;
        const limitTotal = targetUser.limitTotalReq || 0;
        const limitDaily = targetUser.limitDailyReq || 0;
        const totalGb = (totalReqs/6000).toFixed(2);
        const limitTotalGb = limitTotal ? (limitTotal/6000).toFixed(2) : "∞";
        const dailyGb = (dailyReqs/6000).toFixed(2);
        const limitDailyGb = limitDaily ? (limitDaily/6000).toFixed(2) : "∞";
        const totalPercent = limitTotal ? Math.min(100, (totalReqs/limitTotal)*100).toFixed(1) : "0";
        const dailyPercent = limitDaily ? Math.min(100, (dailyReqs/limitDaily)*100).toFixed(1) : "0";
        let expiryDateTxt = "—", daysLeft = "∞", isExpired = false;
        if (targetUser.expiryMs) { expiryDateTxt = new Date(targetUser.expiryMs).toISOString().split("T")[0]; const rem = Math.ceil((targetUser.expiryMs - Date.now())/86400000); daysLeft = rem >= 0 ? rem : 0; if (Date.now() > targetUser.expiryMs) isExpired = true; }
        let statusCode = "active";
        if (targetUser.isPaused) statusCode = "paused"; else if (isExpired) statusCode = "expired"; else if (limitTotal && totalReqs >= limitTotal) statusCode = "limit"; else if (limitDaily && dailyReqs >= limitDaily) statusCode = "dailyLimit";
        let cleanUrl = new URL(url.href);
        let panelUrlToUse = sysConfig.customPanelUrl;
        if (targetUser.userPanelUrl && targetUser.userPanelUrl.trim()) panelUrlToUse = targetUser.userPanelUrl.trim();
        if (panelUrlToUse) { let c = panelUrlToUse; if (!c.startsWith("http")) c = "https://" + c; try { const cu = new URL(c); cleanUrl.protocol = cu.protocol; cleanUrl.host = cu.host; } catch (e) {} }
        cleanUrl.searchParams.delete("flag"); cleanUrl.searchParams.delete("format"); cleanUrl.searchParams.delete("type"); cleanUrl.searchParams.delete("output"); cleanUrl.searchParams.delete("raw");
        const syncNormal = cleanUrl.href;
        const syncRaw = cleanUrl.href + (cleanUrl.href.includes("?") ? "&flag=a" : "?flag=a");
        const frag = getActiveFragmentValue();
        const fragHtml = frag ? '<div class="frg">Fragment: <code>' + frag + '</code></div>' : "";
        const logoHtml = sysConfig.customLogo ? '<img src="' + sysConfig.customLogo + '" style="width:70px;height:70px;border-radius:20px;object-fit:cover" alt="logo">' : "";
        const tags = (targetUser.tags || []).length > 0 ? '<div class="frg">Tags: ' + targetUser.tags.join(", ") + '</div>' : "";
        html = html.replace(/__USER_NAME__/g, targetUser.name).replace(/__USER_ID__/g, targetUser.id).replace(/__STATUS_CODE__/g, statusCode).replace(/__TOTAL_GB__/g, totalGb).replace(/__LIMIT_TOTAL_GB__/g, limitTotalGb).replace(/__TOTAL_PERCENT__/g, totalPercent + "%").replace(/__DAILY_GB__/g, dailyGb).replace(/__LIMIT_DAILY_GB__/g, limitDailyGb).replace(/__DAILY_PERCENT__/g, dailyPercent + "%").replace(/__EXPIRY_DATE__/g, expiryDateTxt).replace(/__DAYS_LEFT__/g, daysLeft).replace(/__SYNC_NORMAL__/g, syncNormal).replace(/__SYNC_RAW__/g, syncRaw).replace(/__PANEL_NAME__/g, sysConfig.name || PANEL_BRAND).replace(/__FRAGMENT_BADGE__/g, fragHtml + tags).replace(/__CUSTOM_LOGO_BLOCK__/g, logoHtml).replace(/__CURRENT_VERSION__/g, CURRENT_VERSION);
        return new Response(html, { headers:{ "Content-Type":"text/html; charset=utf-8" } });
      } catch (e) { return new Response("Failed", { status:502 }); }
    } else return serveMaintenancePage(request, url);
  }
  if (hasMultiUser && !isValidUser) return new Response("Error", { status:403 });
  const allowInsecure = url.searchParams.get("insecure") === "true" || url.searchParams.get("allowInsecure") === "true";
  const resHeaders = new Headers();
  resHeaders.set("Cache-Control","no-store");
  resHeaders.set("Access-Control-Allow-Origin","*");
  let flag = (url.searchParams.get("flag") || url.searchParams.get("format") || url.searchParams.get("type") || "").toLowerCase();
  if (isValidUser && targetUser) {
    const idClean = targetUser.id.replace(/-/g,"").toLowerCase();
    const sysU = sysUsageCache?.users?.[idClean] || { reqs:0 };
    const totalReqs = sysU.reqs || 0;
    let limitTotal = 0, expiryMs = 0;
    if (hasMultiUser) { limitTotal = targetUser.limitTotalReq || 0; expiryMs = targetUser.expiryMs || 0; }
    else { limitTotal = sysConfig.limitTotalReq || 0; expiryMs = sysConfig.expiryMs || 0; }
    const usedBytes = Math.floor(totalReqs * (1073741824/6000));
    const limitBytes = Math.floor(limitTotal * (1073741824/6000));
    const expireSec = expiryMs ? Math.floor(expiryMs/1000) : 0;
    resHeaders.set("Subscription-UserInfo", `upload=0; download=${usedBytes}; total=${limitBytes}; expire=${expireSec}`);
    const cleanName = encodeURIComponent(targetUser.name);
    resHeaders.set("Content-Disposition", `attachment; filename="${cleanName}"; filename*=UTF-8''${cleanName}`);
  }
  let isClashYaml = false, isSingboxJson = false, isClashJson = false, isVJson = false, isSurge = false, isLoon = false;
  if (flag === "clash" || flag === "yaml" || flag === "meta" || flag === "stash" || flag === "y") isClashYaml = true;
  else if (flag === "b") isClashJson = true;
  else if (flag === "sing" || flag === "singbox" || flag === "sing-box" || flag === "sb" || flag === "s" || flag === "c" || flag === "g") isSingboxJson = true;
  else if (flag === "vjson" || flag === "v") isVJson = true;
  else if (flag === "surge") isSurge = true;
  else if (flag === "loon") isLoon = true;
  else if (flag === "a" || flag === "raw" || flag === "") {
    if (ua.includes(getGamma()) || ua.includes("meta") || ua.includes("mihomo") || ua.includes("clash")) isClashYaml = true;
    else if (ua.includes("sing-box") || ua.includes("singbox") || ua.includes("karing")) isSingboxJson = true;
    else if (ua.includes("surge")) isSurge = true;
    else if (ua.includes("loon")) isLoon = true;
  }
  if (isClashYaml) { resHeaders.set("Content-Type","text/yaml; charset=utf-8"); return new Response(await buildYamlProfile(clientHost, targetSub, allowInsecure, env), { headers:resHeaders }); }
  if (isSingboxJson) { resHeaders.set("Content-Type","application/json; charset=utf-8"); return new Response(JSON.stringify(await buildSingBoxJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers:resHeaders }); }
  if (isClashJson) { resHeaders.set("Content-Type","application/json; charset=utf-8"); return new Response(JSON.stringify(await buildClashJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers:resHeaders }); }
  if (isVJson) { resHeaders.set("Content-Type","application/json; charset=utf-8"); return new Response(JSON.stringify(await buildVJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers:resHeaders }); }
  if (isSurge) { resHeaders.set("Content-Type","text/plain; charset=utf-8"); return new Response(await buildSurgeProfile(clientHost, targetSub, allowInsecure), { headers:resHeaders }); }
  if (isLoon) { resHeaders.set("Content-Type","text/plain; charset=utf-8"); return new Response(await buildLoonProfile(clientHost, targetSub, allowInsecure), { headers:resHeaders }); }
  resHeaders.set("Content-Type","text/plain; charset=utf-8");
  const raw = await buildUriProfile(clientHost, targetSub, allowInsecure);
  return new Response(safeBtoa(raw), { headers:resHeaders });
}
function getActiveFragmentValue() {
  const id = sysConfig.activeFragment || "off";
  if (id === "off") return "";
  const presets = sysConfig.fragmentPresets || [];
  const found = presets.find(p => p.id === id);
  return found ? found.value : "";
}

/* ==================== TELEMETRY ==================== */
async function processTelemetryStream(env, ctx, wsRelayIdx) {
  const [client, webSocket] = Object.values(new WebSocketPair());
  webSocket.accept();
  webSocket.binaryType = "arraybuffer";
  startDataPipe(webSocket, env, ctx, wsRelayIdx);
  return new Response(null, { status:101, webSocket: client });
}
async function startDataPipe(webSocket, env, ctx, wsRelayIdx) {
  activeConnections++;
  let activeClientHash = null;
  webSocket.addEventListener("close", () => { activeConnections--; if (activeClientHash) { const c = activeConns.get(activeClientHash) || 0; if (c > 0) activeConns.set(activeClientHash, c-1); } });
  webSocket.addEventListener("error", () => {});
  let remoteSocket, dataWriter, isInit = true, queue = Promise.resolve();
  webSocket.addEventListener("message", (event) => { queue = queue.then(async () => { try { if (isInit) { isInit = false; const a = await parseSensorData(event.data, wsRelayIdx); if (a) webSocket.send(new Uint8Array([0,0])); } else if (dataWriter) await dataWriter.write(event.data); } catch (err) { webSocket.close(); } }); });
  async function parseSensorData(bufferData, wsRelayIdx) {
    const view = new Uint8Array(bufferData);
    let targetAddr = "", targetPort = 0, offset = 0, isModeAlpha = false, activeProfile = null;
    if (view[0] === 0x00) {
      isModeAlpha = true;
      const clientHash = Array.from(view.slice(1,17)).map(b => b.toString(16).padStart(2,"0")).join("");
      let entry = lookupConfigEntry(clientHash);
      if (entry) { activeClientHash = entry.userId.replace(/-/g,"").toLowerCase(); activeProfile = getAllProfiles().find(p => p.id.replace(/-/g,"").toLowerCase() === activeClientHash); if (!activeProfile) return false; if (entry.relayIp) activeProfile = { ...activeProfile, proxyIp: entry.relayIp }; }
      else { const decoded = decodeConfigUuid(clientHash); if (decoded) { activeProfile = getAllProfiles().find(p => p.id.replace(/-/g,"").toLowerCase().startsWith(decoded.userFingerprint)); if (activeProfile && decoded.relayIpIndex >= 0) { const pips = getEffectivePips(activeProfile); if (pips.length > 0) activeProfile = { ...activeProfile, proxyIp: pips[decoded.relayIpIndex % pips.length] }; } } if (!activeProfile) activeProfile = getAllProfiles().find(p => p.id.replace(/-/g,"").toLowerCase() === clientHash); if (!activeProfile) return false; activeClientHash = activeProfile.id.replace(/-/g,"").toLowerCase(); }
      trackUsage(activeClientHash, 0, env, ctx);
      const cur = activeConns.get(activeClientHash) || 0;
      if (activeProfile.connLimit && cur >= activeProfile.connLimit) { webSocket.close(); return isModeAlpha; }
      activeConns.set(activeClientHash, cur+1);
      const optLen = view[17], pPos = 18 + optLen + 1;
      targetPort = new DataView(bufferData.slice(pPos, pPos+2)).getUint16(0);
      const aType = view[pPos+2]; let vPos = pPos+3, aLen = 0;
      if (aType === 1) { aLen = 4; targetAddr = view.slice(vPos, vPos+aLen).join("."); } else if (aType === 2) { aLen = view[vPos]; vPos++; targetAddr = new TextDecoder().decode(view.slice(vPos, vPos+aLen)); } else if (aType === 3) { aLen = 16; const dv = new DataView(bufferData.slice(vPos, vPos+aLen)); targetAddr = Array.from({length:8}, (_,i) => dv.getUint16(i*2).toString(16)).join(":"); }
      offset = vPos + aLen;
    } else {
      let ePos = bufferData.byteLength;
      for (let i = 0; i < bufferData.byteLength; i++) if (view[i] === 0x0d && view[i+1] === 0x0a) { ePos = i; break; }
      const clientHashHex = new TextDecoder().decode(view.slice(0, ePos));
      let entry = lookupConfigEntry(clientHashHex);
      if (entry) { activeClientHash = entry.userId.replace(/-/g,"").toLowerCase(); activeProfile = getAllProfiles().find(p => p.id.replace(/-/g,"").toLowerCase() === activeClientHash); if (!activeProfile) return false; if (entry.relayIp) activeProfile = { ...activeProfile, proxyIp: entry.relayIp }; }
      else { activeProfile = getAllProfiles().find(p => getTrojanHash(p.id) === clientHashHex); if (!activeProfile) return false; activeClientHash = activeProfile.id.replace(/-/g,"").toLowerCase(); }
      trackUsage(activeClientHash, 0, env, ctx);
      const cur = activeConns.get(activeClientHash) || 0;
      if (activeProfile.connLimit && cur >= activeProfile.connLimit) { webSocket.close(); return isModeAlpha; }
      activeConns.set(activeClientHash, cur+1);
      let hPos = ePos+2; hPos++;
      const aType = view[hPos]; hPos++;
      let aLen = 0;
      if (aType === 1) { aLen = 4; targetAddr = view.slice(hPos, hPos+aLen).join("."); } else if (aType === 3) { aLen = view[hPos]; hPos++; targetAddr = new TextDecoder().decode(view.slice(hPos, hPos+aLen)); } else if (aType === 4) { aLen = 16; const dv = new DataView(bufferData.slice(hPos, hPos+aLen)); targetAddr = Array.from({length:8}, (_,i) => dv.getUint16(i*2).toString(16)).join(":"); }
      hPos += aLen; targetPort = new DataView(bufferData.slice(hPos, hPos+2)).getUint16(0); offset = hPos+4;
    }
    const isDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(targetAddr) || /^[a-zA-Z0-9-]+$/.test(targetAddr);
    let connectAddr = targetAddr;
    if (isDomain) { const dnsUrl = pickDnsFromPool(); try { const dohUrl = new URL(dnsUrl); dohUrl.searchParams.set("name", targetAddr); dohUrl.searchParams.set("type", "A"); const r = await fetch(dohUrl.toString(), { headers:{ accept:"application/dns-json" }, signal: AbortSignal.timeout(3000) }); const j = await r.json(); if (j.Answer && j.Answer.length > 0) connectAddr = j.Answer[0].data; } catch (e) {} }
    try { remoteSocket = connect({ hostname:connectAddr, port:targetPort }); await remoteSocket.opened; }
    catch {
      let pips = [];
      if (activeProfile && activeProfile.proxyIp) pips = activeProfile.proxyIp.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean);
      if (pips.length === 0 && sysConfig.backupRelay) pips = sysConfig.backupRelay.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean);
      let startIdx = 0;
      if (pips.length > 1 && activeProfile) { let h = 0; for (let i = 0; i < activeProfile.id.length; i++) h = activeProfile.id.charCodeAt(i) + ((h << 5) - h); startIdx = Math.abs(h) % pips.length; }
      let connected = false;
      for (let a = 0; a < Math.min(pips.length, 3); a++) { const idx = (startIdx + a) % pips.length; try { const [host, port] = pips[idx].split(":"); remoteSocket = connect({ hostname:host, port: port ? Number(port) : targetPort }); await remoteSocket.opened; connected = true; break; } catch (e) {} }
      if (!connected) { webSocket.close(); return isModeAlpha; }
    }
    dataWriter = remoteSocket.writable.getWriter();
    if (offset < bufferData.byteLength) await dataWriter.write(bufferData.slice(offset));
    remoteSocket.readable.pipeTo(new WritableStream({ write(chunk) { webSocket.send(chunk); } }));
    return isModeAlpha;
  }
}

/* ==================== HELPERS ==================== */
function generateHardwareId(seed) { const h = Array.from(new TextEncoder().encode(seed)).map(b => b.toString(16).padStart(2,"0")).join("").slice(0,20).padEnd(20,"0"); return `${h.slice(0,8)}-0000-4000-8000-${h.slice(-12)}`; }
function getTransportParams(port) { return ["80","8080","8880","2052","2082","2086","2095"].includes(port.toString()) ? "none" : "tls"; }
function getSubscriptionStats(targetSub = null) { const hasMU = sysConfig.users && sysConfig.users.length > 0; let id = activeDeviceId, limitTotalReq = 0, expiryMs = 0; if (hasMU && targetSub) { const u = sysConfig.users.find(x => x.name.toLowerCase() === targetSub.toLowerCase() || x.id === targetSub); if (u) { id = u.id; limitTotalReq = u.limitTotalReq || 0; expiryMs = u.expiryMs || 0; } } const c = id.replace(/-/g,"").toLowerCase(); const s = sysUsageCache?.users?.[c] || { reqs:0 }; const tg = (s.reqs/6000).toFixed(2); const lg = limitTotalReq ? (limitTotalReq/6000).toFixed(2) : "Unlimited"; return { usedStr:`Used: ${tg} GB / ${lg} GB`, expiryStr:`Expiry` }; }
function getFakeConfigNames(targetSub = null) { const stats = getSubscriptionStats(targetSub); return (sysConfig.fakeConfigs || []).filter(f => f && f.enabled && f.name).map(f => f.name.replace(/\{usage\}/g, stats.usedStr).replace(/\{expiry\}/g, stats.expiryStr)); }
function getCleanIpsByRegion() { const regions = sysConfig.cleanIpRegions || []; const active = sysConfig.activeCleanRegions || []; const out = []; for (const id of active) { const r = regions.find(x => x.id === id); if (r && r.ips && r.ips.length > 0) out.push({ region:r, ips:r.ips }); } return out; }
function getCleanIps(hostName, userCleanIps = null) { const raw = userCleanIps || sysConfig.cleanIps; let ips = raw ? raw.split(/[\r\n,;]+/).map(s => { const t = s.trim(); return t ? t.split("#")[0].trim() : ""; }).filter(Boolean) : []; if (ips.length === 0) { const rg = getCleanIpsByRegion(); if (rg.length > 0) { const flat = []; rg.forEach(g => flat.push(...g.ips)); ips = flat; } } if (ips.length === 0 && sysConfig.autoCleanIpCache?.ips?.length > 0) ips = sysConfig.autoCleanIpCache.ips; if (ips.length === 0) ips = [hostName.endsWith(".pages.dev") ? sysConfig.metricNode : hostName]; return ips; }
function getCleanIpsWithNames(hostName, userCleanIps = null) { const raw = userCleanIps || sysConfig.cleanIps; let entries = raw ? raw.split(/[\r\n,;]+/).map(s => { const t = s.trim(); if (!t) return null; const p = t.split("#"); const ip = p[0].trim(); const name = (p[1]||"").trim(); return ip ? { ip, name } : null; }).filter(Boolean) : []; if (entries.length === 0) { const rg = getCleanIpsByRegion(); if (rg.length > 0) rg.forEach(g => g.ips.forEach(ip => entries.push({ ip, name:"", regionId:g.region.id, regionName:g.region.name, regionFlag:g.region.flag }))); } if (entries.length === 0 && sysConfig.autoCleanIpCache?.ips?.length > 0) entries = sysConfig.autoCleanIpCache.ips.map(ip => ({ ip, name:"auto" })); if (entries.length === 0) entries = [{ ip: hostName.endsWith(".pages.dev") ? sysConfig.metricNode : hostName, name:"" }]; return entries; }
function getAllProfiles(targetSub = null) {
  let list = [{ id: activeDeviceId, name:"Default" }];
  if (sysConfig.users && sysConfig.users.length > 0) {
    const now = Date.now();
    sysConfig.users.forEach(u => {
      let skip = false;
      if (u.expiryMs && now > u.expiryMs) skip = true;
      if (u.isPaused) skip = true;
      const c = u.id.replace(/-/g,"").toLowerCase();
      if (u.limitTotalReq && sysUsageCache?.users?.[c]?.reqs >= u.limitTotalReq) skip = true;
      if (!skip) { list.push({ id:u.id, name:u.name, isp:u.isp||null, tags:u.tags||[], bandwidthKbps:u.bandwidthKbps||null, proxyIp:u.proxyIp, cleanIp:u.cleanIp||null, userMode:u.userMode||null, userPorts:u.userPorts||null, maxConfigs:u.maxConfigs||null, userNodes:u.userNodes||null, nat64:u.nat64||null, connLimit:u.connLimit||null, userPanelUrl:u.userPanelUrl||null }); registerConfigEntry(u.id, u.id, u.proxyIp || ""); }
    });
  }
  if (targetSub) list = list.filter(p => p.name.toLowerCase() === targetSub.toLowerCase() || p.id === targetSub);
  return list;
}
function linkedPanelHost(p) { let raw = p && typeof p === "object" ? p.url || "" : p || ""; raw = String(raw).trim(); if (!raw) return ""; raw = raw.replace(/^[a-zA-Z]+:\/\//,"").split("/")[0].split("@").pop(); if (raw.startsWith("[")) return raw.slice(0, raw.indexOf("]")+1); return raw.split(":")[0]; }
function getGlobalNodeHosts() { const hosts = []; if (sysConfig.slaveNodes) hosts.push(...sysConfig.slaveNodes.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean)); if (Array.isArray(sysConfig.linkedPanels)) hosts.push(...sysConfig.linkedPanels.map(linkedPanelHost).filter(Boolean)); return [...new Set(hosts)]; }
function getProxyIpsArray(s) { if (!s) return []; return s.split(/[\r\n,;]+/).map(x => { const t = x.trim(); if (!t) return ""; const hp = t.split("#")[0].split("@")[0]; if (hp.includes(":") && !hp.includes("]")) return hp.split(":")[0]; if (hp.startsWith("[") && hp.includes("]")) return hp.split("]")[0].replace("[",""); return hp; }).filter(Boolean); }
function ipv4ToNat64(ipv4, prefix) { if (!prefix || !ipv4) return null; const p = ipv4.split("."); if (p.length !== 4) return null; const hex = p.map(x => parseInt(x).toString(16).padStart(2,"0")).join(""); const suffix = hex.match(/.{1,4}/g).join(":"); return prefix.replace(/\/\d+$/,"").replace(/:$/,"") + "::" + suffix; }
function getProxyIpsWithNat64(s, nat64Prefix) { let ips = getProxyIpsArray(s); if (nat64Prefix) { const prefixes = nat64Prefix.split(/[\r\n,;]+/).map(x => x.trim()).filter(Boolean); const nat64Ips = []; prefixes.forEach(pre => { ips.forEach(ip => { if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) { const n = ipv4ToNat64(ip, pre); if (n) nat64Ips.push(n); } }); }); ips = ips.concat(nat64Ips); } return ips; }
const ipGeoCache = new Map();
async function preloadIpFlags(profiles, hostNames) {
  const uniqueIps = new Set();
  profiles.forEach(p => { hostNames.forEach(h => { getCleanIps(h, p.cleanIp).forEach(ip => uniqueIps.add(ip)); }); if (p.proxyIp) getProxyIpsArray(p.proxyIp).forEach(ip => uniqueIps.add(ip)); });
  const uncached = Array.from(uniqueIps).filter(ip => !ipGeoCache.has(ip));
  for (let i = 0; i < uncached.length; i += 100) { const batch = uncached.slice(i, i+100); const queries = batch.map(ip => ({ query: ip.split(":")[0].replace(/[\[\]]/g,"").split("#")[0].trim(), fields:"status,country,countryCode,city,isp,org" })); try { const r = await fetch("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(queries), signal: AbortSignal.timeout(5000) }); const results = await r.json(); batch.forEach((ip, idx) => { const d = results[idx]; if (d && d.status === "success") { const cp = d.countryCode.toUpperCase().split("").map(c => 127397 + c.charCodeAt()); ipGeoCache.set(ip, { flag: String.fromCodePoint(...cp), country:d.country||"Unknown", countryCode:d.countryCode||"", city:d.city||"", isp:d.isp||d.org||"" }); } else ipGeoCache.set(ip, { flag:"🌐", country:"Unknown", countryCode:"", city:"", isp:"" }); }); } catch (e) { batch.forEach(ip => { if (!ipGeoCache.has(ip)) ipGeoCache.set(ip, { flag:"🌐", country:"Unknown", countryCode:"", city:"", isp:"" }); }); } }
}
function getGeoInfo(ip) { if (!ip) return { flag:"🌐", country:"Unknown", countryCode:"", city:"", isp:"" }; const clean = ip.split(":")[0].replace(/[\[\]]/g,"").split("#")[0].trim(); return ipGeoCache.get(ip) || ipGeoCache.get(clean) || { flag:"🌐", country:"Unknown", countryCode:"", city:"", isp:"" }; }
async function fetchIpGeoData(ip) { if (!ip) return null; try { const r = await fetch(`http://ip-api.com/json/${ip.split(":")[0].replace(/[\[\]]/g,"").split("#")[0].trim()}?fields=status,country,countryCode,city,isp,org`, { signal: AbortSignal.timeout(5000) }); const d = await r.json(); if (d && d.status === "success") { const cp = d.countryCode.toUpperCase().split("").map(c => 127397 + c.charCodeAt()); return { flag: String.fromCodePoint(...cp), country:d.country||"Unknown", countryCode:d.countryCode||"", city:d.city||"", isp:d.isp||d.org||"" }; } } catch (e) {} return null; }
async function resolveUserProxyIpGeo(user) { if (!user.proxyIp) { user.proxyIpGeo = null; return; } const pips = getProxyIpsArray(user.proxyIp); if (pips.length === 0) { user.proxyIpGeo = null; return; } const geo = await fetchIpGeoData(pips[0]); user.proxyIpGeo = geo || { flag:"🌐", country:"Unknown", countryCode:"", city:"", isp:"" }; }
function getConfigName(type, profileName, port, hostName, ip, proxyIp = null, configIndex = 0, ipName = "", isDirect = false, regionInfo = null) {
  const prefix = sysConfig.namePrefix || "Hamed";
  const strategy = sysConfig.nameStrategy || "default";
  const cleanName = profileName === "Default" ? "" : `-${profileName}`;
  const typeLab = type === "alpha" ? "V" : "T";
  const regionFlagOnly = regionInfo && regionInfo.flag ? regionInfo.flag + " " : "";
  if (strategy.includes("{") && strategy.includes("}")) {
    const lookupIp = proxyIp || ip;
    const geo = getGeoInfo(lookupIp);
    const protoLab = type === "alpha" ? "VLESS" : "Trojan";
    const now = new Date();
    const dateStr = now.getFullYear() + "-" + String(now.getMonth()+1).padStart(2,"0") + "-" + String(now.getDate()).padStart(2,"0");
    const workerName = sysConfig.cfWorkerName || sysConfig.name || hostName || "";
    const flagToUse = isDirect ? "☁" : (regionInfo && regionInfo.flag ? regionInfo.flag : geo.flag);
    const countryToUse = regionInfo ? regionInfo.name : geo.country;
    let name = strategy.replace(/{FLAG}/g, flagToUse).replace(/{COUNTRY}/g, countryToUse).replace(/{CITY}/g, geo.city).replace(/{ISP}/g, geo.isp).replace(/{PROTOCOL}/g, protoLab).replace(/{USER}/g, profileName).replace(/{PORT}/g, port).replace(/{PREFIX}/g, prefix).replace(/{IP}/g, ip||"").replace(/{IP_NAME}/g, ipName||"").replace(/{HOST}/g, hostName||"").replace(/{DATE}/g, dateStr).replace(/{INDEX}/g, String(configIndex)).replace(/{WORKER}/g, workerName);
    if (name.length > MAX_CONFIG_NAME_LEN) name = name.slice(0, MAX_CONFIG_NAME_LEN);
    return name;
  }
  if (strategy === "type-user-port") return `${regionFlagOnly}${type === "alpha" ? "vl"+"ess" : "tro"+"jan"}-${profileName}-${port}`;
  if (strategy === "user-port") return `${regionFlagOnly}${profileName}-${port}`;
  if (strategy === "prefix-user-port") return `${regionFlagOnly}${prefix}${cleanName}-${port}`;
  if (strategy === "ip") return regionFlagOnly + (ip || "unknown");
  return `${regionFlagOnly}${typeLab}-${prefix}-${port}${cleanName}`;
}
function calcEffectiveIps(ips, maxCfg, mode, ports, pipsCount = 1) { if (!maxCfg) return ips; const protoCount = mode === "both" ? 2 : 1; const portCount = ports.length; const multiplier = protoCount * portCount * Math.max(1, pipsCount); const needed = Math.max(1, Math.floor(maxCfg / multiplier)); return ips.slice(0, needed); }
function getProfileHostNames(hostName, profile) { const primary = profile && profile.userPanelUrl ? profile.userPanelUrl : hostName; const names = []; if (profile && profile.userNodes && profile.userNodes.trim()) names.push(...profile.userNodes.split(/[\r\n,;]+/).map(s => linkedPanelHost(s.trim())).filter(Boolean)); else { names.push(linkedPanelHost(primary)); names.push(...getGlobalNodeHosts()); } return [...new Set(names)]; }
function getEffectiveNat64(userNat64) { const parts = []; if (userNat64) parts.push(...userNat64.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean)); if (sysConfig.nat64Prefix) parts.push(...sysConfig.nat64Prefix.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean)); else if (sysConfig.activeCarrier && CARRIERS[sysConfig.activeCarrier]) parts.push(CARRIERS[sysConfig.activeCarrier].nat64); return [...new Set(parts)].join(",") || null; }
function getEffectivePips(p) { const nat64 = getEffectiveNat64(p.nat64); let pips = getProxyIpsWithNat64(p.proxyIp, nat64); if (pips.length === 0 && sysConfig.backupRelay) pips = getProxyIpsWithNat64(sysConfig.backupRelay, nat64); if (pips.length === 0 && sysConfig.customRelay) pips = getProxyIpsWithNat64(sysConfig.customRelay, nat64); return pips; }

function parseVlessUri(uri) {
  if (!uri || typeof uri !== "string" || !uri.startsWith("vless://")) return null;
  try { let rest = uri.slice(8); let fragment = ""; const hi = rest.indexOf("#"); if (hi !== -1) { fragment = decodeURIComponent(rest.slice(hi+1)); rest = rest.slice(0, hi); } let qs = ""; const qi = rest.indexOf("?"); if (qi !== -1) { qs = rest.slice(qi+1); rest = rest.slice(0, qi); } const params = {}; if (qs) qs.split("&").forEach(pair => { const [k,v] = pair.split("="); if (k) params[decodeURIComponent(k)] = decodeURIComponent(v||""); }); const ai = rest.indexOf("@"); if (ai === -1) return null; const uuid = rest.slice(0, ai); const hp = rest.slice(ai+1); let server, port; if (hp.startsWith("[")) { const be = hp.indexOf("]"); server = hp.slice(1,be); port = parseInt(hp.slice(be+2)) || 443; } else { const ci = hp.lastIndexOf(":"); server = hp.slice(0,ci); port = parseInt(hp.slice(ci+1)) || 443; } return { uuid, server, port, name:fragment||"Upstream", security:params.security||"tls", sni:params.sni||params.servername||server, host:params.host||server, path:params.path||"/", type:params.type||"ws", fp:params.fp||"random", allowInsecure:params.allowInsecure==="1", pbk:params.pbk||"", sid:params.sid||"", flow:params.flow||"", encryption:params.encryption||"none", alpn:params.alpn||"", raw:uri }; } catch (e) { return null; }
}
function upstreamToSingboxOb(p) { if (!p) return null; const ob = { type:"vless", tag:"🔗 " + p.name, server:p.server, server_port:p.port, uuid:p.uuid, packet_encoding:"xudp", network:p.type||"ws", tls:{ enabled:p.security==="tls"||p.security==="reality", server_name:p.sni, insecure:p.allowInsecure, utls:{ enabled:true, fingerprint:p.fp||"randomized" } }, transport:{ type:p.type||"ws", path:p.path||"/", headers:{ Host:p.host||p.sni } } }; if (p.flow) ob.flow = p.flow; if (p.pbk) ob.tls.reality = { enabled:true, public_key:p.pbk, short_id:p.sid||"" }; return ob; }
function upstreamToClashProxy(p) { if (!p) return null; const proxy = { name:p.name, type:"vless", server:p.server, port:p.port, uuid:p.uuid, udp:true, tls:p.security==="tls"||p.security==="reality", servername:p.sni, "client-fingerprint":p.fp||"random", "skip-cert-verify":p.allowInsecure, network:p.type||"ws", "ws-opts":{ path:p.path||"/", headers:{ Host:p.host||p.sni } } }; if (p.flow) proxy.flow = p.flow; if (p.pbk) proxy["reality-opts"] = { "public-key":p.pbk, "short-id":p.sid||"" }; return proxy; }
function upstreamToV2RayOb(p) { if (!p) return null; return { tag:"🔗 " + p.name, protocol:"vless", settings:{ vnext:[{ address:p.server, port:p.port, users:[{ id:p.uuid, encryption:p.encryption||"none", flow:p.flow||"" }] }] }, streamSettings:{ network:p.type||"ws", security:p.security==="tls"||p.security==="reality"?"tls":"none", tlsSettings:p.security==="tls"?{ serverName:p.sni, allowInsecure:p.allowInsecure } : undefined, wsSettings:{ path:p.path||"/", headers:{ Host:p.host||p.sni } } } }; }

async function buildUriProfile(hostName, targetSub = null, allowInsecure = false) {
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  const reqPath = encodeURI(`/${sysConfig.apiRoute}`);
  const fragValue = getActiveFragmentValue();
  const fragParam = fragValue ? `&fragment=${encodeURIComponent(fragValue)}` : "";
  const lines = [];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
  await preloadIpFlags(profiles, allHostNames);
  getFakeConfigNames(targetSub).forEach(name => { lines.push(`trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#${encodeURIComponent(name)}`); });
  // v1.0.6: add extra inbound entries (start position)
  const _targetId = targetSub ? (sysConfig.users.find(u => u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub)?.id || activeDeviceId) : activeDeviceId;
  const extraEntries = getExtraInboundEntries(_targetId);
  extraEntries.filter(e => e.position !== "end").forEach(e => { const u = buildStaticInboundURI(e); if (u) lines.push(u); });
  profiles.forEach(p => {
    const ispTemplate = applyIspTemplate(p, fragValue);
    const pips = getEffectivePips(p);
    const mode = p.userMode || sysConfig.mode;
    const ePorts = p.userPorts ? p.userPorts.split(",").map(s => s.trim()).filter(Boolean) : (ispTemplate.ports ? ispTemplate.ports.split(",").map(s => s.trim()).filter(Boolean) : ports);
    let configIndex = 0;
    getProfileHostNames(hostName, p).forEach(hName => {
      const entries = getCleanIpsWithNames(hName, p.cleanIp);
      const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ePorts, pips.length);
      const ipEntryMap = {}; entries.forEach(e => { ipEntryMap[e.ip] = e; });
      ePorts.forEach(port => {
        const sec = getTransportParams(port);
        const ispFrag = ispTemplate.fragment ? `&fragment=${encodeURIComponent(ispTemplate.fragment)}` : fragParam;
        let extBase = `encryption=none&security=${sec}&sni=${hName}&fp=${ispTemplate.agent || sysConfig.agent || "chrome"}&type=ws&host=${hName}&path=${reqPath}${ispFrag}`;
        if (sysConfig.enableOpt2) extBase += `&pbk=enabled`;
        extBase += `&allowInsecure=${allowInsecure ? "1" : "0"}`;
        ips.forEach(ip => {
          const _pips = pips.length > 0 ? pips : [null];
          _pips.forEach(sel => {
            const ipEntry = ipEntryMap[ip] || {};
            const regionInfo = ipEntry.regionId ? { id:ipEntry.regionId, name:ipEntry.regionName, flag:ipEntry.regionFlag } : null;
            if (mode === "alpha" || mode === "both") { const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); lines.push(`${getAlpha()}://${cfgUuid}@${ip}:${port}?${extBase}#${encodeURIComponent(buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false))}`); }
            if (mode === "beta" || mode === "both") { const junk = Array.from({ length:11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random()*62)]).join(""); const payload = { junk, protocol:"tr", mode:"proxyip", panelIPs:[], relayIdx:configIndex }; const pathStr = "/" + btoa(JSON.stringify(payload)); let tb = `security=${sec}&sni=${hName}&fp=${ispTemplate.agent || sysConfig.agent || "chrome"}&type=ws&host=${hName}&path=${encodeURIComponent(pathStr)}${ispFrag}`; if (sysConfig.enableOpt2) tb += `&pbk=enabled`; tb += `&allowInsecure=${allowInsecure ? "1" : "0"}`; lines.push(`${getBeta()}://${p.id}@${ip}:${port}?${tb}#${encodeURIComponent(buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false))}`); }
            configIndex++;
          });
        });
      });
    });
  });
  const up = parseVlessUri(sysConfig.upstreamUri);
  if (up) lines.unshift(up.raw);
  extraEntries.filter(e => e.position === "end").forEach(e => { const u = buildStaticInboundURI(e); if (u) lines.push(u); });
  return lines.join("\n");
}

async function buildYamlProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
  await preloadIpFlags(profiles, allHostNames);
  const proxies = [], proxyNames = [], proxyGeoInfo = new Map();
  const nameCounts = {};
  getFakeConfigNames(targetSub).forEach(name => { proxies.push(`- name: "${name}"\n  type: ${getBeta()}\n  server: 127.0.0.1\n  port: 80\n  password: "${activeDeviceId}"\n  udp: true\n  tls: false`); });
  const uniqueName = base => { if (!nameCounts[base]) { nameCounts[base] = 1; return base; } let c = nameCounts[base]; let n = `${base}-${c}`; while (nameCounts[n]) { c++; n = `${base}-${c}`; } nameCounts[base] = c+1; nameCounts[n] = 1; return n; };
  profiles.forEach(p => {
    const ispTemplate = applyIspTemplate(p, "");
    const pips = getEffectivePips(p);
    const mode = p.userMode || sysConfig.mode;
    const ePorts = p.userPorts ? p.userPorts.split(",").map(s => s.trim()).filter(Boolean) : (ispTemplate.ports ? ispTemplate.ports.split(",").map(s => s.trim()).filter(Boolean) : ports);
    let configIndex = 0;
    getProfileHostNames(hostName, p).forEach(hName => {
      const entries = getCleanIpsWithNames(hName, p.cleanIp);
      const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ePorts, pips.length);
      const ipEntryMap = {}; entries.forEach(e => { ipEntryMap[e.ip] = e; });
      ePorts.forEach(port => {
        const sec = getTransportParams(port) === "tls" ? "true" : "false";
        ips.forEach(ip => {
          const _pips = pips.length > 0 ? pips : [null];
          _pips.forEach(sel => {
            const ipEntry = ipEntryMap[ip] || {};
            const regionInfo = ipEntry.regionId ? { id:ipEntry.regionId, name:ipEntry.regionName, flag:ipEntry.regionFlag } : null;
            if (mode === "alpha" || mode === "both") { let vName = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false)); proxyNames.push(`"${vName}"`); proxyGeoInfo.set(vName, regionInfo ? { country:regionInfo.name, flag:regionInfo.flag } : getGeoInfo(sel || ip)); const junk = Array.from({ length:11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random()*62)]).join(""); const pathStr = "/" + btoa(JSON.stringify({ junk, protocol:"vl", mode:"proxyip", panelIPs:[] })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); proxies.push(`- name: "${vName.replace(/"/g, '""')}"\n  type: ${getAlpha()}\n  server: ${ip}\n  port: ${port}\n  uuid: ${cfgUuid}\n  udp: true\n  tls: ${sec}\n  servername: ${hName}\n  client-fingerprint: ${ispTemplate.agent || sysConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStr}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}`); }
            if (mode === "beta" || mode === "both") { let tName = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false)); proxyNames.push(`"${tName}"`); proxyGeoInfo.set(tName, regionInfo ? { country:regionInfo.name, flag:regionInfo.flag } : getGeoInfo(sel || ip)); const junk = Array.from({ length:11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random()*62)]).join(""); const pathStr = "/" + btoa(JSON.stringify({ junk, protocol:"tr", mode:"proxyip", panelIPs:[], relayIdx:configIndex })); proxies.push(`- name: "${tName.replace(/"/g, '""')}"\n  type: ${getBeta()}\n  server: ${ip}\n  port: ${port}\n  password: "${p.id}"\n  udp: true\n  tls: ${sec}\n  sni: ${hName}\n  client-fingerprint: ${ispTemplate.agent || sysConfig.agent || "random"}\n  network: ws\n  ws-opts:\n    path: "${pathStr}"\n    headers:\n      Host: ${hName}\n  skip-cert-verify: ${allowInsecure}`); }
            configIndex++;
          });
        });
      });
    });
  });
  const countryGroups = new Map();
  proxyGeoInfo.forEach((geo, name) => { const k = geo.country || "Unknown"; if (!countryGroups.has(k)) countryGroups.set(k, { flag: geo.flag || "🌐", proxies:[] }); countryGroups.get(k).proxies.push(name); });
  const sorted = Array.from(countryGroups.entries()).sort((a,b) => a[0].localeCompare(b[0]));
  let groups = 'proxy-groups:\n  - name: "✅ Selector"\n    type: select\n    proxies:\n      - "⚡ Fastest"\n      - "🖐 Manual"\n';
  sorted.forEach(([c, i]) => { groups += `      - "${i.flag} ${c}"\n`; });
  groups += '\n  - name: "⚡ Fastest"\n    type: url-test\n    url: "https://www.gstatic.com/generate_204"\n    interval: 30\n    tolerance: 50\n    proxies:\n';
  proxyNames.forEach(n => { groups += `      - ${n}\n`; });
  return `mixed-port: 7890\nipv6: true\nallow-lan: false\nlog-level: warning\nmode: rule\ntcp-concurrent: true\ndns:\n  enable: true\n  listen: 127.0.0.1:1053\n  nameserver: ["https://8.8.8.8/dns-query#✅ Selector"]\n  enhanced-mode: redir-host\ntun:\n  enable: true\n  stack: mixed\n  auto-route: true\n  dns-hijack: ["any:53"]\n  mtu: 9000\n\nproxies:\n${proxies.join("\n")}\n\n${groups}\n\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,✅ Selector\n`;
}

async function buildClashJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
  await preloadIpFlags(profiles, allHostNames);
  const proxiesArr = [], dynamicTags = [];
  const uniqueName = base => { let c = 0, n = base; while (proxiesArr.some(p => p.name === n)) { c++; n = `${base}-${c}`; } return n; };
  profiles.forEach(p => {
    const ispTemplate = applyIspTemplate(p, "");
    const pips = getEffectivePips(p);
    const mode = p.userMode || sysConfig.mode;
    const ePorts = p.userPorts ? p.userPorts.split(",").map(s => s.trim()).filter(Boolean) : (ispTemplate.ports ? ispTemplate.ports.split(",").map(s => s.trim()).filter(Boolean) : ports);
    let configIndex = 0;
    getProfileHostNames(hostName, p).forEach(hName => {
      const entries = getCleanIpsWithNames(hName, p.cleanIp);
      const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ePorts, pips.length);
      const ipEntryMap = {}; entries.forEach(e => { ipEntryMap[e.ip] = e; });
      ePorts.forEach(port => {
        const sec = getTransportParams(port) === "tls";
        ips.forEach(ip => {
          const _pips = pips.length > 0 ? pips : [null];
          _pips.forEach(sel => {
            const ipEntry = ipEntryMap[ip] || {};
            const regionInfo = ipEntry.regionId ? { id:ipEntry.regionId, name:ipEntry.regionName, flag:ipEntry.regionFlag } : null;
            if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false)); dynamicTags.push(tag); const junk = Array.from({ length:11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random()*62)]).join(""); const pathStr = "/" + btoa(JSON.stringify({ junk, protocol:"vl", mode:"proxyip", panelIPs:[] })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); proxiesArr.push({ name:tag, type:"vless", server:ip, port:parseInt(port), udp:true, uuid:cfgUuid, tls:sec, servername:hName, "client-fingerprint": ispTemplate.agent || "random", "skip-cert-verify":allowInsecure, network:"ws", "ws-opts":{ path:pathStr, headers:{ Host:hName } } }); }
            if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false)); dynamicTags.push(tag); const junk = Array.from({ length:11 }, () => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random()*62)]).join(""); const pathStr = "/" + btoa(JSON.stringify({ junk, protocol:"tr", mode:"proxyip", panelIPs:[], relayIdx:configIndex })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); proxiesArr.push({ name:tag, type:"trojan", server:ip, port:parseInt(port), udp:true, password:p.id, tls:sec, sni:hName, "client-fingerprint": ispTemplate.agent || "random", "skip-cert-verify":allowInsecure, network:"ws", "ws-opts":{ path:pathStr, headers:{ Host:hName } } }); }
            configIndex++;
          });
        });
      });
    });
  });
  if (dynamicTags.length === 0) dynamicTags.push("direct");
  return { "mixed-port":7890, ipv6:true, "allow-lan":false, "log-level":"warning", mode:"rule", "tcp-concurrent":true, "proxies": proxiesArr, "proxy-groups":[ { name:"✅ Selector", type:"select", proxies:["⚡ Fastest", ...dynamicTags] }, { name:"⚡ Fastest", type:"url-test", url:"https://www.gstatic.com/generate_204", interval:30, proxies:dynamicTags } ], rules:["GEOIP,IR,DIRECT","MATCH,✅ Selector"] };
}

async function buildVJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
  await preloadIpFlags(profiles, allHostNames);
  const outbounds = [];
  const uniqueName = base => { let c = 0, n = base; while (outbounds.some(o => o.tag === n)) { c++; n = `${base}-${c}`; } return n; };
  let configIndex = 0;
  profiles.forEach(p => {
    const ispTemplate = applyIspTemplate(p, "");
    const pips = getEffectivePips(p);
    const mode = p.userMode || sysConfig.mode;
    const ePorts = p.userPorts ? p.userPorts.split(",").map(s => s.trim()).filter(Boolean) : (ispTemplate.ports ? ispTemplate.ports.split(",").map(s => s.trim()).filter(Boolean) : ports);
    getProfileHostNames(hostName, p).forEach(hName => {
      const entries = getCleanIpsWithNames(hName, p.cleanIp);
      const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ePorts, pips.length);
      ePorts.forEach(port => {
        const sec = getTransportParams(port) === "tls" ? "tls" : "none";
        ips.forEach(ip => {
          const _pips = pips.length > 0 ? pips : [null];
          _pips.forEach(sel => {
            if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, null, false)); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); const path = "/" + btoa(JSON.stringify({ junk:"j", protocol:"vl", mode:"proxyip", panelIPs:[], relayIdx:configIndex })); outbounds.push({ tag, protocol:"vless", settings:{ vnext:[{ address:ip, port:parseInt(port), users:[{ id:cfgUuid, encryption:"none" }] }] }, streamSettings:{ network:"ws", security:sec, tlsSettings: sec === "tls" ? { serverName:hName, allowInsecure } : undefined, wsSettings:{ path, headers:{ Host:hName } } } }); }
            if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, null, false)); const path = "/" + btoa(JSON.stringify({ junk:"j", protocol:"tr", mode:"proxyip", panelIPs:[], relayIdx:configIndex })); outbounds.push({ tag, protocol:"trojan", settings:{ servers:[{ address:ip, port:parseInt(port), password:p.id }] }, streamSettings:{ network:"ws", security:sec, tlsSettings: sec === "tls" ? { serverName:hName, allowInsecure } : undefined, wsSettings:{ path, headers:{ Host:hName } } } }); }
            configIndex++;
          });
        });
      });
    });
  });
  return { outbounds };
}

async function buildSingBoxJsonProfile(hostName, targetSub = null, allowInsecure = false, env = null) {
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = [...new Set(profiles.flatMap(p => getProfileHostNames(hostName, p)))];
  await preloadIpFlags(profiles, allHostNames);
  const outbounds = [];
  const uniqueName = base => { let c = 0, n = base; while (outbounds.some(o => o.tag === n)) { c++; n = `${base}-${c}`; } return n; };
  let configIndex = 0;
  profiles.forEach(p => {
    const ispTemplate = applyIspTemplate(p, "");
    const pips = getEffectivePips(p);
    const mode = p.userMode || sysConfig.mode;
    const ePorts = p.userPorts ? p.userPorts.split(",").map(s => s.trim()).filter(Boolean) : (ispTemplate.ports ? ispTemplate.ports.split(",").map(s => s.trim()).filter(Boolean) : ports);
    getProfileHostNames(hostName, p).forEach(hName => {
      const entries = getCleanIpsWithNames(hName, p.cleanIp);
      const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ePorts, pips.length);
      ePorts.forEach(port => {
        const sec = getTransportParams(port) === "tls";
        ips.forEach(ip => {
          const _pips = pips.length > 0 ? pips : [null];
          _pips.forEach(sel => {
            if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, null, false)); const path = "/" + btoa(JSON.stringify({ junk:"j", protocol:"vl", mode:"proxyip", panelIPs:[] })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); outbounds.push({ type:"vless", tag, server:ip, server_port:parseInt(port), uuid:cfgUuid, network:"tcp", tls:{ enabled:sec, server_name:hName, insecure:allowInsecure, utls:{ enabled:true, fingerprint:"randomized" } }, transport:{ type:"ws", path, headers:{ Host:hName } } }); }
            if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, null, false)); const path = "/" + btoa(JSON.stringify({ junk:"j", protocol:"tr", mode:"proxyip", panelIPs:[], relayIdx:configIndex })); outbounds.push({ type:"trojan", tag, server:ip, server_port:parseInt(port), password:p.id, network:"tcp", tls:{ enabled:sec, server_name:hName, insecure:allowInsecure, utls:{ enabled:true, fingerprint:"randomized" } }, transport:{ type:"ws", path, headers:{ Host:hName } } }); }
            configIndex++;
          });
        });
      });
    });
  });
  return { log:{ disabled:false, level:"warn", timestamp:true }, dns:{ servers:[{ tag:"cf", address:"https://1.1.1.1/dns-query", detour:"direct" }], rules:[] }, inbounds:[{ type:"mixed", tag:"mixed-in", listen:"127.0.0.1", listen_port:2080 }], outbounds:[{ type:"direct", tag:"direct" }, ...outbounds], route:{ rules:[], final:"direct" } };
}

async function buildSurgeProfile(hostName, targetSub = null, allowInsecure = false) {
  const lines = ["[Proxy]"];
  const profiles = getAllProfiles(targetSub);
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  profiles.forEach(p => { const mode = p.userMode || sysConfig.mode; getProfileHostNames(hostName, p).forEach(hName => { const entries = getCleanIpsWithNames(hName, p.cleanIp); const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ports, 1); ips.forEach(ip => { if (mode === "alpha" || mode === "both") { const cfgUuid = generateConfigUuid(p.id, 0); registerConfigEntry(cfgUuid, p.id, ""); lines.push(`${p.name}-V-${ip} = vless, ${ip}, ${ports[0]}, username=${cfgUuid}, tls=true, ws=true, ws-path=/${sysConfig.apiRoute}, ws-headers=Host:${hName}, sni=${hName}`); } if (mode === "beta" || mode === "both") lines.push(`${p.name}-T-${ip} = trojan, ${ip}, ${ports[0]}, password=${p.id}, tls=true, ws=true, ws-path=/${sysConfig.apiRoute}, ws-headers=Host:${hName}, sni=${hName}`); }); }); });
  lines.push("", "[Proxy Group]", "Proxy = select, " + profiles.map(p => p.name).join(", "));
  lines.push("", "[Rule]", "GEOIP,IR,DIRECT", "FINAL,Proxy");
  return lines.join("\n");
}
async function buildLoonProfile(hostName, targetSub = null, allowInsecure = false) {
  const lines = ["[Proxy]"];
  const profiles = getAllProfiles(targetSub);
  const ports = sysConfig.socketPorts ? sysConfig.socketPorts.split(",").map(s => s.trim()).filter(Boolean) : ["443"];
  profiles.forEach(p => { const mode = p.userMode || sysConfig.mode; getProfileHostNames(hostName, p).forEach(hName => { const entries = getCleanIpsWithNames(hName, p.cleanIp); const ips = calcEffectiveIps(entries.map(e => e.ip), p.maxConfigs||null, mode, ports, 1); ips.forEach(ip => { if (mode === "alpha" || mode === "both") { const cfgUuid = generateConfigUuid(p.id, 0); registerConfigEntry(cfgUuid, p.id, ""); lines.push(`${p.name}-V-${ip} = vless,${ip},${ports[0]},"${cfgUuid}",over-tls=true,tls-name=${hName},transport=ws,path=/${sysConfig.apiRoute},host=${hName}`); } if (mode === "beta" || mode === "both") lines.push(`${p.name}-T-${ip} = trojan,${ip},${ports[0]},"${p.id}",over-tls=true,tls-name=${hName},transport=ws,path=/${sysConfig.apiRoute},host=${hName}`); }); }); });
  lines.push("", "[Proxy Group]", "Proxy = select, " + profiles.map(p => p.name).join(", "));
  lines.push("", "[Rule]", "GEOIP,CN,DIRECT", "FINAL,Proxy");
  return lines.join("\n");
}

function getCustomRouting() { const cr = sysConfig.customRouting || ""; const lines = cr.split("\n").map(l => l.trim()).filter(Boolean); const domains = [], ips = [], geoips = [], geosites = []; for (const l of lines) { const low = l.toLowerCase(); if (low.startsWith("geoip:")) geoips.push(l.substring(6).trim().toUpperCase()); else if (low.startsWith("geosite:")) geosites.push(l.substring(8).trim().toLowerCase()); else if (l.match(/^[0-9\.\/:]+$/)) ips.push(l); else domains.push(l); } if (sysConfig.iranRouting) { for (const d of IRAN_DOMAINS_PRESET) if (!domains.includes(d)) domains.push(d); if (!geoips.includes("IR")) geoips.push("IR"); } return { domains, ips, geoips, geosites }; }

/* Loaders, maintenance, etc. */
async function serveMaintenancePage(request, url) {
  let list = sysConfig.maintenanceHost ? sysConfig.maintenanceHost.split(",").map(s => s.trim()).filter(s => s) : ["https://www.ubuntu.com"];
  const ip = request.headers.get("cf-connecting-ip") || "0.0.0.0";
  const h = Array.from(ip).reduce((a,c) => a + c.charCodeAt(0), 0);
  const target = list[h % list.length].startsWith("http") ? list[h % list.length] : `https://${list[h % list.length]}`;
  try {
    const turl = new URL(target);
    if (url.pathname !== "/") turl.pathname = url.pathname;
    turl.search = url.search;
    const hd = new Headers(request.headers);
    hd.set("Host", turl.hostname);
    hd.delete("cf-connecting-ip"); hd.delete("x-forwarded-for");
    const init = { method: request.method, headers: hd, redirect:"follow" };
    if (request.method !== "GET" && request.method !== "HEAD") init.body = request.body;
    return await fetch(new Request(turl.toString(), init));
  } catch (e) { return new Response("Not Found", { status:404 }); }
}
let sysConfigLoading = null, sysUsageLoading = null, backupIpLoading = null, sysHistoryLoading = null;
function migrateSlaveNodesToLinkedPanels(cfg) {
  let modified = false;
  if (cfg && cfg.slaveNodes && cfg.slaveNodes.trim().length > 0) {
    if (!cfg.linkedPanels) cfg.linkedPanels = [];
    const nodes = cfg.slaveNodes.split(/[\r\n,;]+/).map(s => s.trim()).filter(Boolean);
    const syncKey = cfg.syncApiKey || "";
    nodes.forEach(node => {
      const cn = node.replace(/^[a-zA-Z]+:\/\//,"").split("/")[0].split("@").pop().split(":")[0].toLowerCase();
      const exists = cfg.linkedPanels.some(p => p && p.url && p.url.replace(/^[a-zA-Z]+:\/\//,"").split("/")[0].split("@").pop().split(":")[0].toLowerCase() === cn);
      if (!exists) { cfg.linkedPanels.push({ url:node, apiKey:syncKey }); modified = true; }
    });
    cfg.slaveNodes = ""; modified = true;
  }
  return modified;
}
async function loadSysConfig(env, ctx = null) {
  const now = Date.now();
  if (env.IOT_DB) {
    if (now - sysConfigCacheTime > CACHE_TTL_CONFIG) {
      if (!sysConfigLoading) {
        sysConfigLoading = d1Get(env, "sys_config")
          .then(async (stored) => {
            let loaded = { ...SYSTEM_DEFAULTS, ...(stored ? JSON.parse(stored) : null) };
            if (!loaded.inboundConfigs) loaded.inboundConfigs = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs));
            const dec = await decryptSensitiveInConfig(loaded, loaded.masterKey || "admin");
            sysConfig = { ...loaded, ...dec };
            sysConfigCacheTime = Date.now();
            if (migrateSlaveNodesToLinkedPanels(sysConfig)) {
              const p = cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
              if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p.catch(() => {})); else p.catch(() => {});
            }
          })
          .catch(() => { sysConfig = { ...SYSTEM_DEFAULTS }; sysConfigCacheTime = Date.now(); })
          .finally(() => { sysConfigLoading = null; });
      }
      await sysConfigLoading;
    }
    if (now - sysUsageCacheTime > CACHE_TTL_USAGE) {
      if (!sysUsageLoading) {
        sysUsageLoading = d1Get(env, "sys_usage")
          .then(u => { if (u) sysUsageCache = JSON.parse(u); else sysUsageCache = { users:{} }; sysUsageCacheTime = Date.now(); })
          .catch(() => { sysUsageCache = { users:{} }; sysUsageCacheTime = Date.now(); })
          .finally(() => { sysUsageLoading = null; });
      }
      await sysUsageLoading;
    }
    if (sysConfig.historyEnabled && now - sysHistoryCacheTime > CACHE_TTL_HISTORY) {
      if (!sysHistoryLoading) {
        sysHistoryLoading = d1Get(env, "sys_history")
          .then(h => { if (h) sysHistoryCache = JSON.parse(h); else sysHistoryCache = { days:{} }; sysHistoryCacheTime = Date.now(); })
          .catch(() => { sysHistoryCache = { days:{} }; sysHistoryCacheTime = Date.now(); })
          .finally(() => { sysHistoryLoading = null; });
      }
      await sysHistoryLoading;
    }
  }
  if (now - backupIpCacheTime > CACHE_TTL_BACKUP_IP) {
    if (!backupIpLoading) {
      backupIpLoading = (env.IOT_DB ? d1Get(env, "backup_ip") : Promise.resolve(null))
        .then(v => { backupIpCache = v; backupIpCacheTime = Date.now(); })
        .catch(() => { backupIpCacheTime = Date.now(); })
        .finally(() => { backupIpLoading = null; });
    }
    await backupIpLoading;
  }
  sysConfig.customRelay = backupIpCache ?? env.RELAY_IP ?? "";
}
async function fetchCloudflareUsage(accountId, apiToken) {
  if (!accountId || !apiToken) return null;
  try {
    const start = new Date().toISOString().split("T")[0] + "T00:00:00Z";
    const query = `query($a:String!,$s:ISO8601DateTime!){viewer{accounts(filter:{accountTag:$a}){workersInvocationsAdaptive(limit:1,filter:{datetime_geq:$s}){sum{requests}}}}}`;
    const r = await fetch("https://api.cloudflare.com/client/v4/graphql", { method:"POST", headers:{ Authorization:`Bearer ${apiToken}`, "Content-Type":"application/json" }, body: JSON.stringify({ query, variables:{ a:accountId, s:start } }), signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    const reqs = j?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive?.[0]?.sum?.requests;
    return typeof reqs === "number" ? reqs : null;
  } catch (e) { return null; }
}
async function logActivity(env, type, detail) {
  if (!env || !env.IOT_DB) return;
  try { const ts = new Date().toISOString(); let logs = []; const stored = await d1Get(env, "sys_logs"); if (stored) logs = JSON.parse(stored); logs.unshift({ ts, type, detail }); if (logs.length > 300) logs = logs.slice(0,300); await d1Put(env, "sys_logs", JSON.stringify(logs)); } catch (e) {}
}

/* TELEGRAM */
async function handleTelegramWebhook(request, env, hostName, ctx) {
  try {
    const update = await request.json();
    const tgApi = `https://api.telegram.org/bot${sysConfig.tgToken}`;
    const callerId = update.callback_query?.from?.id?.toString() || update.message?.from?.id?.toString();
    const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
    const isAuthorized = adminId && callerId === adminId.toString();
    if (!isAuthorized) { const chatId = update.callback_query?.message?.chat?.id || update.message?.chat?.id; if (chatId) await fetch(`${tgApi}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id:chatId, text:"دسترسی ندارید" }), signal: AbortSignal.timeout(8000) }); return new Response("OK"); }
    const sendMsg = async (chatId, text, kb = null) => await fetch(`${tgApi}/sendMessage`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ chat_id:chatId, text, parse_mode:"Markdown", reply_markup:kb }), signal: AbortSignal.timeout(8000) });
    const mainMenu = () => {
      const users = sysConfig.users || [];
      const active = users.filter(u => !u.isPaused).length;
      return {
        text: `🦦 *${PANEL_BRAND}*\n━━━━━━━━━━━━━━━━\nکاربران: ${users.length} (${active} فعال)\nوضعیت: ${sysConfig.isPaused ? "متوقف" : "فعال"}\nنسخه: v${CURRENT_VERSION}\n━━━━━━━━━━━━━━━━`,
        kb: { inline_keyboard: [[{ text:"پنل", web_app:{ url:`https://${hostName}/panel` } }]] },
      };
    };
    if (update.callback_query) {
      const cb = update.callback_query, chatId = cb.message?.chat?.id;
      const m = mainMenu();
      await sendMsg(chatId, m.text, m.kb);
      await fetch(`${tgApi}/answerCallbackQuery`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ callback_query_id:cb.id, text:"✓" }) }).catch(() => {});
    } else if (update.message?.text) {
      const chatId = update.message.chat.id;
      const m = mainMenu();
      await sendMsg(chatId, m.text, m.kb);
    }
    return new Response("OK");
  } catch (e) { return new Response("OK"); }
}
/* ═══════════════════════════════════════════════════════════════
   DASHBOARD HTML — v1.0.6 Design Edition (SVG Icons)
   ═══════════════════════════════════════════════════════════════ */
const DASHBOARD_HTML = '<!DOCTYPE html><html lang="fa" dir="rtl"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
'<title>Hamed Panel · Design</title><meta name="theme-color" content="#05070d">' +
'<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'%3E%3Ctext y=\'.9em\' font-size=\'90\'%3E%F0%9F%A6%A6%3C/text%3E%3C/svg%3E">' +
'<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
'<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">' +
'<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>' +
'<style>' +
':root{--bg:#05070d;--panel:rgba(18,24,40,.72);--border:rgba(148,163,184,.1);--border-2:rgba(148,163,184,.18);--text:#e8ecf6;--text-2:#b8c1d9;--muted:#7c88a6;--muted-2:#4d5a78;--c1:#06b6d4;--c2:#8b5cf6;--c3:#ec4899;--c4:#f59e0b;--c5:#10b981;--ok:#10b981;--warn:#f59e0b;--danger:#ef4444;--info:#38bdf8;--grad:linear-gradient(135deg,#06b6d4 0%,#8b5cf6 50%,#ec4899 100%);--ease:cubic-bezier(.2,.9,.3,1)}' +
'*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}' +
'body{background:var(--bg);color:var(--text);font-family:\'Vazirmatn\',system-ui,sans-serif;-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden;line-height:1.5}' +
'.aurora{position:fixed;inset:0;z-index:-2;overflow:hidden;pointer-events:none}' +
'.aurora::before,.aurora::after{content:"";position:absolute;border-radius:50%;filter:blur(120px);opacity:.5;animation:af 22s ease-in-out infinite}' +
'.aurora::before{width:800px;height:800px;top:-300px;right:-200px;background:radial-gradient(circle,#06b6d4 0%,transparent 70%)}' +
'.aurora::after{width:700px;height:700px;bottom:-300px;left:-200px;background:radial-gradient(circle,#ec4899 0%,transparent 70%);animation-delay:-11s}' +
'@keyframes af{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(80px,-60px) scale(1.15)}66%{transform:translate(-60px,60px) scale(.9)}}' +
'.grid-bg{position:fixed;inset:0;z-index:-1;opacity:.14;pointer-events:none;background-image:linear-gradient(rgba(139,92,246,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(139,92,246,.08) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse at center,black 20%,transparent 75%);mask-image:radial-gradient(ellipse at center,black 20%,transparent 75%)}' +
'::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:linear-gradient(180deg,rgba(99,102,241,.4),rgba(236,72,153,.4));border-radius:10px;border:2px solid transparent;background-clip:content-box}' +
'::selection{background:rgba(139,92,246,.4);color:#fff}' +
'.icn{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;vertical-align:middle}' +
'.icn svg{display:block;width:1em;height:1em;stroke-width:2;stroke:currentColor;fill:none;stroke-linecap:round;stroke-linejoin:round}' +
'.icn-fill svg{fill:currentColor;stroke:none}' +
'.login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}' +
'.lcard{width:100%;max-width:440px;padding:44px 36px 32px;border-radius:32px;background:linear-gradient(180deg,rgba(20,26,44,.9),rgba(10,14,26,.94));backdrop-filter:blur(24px);border:1px solid var(--border-2);box-shadow:0 40px 100px -20px rgba(0,0,0,.7);position:relative;overflow:hidden}' +
'.lcard::before{content:"";position:absolute;top:-100px;right:-100px;width:300px;height:300px;background:radial-gradient(circle,rgba(6,182,212,.35),transparent 70%);pointer-events:none}' +
'.lcard::after{content:"";position:absolute;bottom:-100px;left:-100px;width:300px;height:300px;background:radial-gradient(circle,rgba(236,72,153,.25),transparent 70%);pointer-events:none}' +
'.lcard>*{position:relative;z-index:1}' +
'.otter{width:110px;height:110px;margin:0 auto 20px;position:relative;display:flex;align-items:center;justify-content:center}' +
'.otter::before{content:"";position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,#06b6d4,#8b5cf6,#ec4899,#f59e0b,#06b6d4);animation:spin 8s linear infinite;filter:blur(14px);opacity:.55}' +
'.otter::after{content:"";position:absolute;inset:12px;border-radius:50%;background:#0a0e1a;border:1px solid var(--border-2)}' +
'.otter svg,.otter img{position:relative;z-index:2;width:76px;height:76px;border-radius:20px;object-fit:cover;filter:drop-shadow(0 0 20px rgba(139,92,246,.6))}' +
'@keyframes spin{to{transform:rotate(360deg)}}' +
'.tg{background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:900;letter-spacing:-.02em}' +
'.fld{width:100%;padding:14px 16px;border-radius:14px;background:rgba(10,14,26,.7);border:1px solid var(--border);color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:.25s}' +
'.fld:focus{border-color:rgba(139,92,246,.6);box-shadow:0 0 0 4px rgba(99,102,241,.15)}' +
'.btn{padding:12px 18px;border-radius:14px;font-weight:700;font-size:14px;cursor:pointer;border:none;font-family:inherit;transition:.2s;display:inline-flex;align-items:center;justify-content:center;gap:8px;white-space:nowrap;user-select:none}' +
'.btn:active{transform:scale(.97)}' +
'.btn-p{background:var(--grad);color:#fff;box-shadow:0 10px 30px -10px rgba(99,102,241,.7)}' +
'.btn-p:hover{filter:brightness(1.1)}' +
'.btn-g{background:rgba(148,163,184,.08);color:var(--text);border:1px solid var(--border-2)}' +
'.btn-g:hover{background:rgba(148,163,184,.15)}' +
'.btn-d{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}' +
'.btn-d:hover{background:rgba(239,68,68,.22)}' +
'.btn-s{padding:8px 12px;font-size:12px;border-radius:10px}' +
'.shell{display:none;min-height:100vh}.shell.on{display:block}' +
'.sb{position:fixed;top:0;right:0;bottom:0;width:280px;background:linear-gradient(180deg,rgba(14,19,32,.98),rgba(8,12,22,.98));backdrop-filter:blur(20px);border-left:1px solid var(--border);padding:20px 16px;z-index:50;overflow-y:auto;transition:transform .35s var(--ease)}' +
'.brand{text-align:center;padding:18px 12px;margin-bottom:16px;background:linear-gradient(135deg,rgba(6,182,212,.12),rgba(236,72,153,.08));border-radius:18px;border:1px solid rgba(139,92,246,.22)}' +
'.brand .om{width:48px;height:48px;margin:0 auto 8px;border-radius:14px;object-fit:cover}' +
'.brand .nm{font-size:15px;font-weight:900}' +
'.brand .tg2{font-size:10px;color:var(--muted);margin-top:4px;letter-spacing:.1em;text-transform:uppercase}' +
'.nv{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:12px;color:var(--muted);font-weight:600;font-size:13px;cursor:pointer;transition:.22s;border:1px solid transparent;text-decoration:none;position:relative;overflow:hidden}' +
'.nv:hover{color:var(--text);background:rgba(148,163,184,.06);transform:translateX(-3px)}' +
'.nv.on{color:#fff;background:linear-gradient(90deg,rgba(6,182,212,.2),rgba(139,92,246,.05));border-color:rgba(139,92,246,.28)}' +
'.nv.on::before{content:"";position:absolute;right:0;top:8px;bottom:8px;width:3px;background:var(--grad);border-radius:3px}' +
'.nv .icn{font-size:18px}' +
'.nav-group{font-size:10px;color:var(--muted-2);font-weight:800;letter-spacing:.1em;text-transform:uppercase;padding:12px 6px 6px;opacity:.7}' +
'.dvd{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:14px 0}' +
'.stp{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;background:rgba(148,163,184,.05);border:1px solid var(--border);font-size:12px}' +
'.pd{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite}' +
'@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(16,185,129,.6)}70%{box-shadow:0 0 0 12px rgba(16,185,129,0)}100%{box-shadow:0 0 0 0 rgba(16,185,129,0)}}' +
'.mc{margin-right:280px;padding:28px;min-height:100vh;transition:margin .35s var(--ease)}' +
'@media(max-width:900px){.sb{transform:translateX(100%)}.sb.on{transform:translateX(0)}.mc{margin-right:0;padding:16px;padding-top:76px}.mm{display:flex!important}}' +
'.mm{display:none;position:fixed;top:16px;right:16px;z-index:60;width:46px;height:46px;border-radius:14px;background:rgba(20,26,44,.95);border:1px solid var(--border-2);align-items:center;justify-content:center;cursor:pointer;color:var(--text);backdrop-filter:blur(12px);font-size:22px}' +
'.ov{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:40;opacity:0;pointer-events:none;transition:opacity .3s;backdrop-filter:blur(6px)}.ov.on{opacity:1;pointer-events:auto}' +
'.ph{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:14px;animation:su .5s ease}' +
'.pt{font-size:26px;font-weight:900;background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;display:flex;align-items:center;gap:10px}' +
'.pt .icn{font-size:26px;-webkit-text-fill-color:initial}' +
'.ps{color:var(--muted);font-size:13px;margin-top:6px}' +
'@keyframes su{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}' +
'.gl{background:linear-gradient(180deg,rgba(20,26,44,.75),rgba(12,16,28,.75));backdrop-filter:blur(18px);border:1px solid var(--border);border-radius:22px;position:relative;overflow:hidden}' +
'.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:20px}' +
'.sc{padding:20px;border-radius:20px;background:linear-gradient(180deg,rgba(20,26,44,.75),rgba(12,16,28,.55));backdrop-filter:blur(16px);border:1px solid var(--border);position:relative;overflow:hidden;transition:.3s;animation:su .5s ease backwards}' +
'.sc:hover{transform:translateY(-3px);border-color:rgba(139,92,246,.35);box-shadow:0 15px 40px -15px rgba(99,102,241,.5)}' +
'.sc::after{content:"";position:absolute;top:-50px;right:-50px;width:130px;height:130px;background:radial-gradient(circle,rgba(99,102,241,.25),transparent 70%);pointer-events:none}' +
'.sl{font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.06em;text-transform:uppercase;display:flex;align-items:center;gap:6px;margin-bottom:8px}' +
'.sl .icn{font-size:14px}' +
'.sv{font-size:30px;font-weight:900;letter-spacing:-.03em;line-height:1.1}' +
'.sv small{font-size:14px;color:var(--muted);font-weight:600}' +
'@media(max-width:600px){.sg{grid-template-columns:1fr 1fr;gap:10px}.sc{padding:14px;border-radius:16px}.sv{font-size:22px}.sv small{font-size:11px}.sl{font-size:9px}.pt{font-size:20px}.ph{margin-bottom:14px}}' +
'.cg{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}' +
'@media(max-width:1000px){.cg{grid-template-columns:1fr}}' +
'.cc{padding:20px;border-radius:20px;background:linear-gradient(180deg,rgba(20,26,44,.75),rgba(12,16,28,.6));backdrop-filter:blur(16px);border:1px solid var(--border)}' +
'.ct{font-size:15px;font-weight:800;margin-bottom:16px;display:flex;align-items:center;gap:10px}' +
'.ct .icn{font-size:18px;color:var(--c2)}' +
'.cw{position:relative;height:280px;padding:8px}' +
'.tw{overflow-x:auto;border-radius:20px;background:linear-gradient(180deg,rgba(20,26,44,.7),rgba(12,16,28,.55));backdrop-filter:blur(16px);border:1px solid var(--border);padding:6px}' +
'table{width:100%;border-collapse:collapse;font-size:13px}' +
'th{text-align:right;padding:14px 12px;color:var(--muted);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}' +
'td{padding:14px 12px;border-bottom:1px solid var(--border);vertical-align:middle}' +
'tr:last-child td{border-bottom:none}tr:hover td{background:rgba(148,163,184,.04)}' +
'.mono{font-family:\'JetBrains Mono\',monospace;direction:ltr;text-align:left;font-size:11px;color:var(--muted)}' +
'.bdg{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:999px;font-size:10px;font-weight:700}' +
'.bdg .icn{font-size:11px}' +
'.bdg-ok{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.25)}' +
'.bdg-w{background:rgba(245,158,11,.15);color:#fcd34d;border:1px solid rgba(245,158,11,.25)}' +
'.bdg-d{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}' +
'.bdg-i{background:rgba(56,189,248,.15);color:#7dd3fc;border:1px solid rgba(56,189,248,.25)}' +
'.bdg-m{background:rgba(148,163,184,.12);color:#cbd5e1;border:1px solid var(--border)}' +
'.prg{height:6px;border-radius:999px;background:rgba(148,163,184,.12);overflow:hidden;margin-top:6px}' +
'.prg>div{height:100%;background:var(--grad);border-radius:999px;transition:width .8s}' +
'.prg.w>div{background:linear-gradient(90deg,#f59e0b,#f97316)}.prg.d>div{background:linear-gradient(90deg,#ef4444,#dc2626)}' +
'.fg{display:grid;gap:14px}.fr{display:grid;grid-template-columns:1fr 1fr;gap:14px}' +
'@media(max-width:600px){.fr{grid-template-columns:1fr}}' +
'.fd{display:flex;flex-direction:column;gap:6px}' +
'.fd label{font-size:12px;font-weight:700;color:var(--text-2);display:flex;align-items:center;gap:6px}' +
'.fd label .icn{font-size:13px;color:var(--c2)}' +
'.fd input,.fd select,.fd textarea{width:100%;padding:12px 14px;border-radius:12px;background:rgba(10,14,26,.7);border:1px solid var(--border);color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:.2s}' +
'.fd input:focus,.fd select:focus,.fd textarea:focus{border-color:rgba(139,92,246,.6);box-shadow:0 0 0 4px rgba(99,102,241,.12)}' +
'.fd textarea{resize:vertical;min-height:80px;font-family:\'JetBrains Mono\',monospace}' +
'.stt{font-size:16px;font-weight:800;margin-bottom:14px;display:flex;align-items:center;gap:10px;padding-bottom:12px;border-bottom:1px solid var(--border)}' +
'.stt .icn{font-size:18px;color:var(--c2)}' +
'.mb{position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(10px);display:flex;align-items:center;justify-content:center;z-index:999;padding:20px;animation:fi .25s}' +
'.md{background:linear-gradient(180deg,#141a2c,#0c101c);border:1px solid var(--border-2);border-radius:24px;padding:26px;max-width:640px;width:100%;box-shadow:0 40px 100px -20px rgba(0,0,0,.7);max-height:90vh;overflow-y:auto;animation:pi .3s var(--ease)}' +
'@keyframes fi{from{opacity:0}to{opacity:1}}@keyframes pi{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}' +
'.tst{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:14px 20px;border-radius:14px;background:rgba(20,26,44,.98);border:1px solid var(--border-2);color:var(--text);font-size:13px;font-weight:700;box-shadow:0 20px 50px -10px rgba(0,0,0,.6);display:flex;align-items:center;gap:10px;z-index:1000;animation:ti .35s;max-width:90vw}' +
'.tst .icn{font-size:16px}' +
'@keyframes ti{from{opacity:0;transform:translate(-50%,20px)}to{opacity:1;transform:translate(-50%,0)}}' +
'.tp{display:none;animation:fi .35s}.tp.on{display:block}' +
'.perm-chip{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:10px;background:rgba(148,163,184,.08);border:1px solid var(--border);color:var(--muted);font-size:11px;font-weight:700;cursor:pointer;transition:.2s;user-select:none}' +
'.perm-chip:hover{border-color:rgba(139,92,246,.4);color:#fff}' +
'.perm-chip.on{background:rgba(6,182,212,.18);border-color:rgba(6,182,212,.5);color:#67e8f9}' +
'.cmdk{position:fixed;top:20%;left:50%;transform:translateX(-50%);width:90%;max-width:560px;background:linear-gradient(180deg,#141a2c,#0c101c);border:1px solid var(--border-2);border-radius:20px;box-shadow:0 30px 80px rgba(0,0,0,.7);z-index:1001;overflow:hidden;display:none}' +
'.cmdk.on{display:block;animation:pi .2s var(--ease)}' +
'.cmdk input{width:100%;padding:18px 20px;background:transparent;border:none;color:var(--text);font-size:15px;font-family:inherit;outline:none;border-bottom:1px solid var(--border)}' +
'.cmdk .rl{max-height:340px;overflow-y:auto}' +
'.cmdk .ri{padding:12px 20px;font-size:13px;font-weight:600;color:var(--text-2);cursor:pointer;display:flex;align-items:center;gap:10px;transition:.15s}' +
'.cmdk .ri:hover,.cmdk .ri.on{background:rgba(6,182,212,.12);color:#fff}' +
'.cmdk .ri .icn{font-size:16px;color:var(--c2)}' +
'.badge-live{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:8px;background:rgba(16,185,129,.15);color:#6ee7b7;font-size:10px;font-weight:800}' +
'.tag-mini{display:inline-block;padding:2px 6px;border-radius:6px;background:rgba(139,92,246,.15);color:#c7d2fe;font-size:9px;font-weight:700;margin-left:4px}' +
'.card2{display:grid;grid-template-columns:1fr 1fr;gap:10px}' +
'@media(max-width:600px){.card2{grid-template-columns:1fr 1fr;gap:8px}}' +
'.node-card{padding:14px;border-radius:16px;background:linear-gradient(180deg,rgba(20,26,44,.75),rgba(12,16,28,.55));border:1px solid var(--border);position:relative;transition:.25s}' +
'.node-card:hover{border-color:rgba(139,92,246,.35);transform:translateY(-2px)}' +
'.empty{padding:40px;text-align:center;color:var(--muted);font-size:13px}' +
'.empty .icn{font-size:32px;display:block;margin:0 auto 12px;color:var(--muted-2)}' +
'.pill{padding:8px 14px;border-radius:10px;background:rgba(148,163,184,.06);border:1px solid var(--border);color:var(--muted);font-size:12px;font-weight:700;cursor:pointer;transition:.2s}' +
'.pill:hover{color:var(--text);border-color:rgba(139,92,246,.35)}' +
'.pill.on{background:var(--grad);color:#fff;border-color:transparent}' +
'.switch{position:relative;display:inline-block;width:44px;height:24px}' +
'.switch input{opacity:0;width:0;height:0}' +
'.switch .sl2{position:absolute;inset:0;background:rgba(148,163,184,.2);border-radius:24px;cursor:pointer;transition:.3s}' +
'.switch .sl2::before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.3s}' +
'.switch input:checked + .sl2{background:var(--grad)}' +
'.switch input:checked + .sl2::before{transform:translateX(20px)}' +
'.weather{display:flex;align-items:center;gap:20px;padding:24px;border-radius:20px;background:linear-gradient(135deg,rgba(6,182,212,.1),rgba(236,72,153,.06));border:1px solid rgba(139,92,246,.22)}' +
'.weather-icon{font-size:56px}' +
'.suggestion{padding:14px;border-radius:14px;background:rgba(148,163,184,.05);border:1px solid var(--border);display:flex;gap:12px;align-items:flex-start;transition:.2s}' +
'.suggestion:hover{border-color:rgba(139,92,246,.35);transform:translateX(-3px)}' +
'.suggestion .icn{font-size:28px;color:var(--c2);flex-shrink:0}' +
'.latency-bar{height:8px;border-radius:4px;background:rgba(148,163,184,.15);overflow:hidden;margin-top:6px}' +
'.latency-bar>div{height:100%;border-radius:4px;transition:width .8s}' +
'.tag-chip{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:10px;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.3);color:#c7d2fe;font-size:12px;font-weight:700;cursor:pointer;transition:.2s}' +
'.tag-chip:hover{background:rgba(139,92,246,.2);transform:translateY(-1px)}' +
'.entry-row{display:flex;gap:10px;align-items:center;padding:12px;border-radius:12px;background:rgba(10,14,26,.5);border:1px solid var(--border);margin-bottom:8px}' +
'.entry-row .txt{flex:1;font-family:\'JetBrains Mono\',monospace;font-size:12px;color:var(--text-2)}' +
'.preview-box{padding:16px;border-radius:14px;background:rgba(139,92,246,.08);border:1px dashed rgba(139,92,246,.3);font-family:\'JetBrains Mono\',monospace;font-size:13px;color:#c7d2fe;text-align:center;word-break:break-word}' +
'</style></head><body>' +
'<div class="aurora"></div><div class="grid-bg"></div>' +
'<div id="login" class="login"><div class="lcard">' +
'<div class="otter" id="loginOtter"><svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">' +
'<defs><linearGradient id="f1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#ec4899"/></linearGradient>' +
'<linearGradient id="f2" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#06b6d4"/><stop offset="100%" stop-color="#8b5cf6"/></linearGradient></defs>' +
'<circle cx="26" cy="30" r="10" fill="url(#f2)"/><circle cx="74" cy="30" r="10" fill="url(#f2)"/>' +
'<circle cx="26" cy="30" r="5" fill="#0a0e1a"/><circle cx="74" cy="30" r="5" fill="#0a0e1a"/>' +
'<ellipse cx="50" cy="55" rx="34" ry="34" fill="url(#f1)"/>' +
'<circle cx="39" cy="52" r="4.5" fill="#0a0e1a"/><circle cx="61" cy="52" r="4.5" fill="#0a0e1a"/>' +
'<circle cx="40.5" cy="50.5" r="1.6" fill="#fff"/><circle cx="62.5" cy="50.5" r="1.6" fill="#fff"/>' +
'<ellipse cx="50" cy="66" rx="13" ry="10" fill="#fff" opacity=".9"/><ellipse cx="50" cy="62" rx="3.5" ry="2.5" fill="#0a0e1a"/>' +
'</svg></div>' +
'<h1 class="tg" style="text-align:center;font-size:28px;margin-bottom:6px">__PANEL_NAME__</h1>' +
'<p style="text-align:center;color:var(--muted);font-size:13px;margin-bottom:26px">Design Edition · v__CURRENT_VERSION__</p>' +
'<div id="le" style="display:none;padding:12px 14px;border-radius:12px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;font-size:13px;margin-bottom:16px;text-align:center;font-weight:600"></div>' +
'<div class="fd" style="margin-bottom:14px"><label>نام کاربری</label><input id="lu" class="fld" placeholder="admin" autocomplete="username"></div>' +
'<div class="fd" style="margin-bottom:18px"><label>رمز عبور</label><input id="lp" type="password" class="fld" placeholder="••••••••" autocomplete="current-password"></div>' +
'<button id="lb" class="btn btn-p" style="width:100%;padding:14px">ورود به پنل</button>' +
'<div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:11px;color:var(--muted-2)">' +
'<div>Design Edition</div><div style="margin-top:4px;opacity:.6">v__CURRENT_VERSION__</div>' +
'</div></div></div>' +
'<div id="shell" class="shell">' +
'<div class="ov" id="ov" onclick="tg()"></div>' +
'<button class="mm" onclick="tg()" id="menuBtn"></button>' +
'<aside class="sb" id="sb">' +
'<div class="brand"><div id="brandLogo"></div>' +
'<div class="nm tg">__PANEL_NAME__</div><div class="tg2" id="whoami">Loading...</div></div>' +
'<nav style="display:flex;flex-direction:column;gap:2px" id="nav"></nav>' +
'<div class="dvd"></div>' +
'<div class="stp"><span class="pd"></span><span style="color:var(--muted)">وضعیت:</span><span id="sst" style="font-weight:800;color:var(--ok)">فعال</span></div>' +
'<button class="btn btn-g" style="width:100%;margin-top:12px" onclick="lo()" id="logoutBtn"></button>' +
'<div style="text-align:center;padding:12px 4px 4px;font-size:10px;color:var(--muted-2)">© 2025 <strong style="color:var(--c2)">__PANEL_NAME__</strong><br>v__CURRENT_VERSION__</div>' +
'</aside>' +
'<main class="mc">' +
/* ═══ OVERVIEW ═══ */
'<div id="tab-overview" class="tp on">' +
'<div class="ph"><div><h1 class="pt" id="h-ov"></h1><p class="ps">نمای کلی سیستم</p></div><div><span class="badge-live">● live</span> <button class="btn btn-g btn-s" onclick="ls()" id="refBtn"></button></div></div>' +
'<div class="sg">' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st1"></span> کل کاربران</div><div class="sv" id="st1">0</div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st2"></span> فعال</div><div class="sv" id="st2" style="color:var(--ok)">0</div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st3"></span> متوقف</div><div class="sv" id="st3" style="color:var(--warn)">0</div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st4"></span> منقضی</div><div class="sv" id="st4" style="color:var(--danger)">0</div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st5"></span> ترافیک کل</div><div class="sv" id="st5">0 <small>GB</small></div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st6"></span> امروز</div><div class="sv" id="st6" style="color:var(--info)">0 <small>GB</small></div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st7"></span> اتصالات</div><div class="sv" id="st7">0</div></div>' +
'<div class="sc"><div class="sl"><span class="icn" id="i-st8"></span> آپتایم</div><div class="sv" id="st8" style="font-size:20px">0h</div></div>' +
'</div>' +
'<div class="cg"><div class="cc"><div class="ct"><span class="icn" id="i-chart1"></span> ترافیک ۷ روز</div><div class="cw"><canvas id="ch1"></canvas></div></div>' +
'<div class="cc"><div class="ct"><span class="icn" id="i-chart2"></span> توزیع امروز</div><div class="cw"><canvas id="ch2"></canvas></div></div></div>' +
'<div class="cc"><div class="ct"><span class="icn" id="i-trophy"></span> پرمصرف‌ترین‌ها</div><div id="topUsers"></div></div>' +
'</div>' +
/* ═══ WEATHER ═══ */
'<div id="tab-weather" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-weather-i"></span> وضعیت شبکه</h1><p class="ps">Network Weather</p></div><button class="btn btn-g btn-s" onclick="lweather()" id="wrefBtn"></button></div>' +
'<div id="weatherBox" class="gl" style="padding:24px"><div class="empty"><span class="icn" id="i-loadw"></span>در حال بارگذاری...</div></div></div>' +
/* ═══ USERS ═══ */
'<div id="tab-users" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-users-i"></span> کاربران</h1><p class="ps">مدیریت مشترکین</p></div><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn btn-g btn-s" onclick="exportCsv()" id="expBtn"></button><button class="btn btn-g btn-s" onclick="openImport()" id="impBtn"></button><button class="btn btn-p btn-s" onclick="ou()" id="addUserBtn"></button></div></div>' +
'<div style="margin-bottom:12px"><input id="userSearch" class="fld" placeholder="جستجو..." oninput="ru()" style="max-width:340px"></div>' +
'<div class="tw"><table><thead><tr><th>نام</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="ub"><tr><td colspan="5" class="empty">بارگذاری...</td></tr></tbody></table></div></div>' +
/* ═══ GROUPS ═══ */
'<div id="tab-groups" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-groups-i"></span> گروه‌ها</h1><p class="ps">پلن‌های پیش‌فرض</p></div><button class="btn btn-p btn-s" onclick="og()" id="addGroupBtn"></button></div>' +
'<div id="groupsGrid" class="card2"></div></div>' +
/* ═══ TRAFFIC ═══ */
'<div id="tab-traffic" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-traffic-i"></span> ترافیک</h1><p class="ps">تحلیل دقیق</p></div></div>' +
'<div style="display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap"><div class="pill on" onclick="setDays(7,this)">۷ روز</div><div class="pill" onclick="setDays(14,this)">۱۴ روز</div><div class="pill" onclick="setDays(30,this)">۳۰ روز</div></div>' +
'<div class="cc" style="margin-bottom:16px"><div class="ct">📊 مصرف کل (GB)</div><div class="cw" style="height:300px"><canvas id="ch3"></canvas></div></div>' +
'<div class="cc" style="margin-bottom:16px"><div class="ct">📈 مقایسه کاربران</div><div class="cw" style="height:340px"><canvas id="ch4"></canvas></div></div>' +
'<div class="cc"><div class="ct">🎯 مقایسه دوره‌ای</div><div class="fr" style="margin-bottom:12px"><div class="fd"><label>ID کاربران</label><input id="cmpIds" placeholder="u_abc,u_def"></div><div class="fd"><label>روز</label><input id="cmpDays" type="number" value="14"></div></div><button class="btn btn-p btn-s" onclick="runCompare()">مقایسه</button><div class="cw" style="height:300px;margin-top:12px"><canvas id="ch5"></canvas></div></div></div>' +
/* ═══ ANOMALIES ═══ */
'<div id="tab-anomalies" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-anom-i"></span> هشدارها</h1><p class="ps">مصرف غیرعادی</p></div><button class="btn btn-g btn-s" onclick="lanom()" id="anomRefBtn"></button></div>' +
'<div id="anomList" class="gl" style="padding:18px"><div class="empty">در حال بررسی...</div></div></div>' +
/* ═══ PREDICTIVE ═══ */
'<div id="tab-predictive" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-pred-i"></span> پیش‌بینی</h1><p class="ps">Predictive Analytics</p></div><button class="btn btn-g btn-s" onclick="lpredictive()" id="predRefBtn"></button></div>' +
'<div id="predictiveBox" class="gl" style="padding:18px;margin-bottom:16px"><div class="empty">در حال محاسبه...</div></div>' +
'<div class="cc"><div class="ct">📈 نمودار پیش‌بینی</div><div class="cw"><canvas id="chPred"></canvas></div></div></div>' +
/* ═══ SUGGESTIONS ═══ */
'<div id="tab-suggestions" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-sug-i"></span> پیشنهادات</h1><p class="ps">Smart Suggestions</p></div><button class="btn btn-g btn-s" onclick="lsug()" id="sugRefBtn"></button></div>' +
'<div id="sugList" class="fg"></div></div>' +
/* ═══ INBOUNDS (NEW) ═══ */
'<div id="tab-inbounds" class="tp">' +
'<div class="ph"><div><h1 class="pt"><span class="icn" id="h-inb-i"></span> اینباند کانفیگ‌ها</h1><p class="ps">تنظیم نام و ورودی‌های کانفیگ‌ها</p></div><button class="btn btn-p btn-s" onclick="saveInboundGlobal()" id="saveInbBtn"></button></div>' +
'<div class="gl" style="padding:20px;margin-bottom:16px"><div class="stt"><span class="icn" id="i-inb1"></span> تنظیمات سراسری</div>' +
'<div class="fg">' +
'<div class="fr"><div class="fd"><label>الگوی نام‌گذاری</label><input id="inb-template" class="fld" placeholder="{FLAG} {PREFIX}-{INDEX}"></div><div class="fd"><label>پیشوند</label><input id="inb-prefix" class="fld" placeholder="Hamed"></div></div>' +
'<div class="fr"><div class="fd"><label>حداکثر طول نام</label><input id="inb-maxlen" type="number" class="fld" value="60"></div><div class="fd"><label>فقط کاراکترهای ASCII</label><div style="padding-top:12px"><label class="switch"><input id="inb-ascii" type="checkbox"><span class="sl2"></span></label></div></div></div>' +
'<div class="fd"><label>پیش‌نمایش</label><div class="preview-box" id="inb-preview">🇩🇪 Hamed-1</div></div>' +
'<div class="fd"><label>تگ‌های موجود (کلیک کنید تا در الگو قرار بگیرد)</label><div id="inb-tags" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px"></div></div>' +
'</div>' +
'<div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap"><button class="btn btn-p" onclick="saveInboundGlobal()" id="inbSaveBtn"></button><button class="btn btn-g" onclick="previewInbound()">پیش‌نمایش</button><button class="btn btn-d" onclick="applyGlobalToAll()">اعمال به همه کاربران</button></div>' +
'</div>' +
'<div class="gl" style="padding:20px;margin-bottom:16px"><div class="stt"><span class="icn" id="i-inb2"></span> ورودی‌های استاتیک (Extra Entries)</div>' +
'<div style="font-size:12px;color:var(--muted);margin-bottom:12px">این متن‌ها به‌صورت کانفیگ اضافی در ابتدا یا انتهای لینک اشتراک اضافه می‌شوند.</div>' +
'<div id="entriesList"></div>' +
'<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">' +
'<input id="newEntryText" class="fld" placeholder="متن ورودی (مثلاً THIS PANEL MADE BY HAMED TEAM)" style="flex:2;min-width:200px">' +
'<input id="newEntryFlag" class="fld" placeholder="پیشوند (اختیاری)" style="width:120px">' +
'<select id="newEntryPos" class="fld" style="width:120px"><option value="start">ابتدا</option><option value="end">انتها</option></select>' +
'<button class="btn btn-p" onclick="addEntry()">افزودن</button>' +
'</div></div>' +
'<div class="gl" style="padding:20px"><div class="stt"><span class="icn" id="i-inb3"></span> تنظیمات اختصاصی هر کاربر</div>' +
'<div style="font-size:12px;color:var(--muted);margin-bottom:12px">برای هر کاربر می‌توانید الگوی نام و ورودی‌های جداگانه تعریف کنید. اگر خالی باشد، از تنظیمات سراسری استفاده می‌شود.</div>' +
'<div class="tw" style="border:none;padding:0"><table><thead><tr><th>کاربر</th><th>الگوی سفارشی</th><th>Override</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="inbUserBody"></tbody></table></div>' +
'</div></div>' +
/* ═══ MANAGERS ═══ */
'<div id="tab-managers" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-mgr-i"></span> مدیران</h1><p class="ps">مدیریت دسترسی</p></div><button class="btn btn-p btn-s" onclick="om()" id="addMgrBtn"></button></div>' +
'<div class="tw"><table><thead><tr><th>کاربر</th><th>دسترسی</th><th>وضعیت</th><th>آخرین ورود</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="mb"></tbody></table></div></div>' +
/* ═══ SESSIONS ═══ */
'<div id="tab-sessions" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-sess-i"></span> نشست‌ها</h1><p class="ps">جلسات فعال</p></div><button class="btn btn-d btn-s" onclick="revokeAll()" id="revAllBtn"></button></div>' +
'<div class="tw"><table><thead><tr><th>کاربر</th><th>IP</th><th>شروع</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="sessBody"></tbody></table></div></div>' +
/* ═══ NODES ═══ */
'<div id="tab-nodes" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-node-i"></span> نودها</h1><p class="ps">پنل‌های متصل</p></div><div style="display:flex;gap:6px"><button class="btn btn-g btn-s" onclick="healthAll()" id="hltBtn"></button><button class="btn btn-p btn-s" onclick="onNode()" id="addNodeBtn"></button></div></div>' +
'<div id="nodesGrid" class="card2"></div></div>' +
/* ═══ BANNED ═══ */
'<div id="tab-banned" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-ban-i"></span> IPهای بسته</h1><p class="ps">آی‌پی‌های مسدود شده</p></div><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn btn-g btn-s" onclick="lbanned()" id="brefBtn"></button><button class="btn btn-p btn-s" onclick="oban()" id="banBtn"></button><button class="btn btn-d btn-s" onclick="clearBanned()" id="clrBanBtn"></button></div></div>' +
'<div class="tw"><table><thead><tr><th>IP</th><th>دلیل</th><th>زمان</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="banBody"></tbody></table></div></div>' +
/* ═══ WORKFLOWS ═══ */
'<div id="tab-workflows" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-wf-i"></span> Workflows</h1><p class="ps">اتوماسیون خودکار</p></div><button class="btn btn-p btn-s" onclick="owf()" id="addWfBtn"></button></div>' +
'<div id="wfGrid" class="card2"></div></div>' +
/* ═══ CRON ═══ */
'<div id="tab-cron" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-cron-i"></span> Cron Jobs</h1><p class="ps">تسک‌های زمان‌بندی‌شده</p></div><button class="btn btn-p btn-s" onclick="ocron()" id="addCronBtn"></button></div>' +
'<div id="cronGrid" class="card2"></div></div>' +
/* ═══ WEBHOOKS ═══ */
'<div id="tab-webhooks" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-wh-i"></span> Webhooks</h1><p class="ps">اعلان به سرویس‌های خارجی</p></div><button class="btn btn-p btn-s" onclick="owh()" id="addWhBtn"></button></div>' +
'<div id="whGrid" class="card2"></div></div>' +
/* ═══ CRISIS ═══ */
'<div id="tab-crisis" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-cri-i"></span> اعلان بحران</h1><p class="ps">ارسال پیام فوری</p></div></div>' +
'<div class="gl" style="padding:20px;margin-bottom:16px"><div class="stt"><span class="icn" id="i-cri1"></span> پیام فوری</div>' +
'<div class="fg"><div class="fd"><label>پیام</label><textarea id="crisisMsg" rows="3" placeholder="متن..."></textarea></div>' +
'<button class="btn btn-p" onclick="sendCrisis()" style="justify-self:flex-start">ارسال به همه</button></div></div>' +
'<div class="gl" style="padding:20px;margin-bottom:16px"><div class="stt"><span class="icn" id="i-cri2"></span> پریست‌ها</div><div id="crisisPresets" class="card2"></div></div>' +
'<div class="gl" style="padding:20px"><div class="stt"><span class="icn" id="i-cri3"></span> تاریخچه</div><div id="crisisHistory"></div></div></div>' +
/* ═══ REGIONS ═══ */
'<div id="tab-regions" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-reg-i"></span> مناطق IP</h1><p class="ps">Clean IP Regions</p></div><div style="display:flex;gap:6px"><button class="btn btn-g btn-s" onclick="runCleanIp()" id="ciTestBtn"></button><button class="btn btn-p btn-s" onclick="oregion()" id="addRegBtn"></button></div></div>' +
'<div class="gl" style="padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap"><label style="display:flex;align-items:center;gap:8px;font-size:12px"><input type="checkbox" id="autoClean" onchange="toggleAutoClean()"> تست خودکار هر ساعت</label><span id="cleanInfo" style="font-size:11px;color:var(--muted)"></span></div>' +
'<div id="regionsGrid" class="card2" style="margin-bottom:16px"></div>' +
'<div class="gl" style="padding:18px"><div class="stt">📊 نتایج آخرین تست</div><div class="tw" style="border:none;padding:0"><table><thead><tr><th>IP</th><th>Ping</th></tr></thead><tbody id="cleanBody"><tr><td colspan="2" class="empty">هنوز تست نشده</td></tr></tbody></table></div></div></div>' +
/* ═══ ISP ═══ */
'<div id="tab-isp" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-isp-i"></span> قالب اپراتور</h1><p class="ps">ISP Templates</p></div><button class="btn btn-p btn-s" onclick="saveIsp()" id="ispSaveBtn"></button></div>' +
'<div id="ispGrid" class="fg"></div></div>' +
/* ═══ DNS ═══ */
'<div id="tab-dns" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-dns-i"></span> DNS Pool</h1><p class="ps">استخر DNS</p></div><div style="display:flex;gap:6px"><button class="btn btn-g btn-s" onclick="dnsTest()" id="dnsTestBtn"></button><button class="btn btn-p btn-s" onclick="saveDns()" id="dnsSaveBtn"></button></div></div>' +
'<div class="gl" style="padding:18px;margin-bottom:16px"><div class="fd"><label>استراتژی</label><select id="dnsStrategy"><option value="weighted">Weighted</option><option value="random">Random</option></select></div></div>' +
'<div id="dnsGrid" class="fg"></div></div>' +
/* ═══ UPSTREAMS ═══ */
'<div id="tab-upstreams" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-up-i"></span> Upstreams</h1><p class="ps">سرورهای زنجیره‌ای</p></div><button class="btn btn-p btn-s" onclick="oupstream()" id="addUpBtn"></button></div>' +
'<div id="upstreamGrid" class="fg"></div></div>' +
/* ═══ SPEEDTEST ═══ */
'<div id="tab-speedtest" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-spd-i"></span> تست سرعت</h1></div><button class="btn btn-p btn-s" onclick="runSpeed()" id="runSpdBtn"></button></div>' +
'<div class="tw"><table><thead><tr><th>Host</th><th>Latency</th><th>Status</th></tr></thead><tbody id="speedBody"><tr><td colspan="3" class="empty">تست نشده</td></tr></tbody></table></div></div>' +
/* ═══ LATENCY ═══ */
'<div id="tab-latency" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-lat-i"></span> Latency Map</h1></div><button class="btn btn-g btn-s" onclick="llatency()" id="latRefBtn"></button></div>' +
'<div id="latencyGrid" class="fg"></div></div>' +
/* ═══ DPI ═══ */
'<div id="tab-dpi" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-dpi-i"></span> DPI Detection</h1></div><button class="btn btn-p btn-s" onclick="runDpi()" id="dpiBtn"></button></div>' +
'<div id="dpiBox" class="gl" style="padding:24px"><div class="empty">برای بررسی کلیک کنید</div></div></div>' +
/* ═══ SETTINGS ═══ */
'<div id="tab-settings" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-set-i"></span> تنظیمات</h1><p class="ps">پیکربندی اصلی</p></div></div>' +
'<div class="gl" style="padding:24px"><div class="stt">🌐 پیکربندی</div><div class="fg">' +
'<div class="fr"><div class="fd"><label>نام پنل</label><input id="c1"></div><div class="fd"><label>مسیر API</label><input id="c2" disabled></div></div>' +
'<div class="fr"><div class="fd"><label>کلید اصلی</label><input id="c3" type="password"></div><div class="fd"><label>پروتکل</label><select id="c4"><option value="alpha">Alpha (VLESS)</option><option value="beta">Beta (Trojan)</option><option value="both">Both</option></select></div></div>' +
'<div class="fr"><div class="fd"><label>پورت‌ها</label><input id="c5"></div><div class="fd"><label>DNS</label><input id="c6"></div></div>' +
'<div class="fd"><label>سایت استتار</label><input id="c7"></div>' +
'<div class="fd"><label>آی‌پی تمیز دستی</label><textarea id="c8" rows="4"></textarea></div>' +
'<div class="stt" style="margin-top:20px">🎨 لوگو</div>' +
'<div class="fd"><label>Base64 یا URL</label><input id="c9"></div>' +
'<div class="fd"><label>رنگ عنوان</label><input id="c10" placeholder="#8b5cf6"></div>' +
'</div><div style="display:flex;gap:10px;margin-top:20px;flex-wrap:wrap"><button class="btn btn-p" onclick="sc()">ذخیره</button><button class="btn btn-g" onclick="fc()">بازنشانی</button><button class="btn btn-d" onclick="clearLogo()">حذف لوگو</button></div></div></div>' +
/* ═══ ADVANCED ═══ */
'<div id="tab-advanced" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-adv-i"></span> تنظیمات پیشرفته</h1></div></div>' +
'<div class="gl" style="padding:24px;display:grid;gap:20px">' +
'<div><div class="stt">🇮🇷 بهینه‌سازی ایران</div><div class="fg">' +
'<div class="fr"><div class="fd"><label>اپراتور پیش‌فرض</label><select id="a9"><option value="">هیچ</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="mokhaberat">مخابرات</option></select></div>' +
'<div class="fd"><label>Fragment Preset</label><select id="a10"></select></div></div>' +
'<div class="fd"><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="a11" style="width:auto"> مسیردهی دامنه‌های ایرانی</label></div>' +
'</div></div>' +
'<div><div class="stt">☁️ Cloudflare</div><div class="fg">' +
'<div class="fr"><div class="fd"><label>Account ID</label><input id="a1"></div><div class="fd"><label>API Token</label><input id="a2" type="password"></div></div>' +
'<div class="fd"><label>Worker Name</label><input id="a3"></div>' +
'</div></div>' +
'<div><div class="stt">🤖 Telegram</div><div class="fg">' +
'<div class="fr"><div class="fd"><label>Bot Token</label><input id="a4" type="password"></div><div class="fd"><label>Chat ID</label><input id="a5"></div></div>' +
'<div class="fd"><label>Admin ID</label><input id="a6"></div>' +
'</div></div>' +
'<div><div class="stt">🖥️ رله و NAT64</div><div class="fg">' +
'<div class="fd"><label>آی‌پی رله</label><textarea id="a7" rows="3"></textarea></div>' +
'<div class="fd"><label>NAT64 Prefix</label><input id="a8"></div>' +
'</div></div>' +
'<div><button class="btn btn-p" onclick="sc()">ذخیره</button></div></div></div>' +
/* ═══ APIKEYS ═══ */
'<div id="tab-apikeys" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-key-i"></span> API Keys</h1></div><button class="btn btn-p btn-s" onclick="ck()" id="addKeyBtn"></button></div>' +
'<div class="tw"><table><thead><tr><th>نام</th><th>کلید</th><th>تاریخ</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="kb"></tbody></table></div></div>' +
/* ═══ BACKUP ═══ */
'<div id="tab-backup" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-bk-i"></span> پشتیبان</h1></div><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn btn-g btn-s" onclick="exportConfig()" id="expCfgBtn"></button><button class="btn btn-g btn-s" onclick="openImportConfig()" id="impCfgBtn"></button><button class="btn btn-p btn-s" onclick="makeBackup()" id="mkBkBtn"></button></div></div>' +
'<div class="tw"><table><thead><tr><th>فایل</th><th>اندازه</th><th>تاریخ</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="backupBody"><tr><td colspan="4" class="empty">بارگذاری...</td></tr></tbody></table></div></div>' +
/* ═══ LOGS ═══ */
'<div id="tab-logs" class="tp"><div class="ph"><div><h1 class="pt"><span class="icn" id="h-log-i"></span> لاگ‌ها</h1></div><button class="btn btn-g btn-s" onclick="ll()" id="logRefBtn"></button></div>' +
'<div class="gl" style="padding:18px"><div id="lc" style="display:flex;flex-direction:column;gap:8px"></div></div></div>' +
'</main></div>' +
/* MODALS */
'<div id="um" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 id="umt" class="tg" style="font-size:18px">کاربر جدید</h3><button class="btn btn-g btn-s" onclick="cu()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="u1"></div>' +
'<div class="fr"><div class="fd"><label>گروه</label><select id="u6"></select></div><div class="fd"><label>اپراتور</label><select id="u9"><option value="">هیچ</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="mokhaberat">مخابرات</option></select></div></div>' +
'<div class="fr"><div class="fd"><label>ترافیک (GB)</label><input id="u2" type="number" placeholder="0=∞"></div><div class="fd"><label>روزانه (GB)</label><input id="u3" type="number" placeholder="0=∞"></div></div>' +
'<div class="fr"><div class="fd"><label>اعتبار (روز)</label><input id="u4" type="number" placeholder="0=∞"></div><div class="fd"><label>محدودیت کانفیگ</label><input id="u7" type="number" placeholder="0=∞"></div></div>' +
'<div class="fr"><div class="fd"><label>پهنای باند (Kbps)</label><input id="u10" type="number" placeholder="0=∞"></div><div class="fd"><label>بازنشانی</label><select id="u8"><option value="none">غیرفعال</option><option value="daily">روزانه</option><option value="weekly">هفتگی</option><option value="monthly">ماهانه</option></select></div></div>' +
'<div class="fd"><label>برچسب‌ها (با کاما)</label><input id="u11" placeholder="VIP,Premium"></div>' +
'<div class="fd"><label>یادداشت</label><input id="u5"></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="su2()">ذخیره</button><button class="btn btn-g" onclick="cu()">انصراف</button></div></div></div></div>' +
'<div id="gml" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 id="gmt" class="tg" style="font-size:18px">گروه</h3><button class="btn btn-g btn-s" onclick="cg()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="g1"></div>' +
'<div class="fr"><div class="fd"><label>ترافیک (GB)</label><input id="g2" type="number"></div><div class="fd"><label>روزانه (GB)</label><input id="g3" type="number"></div></div>' +
'<div class="fr"><div class="fd"><label>اعتبار (روز)</label><input id="g4" type="number"></div><div class="fd"><label>حداکثر کانفیگ</label><input id="g5" type="number"></div></div>' +
'<div class="fd"><label>محدودیت اتصال</label><input id="g6" type="number"></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="sg2()">ذخیره</button><button class="btn btn-g" onclick="cg()">انصراف</button></div></div></div></div>' +
'<div id="mm2" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 id="mmt" class="tg" style="font-size:18px">مدیر</h3><button class="btn btn-g btn-s" onclick="cm()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام کاربری</label><input id="m1"></div>' +
'<div class="fd"><label>رمز</label><input id="m2" type="password"></div>' +
'<div class="fd"><label>دسترسی‌ها</label><div id="mp" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px"></div></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="sm()">ذخیره</button><button class="btn btn-g" onclick="cm()">انصراف</button></div></div></div></div>' +
'<div id="nm" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">نود</h3><button class="btn btn-g btn-s" onclick="cn()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="n1"></div>' +
'<div class="fd"><label>آدرس</label><input id="n2" placeholder="https://..."></div>' +
'<div class="fd"><label>API Key</label><input id="n3" type="password"></div>' +
'<div class="fd"><label>گروه</label><input id="n4" placeholder="default"></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="sn()">ذخیره</button><button class="btn btn-g" onclick="cn()">انصراف</button></div></div></div></div>' +
'<div id="rm" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">منطقه</h3><button class="btn btn-g btn-s" onclick="cr()">✕</button></div>' +
'<div class="fg"><div class="fr"><div class="fd"><label>نام</label><input id="r1"></div><div class="fd"><label>پرچم</label><input id="r2" placeholder="🇩🇪"></div></div>' +
'<div class="fd"><label>آی‌پی‌ها (خط‌به‌خط)</label><textarea id="r3" rows="6"></textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="sr2()">ذخیره</button><button class="btn btn-g" onclick="cr()">انصراف</button></div></div></div></div>' +
'<div id="com" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 id="comt" class="tg" style="font-size:18px">Cron Job</h3><button class="btn btn-g btn-s" onclick="ccj()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="cj1"></div>' +
'<div class="fd"><label>عملیات</label><select id="cj2"></select></div>' +
'<div class="fd"><label>پارامترها (JSON)</label><textarea id="cj3" rows="3">{"userId":""}</textarea></div>' +
'<div class="fr"><div class="fd"><label>فاصله (دقیقه)</label><input id="cj4" type="number" value="60"></div><div class="fd"><label>فعال</label><div style="padding-top:8px"><label class="switch"><input id="cj5" type="checkbox" checked><span class="sl2"></span></label></div></div></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="scj()">ذخیره</button><button class="btn btn-g" onclick="ccj()">انصراف</button></div></div></div></div>' +
'<div id="whm" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Webhook</h3><button class="btn btn-g btn-s" onclick="cwh()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>URL</label><input id="wh1" placeholder="https://hooks.slack.com/..."></div>' +
'<div class="fd"><label>رویدادها</label><div id="whEvents" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px"></div></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="swh()">ذخیره</button><button class="btn btn-g" onclick="cwh()">انصراف</button></div></div></div></div>' +
'<div id="bam" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Ban IP</h3><button class="btn btn-g btn-s" onclick="cban()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>IP</label><input id="b1"></div>' +
'<div class="fd"><label>دلیل</label><input id="b2" placeholder="Suspicious"></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-d" style="flex:1" onclick="doban()">Ban</button><button class="btn btn-g" onclick="cban()">انصراف</button></div></div></div></div>' +
'<div id="wfm" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Workflow</h3><button class="btn btn-g btn-s" onclick="cwf()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="wf1"></div>' +
'<div class="fd"><label>Trigger</label><select id="wf2"></select></div>' +
'<div class="fd"><label>Actions (JSON)</label><textarea id="wf3" rows="5">[{"type":"send.telegram","params":{"message":"سلام {name}"}}]</textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="swf()">ذخیره</button><button class="btn btn-g" onclick="cwf()">انصراف</button></div></div></div></div>' +
'<div id="upm" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Upstream</h3><button class="btn btn-g btn-s" onclick="cup()">✕</button></div>' +
'<div class="fg"><div class="fd"><label>نام</label><input id="up1"></div>' +
'<div class="fd"><label>VLESS URI</label><textarea id="up2" rows="3" placeholder="vless://..."></textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="sup()">ذخیره</button><button class="btn btn-g" onclick="cup()">انصراف</button></div></div></div></div>' +
'<div id="iuom" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 id="iuomTitle" class="tg" style="font-size:18px">Override کاربر</h3><button class="btn btn-g btn-s" onclick="ciuo()">✕</button></div>' +
'<div class="fg">' +
'<div class="fd"><label>الگوی نام سفارشی</label><input id="iuo-template" class="fld" placeholder="{FLAG} {USER}-{INDEX}"></div>' +
'<div class="fd"><label>ورودی‌های استاتیک اختصاصی (یکی در هر خط)</label><textarea id="iuo-entries" rows="4" placeholder="THIS PANEL MADE BY HAMED TEAM&#10;VIP USER"></textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:8px"><button class="btn btn-p" style="flex:1" onclick="saveUserInbound()">ذخیره</button><button class="btn btn-d" onclick="removeUserInbound()">حذف Override</button><button class="btn btn-g" onclick="ciuo()">انصراف</button></div>' +
'</div></div></div>' +
'<div id="im" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Import CSV</h3><button class="btn btn-g btn-s" onclick="ci()">✕</button></div>' +
'<div class="fd"><label>محتوای CSV</label><textarea id="csvData" rows="10"></textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:12px"><button class="btn btn-p" style="flex:1" onclick="doImport()">آپلود</button><button class="btn btn-g" onclick="ci()">انصراف</button></div></div></div>' +
'<div id="imc" class="mb" style="display:none"><div class="md">' +
'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px"><h3 class="tg" style="font-size:18px">Import JSON</h3><button class="btn btn-g btn-s" onclick="cic()">✕</button></div>' +
'<div class="fd"><label>محتوای JSON</label><textarea id="jsonData" rows="10"></textarea></div>' +
'<div style="display:flex;gap:10px;margin-top:12px"><button class="btn btn-p" style="flex:1" onclick="doImportConfig()">آپلود</button><button class="btn btn-g" onclick="cic()">انصراف</button></div></div></div>' +
'<div id="cmdk" class="cmdk"><input id="ck2" placeholder="جستجو... (Ctrl+K)" autocomplete="off"><div class="rl" id="ckl"></div></div>' +
'<div id="tb"></div>' +
'<script>' +
/* ═══ SVG ICON LIBRARY ═══ */
'const ICONS={' +
'home:\'<svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>\',' +
'users:\'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>\',' +
'group:\'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>\',' +
'chart:\'<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 4-6"/></svg>\',' +
'alert:\'<svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>\',' +
'predict:\'<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"/></svg>\',' +
'bulb:\'<svg viewBox="0 0 24 24"><path d="M9 18h6M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.2 1 2.3h6c0-1.1.4-1.8 1-2.3A7 7 0 0 0 12 2z"/></svg>\',' +
'crown:\'<svg viewBox="0 0 24 24"><path d="M3 6l4.5 5L12 4l4.5 7L21 6v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>\',' +
'activity:\'<svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>\',' +
'server:\'<svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>\',' +
'ban:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>\',' +
'workflow:\'<svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>\',' +
'clock:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>\',' +
'webhook:\'<svg viewBox="0 0 24 24"><path d="M18 16.98h-5.99c-1.1 0-2.12.5-2.83 1.34A4.95 4.95 0 0 1 5 20a5 5 0 1 1 5-5"/><path d="M6 8h15a3 3 0 0 1 3 3v6"/></svg>\',' +
'crisis:\'<svg viewBox="0 0 24 24"><path d="M12 2L2 22h20L12 2zM12 9v5M12 18v.01"/></svg>\',' +
'globe:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>\',' +
'wifi:\'<svg viewBox="0 0 24 24"><path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/></svg>\',' +
'layers:\'<svg viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>\',' +
'link:\'<svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>\',' +
'zap:\'<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>\',' +
'gauge:\'<svg viewBox="0 0 24 24"><path d="M12 20v-6M6 20V10M18 20V4"/></svg>\',' +
'radar:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>\',' +
'shield:\'<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>\',' +
'settings:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33"/></svg>\',' +
'sliders:\'<svg viewBox="0 0 24 24"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>\',' +
'key:\'<svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>\',' +
'save:\'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>\',' +
'log:\'<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>\',' +
'tag:\'<svg viewBox="0 0 24 24"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>\',' +
'menu:\'<svg viewBox="0 0 24 24"><path d="M3 12h18M3 6h18M3 18h18"/></svg>\',' +
'refresh:\'<svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>\',' +
'plus:\'<svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>\',' +
'edit:\'<svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>\',' +
'trash:\'<svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>\',' +
'pause:\'<svg viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>\',' +
'play:\'<svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>\',' +
'external:\'<svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>\',' +
'logout:\'<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>\',' +
'trophy:\'<svg viewBox="0 0 24 24"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16M10 14.66V17c0 .55.47.98.97 1.21C9.5 19.5 9 20.5 9 21M14 14.66V17c0 .55-.47.98-.97 1.21C14.5 19.5 15 20.5 15 21"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2z"/></svg>\',' +
'cloud:\'<svg viewBox="0 0 24 24"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>\',' +
'sun:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>\',' +
'rain:\'<svg viewBox="0 0 24 24"><path d="M16 13v8M8 13v8M12 15v8M20 16.58A5 5 0 0 0 18 7h-1.26A8 8 0 1 0 4 15.25"/></svg>\',' +
'storm:\'<svg viewBox="0 0 24 24"><path d="M19 16.9A5 5 0 0 0 18 7h-1.26a8 8 0 1 0-11.62 9"/><polyline points="13 11 9 17 15 17 11 23"/></svg>\',' +
'info:\'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>\',' +
'check:\'<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>\',' +
'x:\'<svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>\',' +
'download:\'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>\',' +
'upload:\'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>\',' +
'play2:\'<svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>\',' +
'eye:\'<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>\',' +
'scan:\'<svg viewBox="0 0 24 24"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/></svg>\'};' +
'function icon(name,cls){const svg=ICONS[name]||ICONS.info;return \'<span class="icn \'+(cls||"")+\'">\'+svg+\'</span>\'}' +
'function setIcon(id,name){const el=document.getElementById(id);if(el){el.innerHTML=ICONS[name]||ICONS.info}}' +
'const AR="__API_ROUTE__",PN="__PANEL_NAME__";' +
'let S={token:null,me:null,config:null,users:[],managers:[],groups:[],sessions:[],nodes:[],regions:[],activeRegions:[],cronJobs:[],cronActions:[],webhooks:[],webhookEvents:[],banned:[],crisisPresets:[],crisisHistory:[],ispTemplates:{},workflows:[],workflowTriggers:[],workflowActions:[],upstreams:[],dnsPool:[],dnsStrategy:"weighted",inbound:null,inboundUsers:[],editU:null,editG:null,editM:null,editCron:null,editWh:null,editRegion:null,editWf:null,editUserInbound:null,days:7,pollTimer:null,charts:{}};' +
'const $=id=>document.getElementById(id);' +
'function ts(m,t){t=t||"info";const c={info:"#38bdf8",ok:"#10b981",warn:"#f59e0b",error:"#ef4444"}[t],ic={info:"info",ok:"check",warn:"alert",error:"x"}[t];const e=document.createElement("div");e.className="tst";e.style.borderLeft="3px solid "+c;e.innerHTML=icon(ic)+\'<span style="color:\'+c+\'">\'+m+\'</span>\';$("tb").appendChild(e);setTimeout(()=>{e.style.opacity="0";e.style.transition=".3s";setTimeout(()=>e.remove(),300)},3000)}' +
'async function ap(p,o){o=o||{};const h=Object.assign({"Content-Type":"application/json"},o.headers||{});if(S.token)h.Authorization="Bearer "+S.token;const r=await fetch("/"+AR+p,Object.assign({},o,{headers:h}));let d;try{d=await r.json()}catch(e){d={}}return{ok:r.ok,status:r.status,data:d}}' +
'function showLoginError(m){const el=$("le");el.style.display="block";el.textContent=m}' +
'async function login(){const u=$("lu").value.trim(),p=$("lp").value;if(!u||!p){showLoginError("نام و رمز الزامی");return}const b=$("lb");b.disabled=true;b.textContent="در حال ورود...";$("le").style.display="none";try{const r=await fetch("/"+AR+"/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});let d;try{d=await r.json()}catch(pe){showLoginError("پاسخ نامعتبر ("+r.status+")");b.disabled=false;b.textContent="ورود به پنل";return}if(d.ok||d.success){const sess=(d.data&&d.data.session)||d.session;const cfg=(d.data&&d.data.config)||d.config;if(!sess||!sess.token){showLoginError("توکن دریافت نشد");b.disabled=false;b.textContent="ورود به پنل";return}S.token=sess.token;S.me=sess;S.config=cfg||{};sessionStorage.setItem("hp_token",S.token);sessionStorage.setItem("hp_user",u);show()}else{showLoginError(d.error||"خطا");b.disabled=false;b.textContent="ورود به پنل"}}catch(e){showLoginError("خطا: "+(e.message||"network"));b.disabled=false;b.textContent="ورود به پنل"}}' +
'function renderNav(){const perms=S.me.isRoot||S.me.permissions.includes("all")||S.me.permissions;const has=p=>S.me.isRoot||S.me.permissions.includes("all")||S.me.permissions.includes(p);const items=[{g:"عمومی"},{t:"overview",i:"home",l:"داشبورد"},{t:"weather",i:"sun",l:"وضعیت شبکه"},{t:"users",i:"users",l:"کاربران",p:"users"},{t:"groups",i:"group",l:"گروه‌ها",p:"groups"},{t:"traffic",i:"chart",l:"ترافیک",p:"stats"},{t:"anomalies",i:"alert",l:"هشدارها",p:"stats"},{t:"predictive",i:"predict",l:"پیش‌بینی",p:"stats"},{t:"suggestions",i:"bulb",l:"پیشنهادات",p:"stats"},{g:"مدیریت"},{t:"managers",i:"crown",l:"مدیران",p:"managers"},{t:"sessions",i:"activity",l:"نشست‌ها",p:"managers"},{t:"nodes",i:"server",l:"نودها",p:"nodes"},{t:"banned",i:"ban",l:"IPهای بسته",p:"advanced"},{g:"اتوماسیون"},{t:"workflows",i:"workflow",l:"Workflows",p:"advanced"},{t:"cron",i:"clock",l:"Cron Jobs",p:"cron"},{t:"webhooks",i:"webhook",l:"Webhooks",p:"webhooks"},{t:"crisis",i:"crisis",l:"اعلان بحران",p:"users"},{g:"شبکه"},{t:"inbounds",i:"tag",l:"اینباند کانفیگ",p:"inbounds"},{t:"regions",i:"globe",l:"مناطق IP",p:"advanced"},{t:"isp",i:"wifi",l:"قالب اپراتور",p:"advanced"},{t:"dns",i:"layers",l:"DNS Pool",p:"advanced"},{t:"upstreams",i:"link",l:"Upstreams",p:"advanced"},{t:"speedtest",i:"gauge",l:"تست سرعت",p:"advanced"},{t:"latency",i:"radar",l:"Latency Map",p:"stats"},{t:"dpi",i:"shield",l:"DPI Detection",p:"advanced"},{g:"تنظیمات"},{t:"settings",i:"settings",l:"تنظیمات",p:"settings"},{t:"advanced",i:"sliders",l:"پیشرفته",p:"advanced"},{t:"apikeys",i:"key",l:"API Keys",p:"apikeys"},{t:"backup",i:"save",l:"پشتیبان",p:"backup"},{t:"logs",i:"log",l:"لاگ‌ها",p:"logs"}];let h="";items.forEach(x=>{if(x.g){h+=\'<div class="nav-group">\'+x.g+\'</div>\'}else{if(!has(x.p))return;h+=\'<a class="nv\'+(x.t==="overview"?" on":"")+\'" data-tab="\'+x.t+\'">\'+icon(x.i)+\'<span>\'+x.l+\'</span></a>\'}});$("nav").innerHTML=h;document.querySelectorAll(".nv").forEach(n=>n.addEventListener("click",()=>tab(n.dataset.tab)))}' +
'function renderStaticIcons(){setIcon("menuBtn","menu");setIcon("logoutBtn","logout");setIcon("refBtn","refresh");setIcon("h-ov","home");setIcon("i-st1","users");setIcon("i-st2","check");setIcon("i-st3","pause");setIcon("i-st4","x");setIcon("i-st5","chart");setIcon("i-st6","sun");setIcon("i-st7","activity");setIcon("i-st8","clock");setIcon("i-chart1","chart");setIcon("i-chart2","chart");setIcon("i-trophy","trophy");setIcon("h-weather-i","sun");setIcon("wrefBtn","refresh");setIcon("i-loadw","refresh");setIcon("h-users-i","users");setIcon("expBtn","download");setIcon("impBtn","upload");setIcon("addUserBtn","plus");setIcon("h-groups-i","group");setIcon("addGroupBtn","plus");setIcon("h-traffic-i","chart");setIcon("h-anom-i","alert");setIcon("anomRefBtn","refresh");setIcon("h-pred-i","predict");setIcon("predRefBtn","refresh");setIcon("h-sug-i","bulb");setIcon("sugRefBtn","refresh");setIcon("h-inb-i","tag");setIcon("saveInbBtn","save");setIcon("i-inb1","settings");setIcon("i-inb2","link");setIcon("i-inb3","users");setIcon("inbSaveBtn","save");setIcon("h-mgr-i","crown");setIcon("addMgrBtn","plus");setIcon("h-sess-i","activity");setIcon("revAllBtn","x");setIcon("h-node-i","server");setIcon("hltBtn","activity");setIcon("addNodeBtn","plus");setIcon("h-ban-i","ban");setIcon("brefBtn","refresh");setIcon("banBtn","plus");setIcon("clrBanBtn","trash");setIcon("h-wf-i","workflow");setIcon("addWfBtn","plus");setIcon("h-cron-i","clock");setIcon("addCronBtn","plus");setIcon("h-wh-i","webhook");setIcon("addWhBtn","plus");setIcon("h-cri-i","crisis");setIcon("i-cri1","crisis");setIcon("i-cri2","link");setIcon("i-cri3","log");setIcon("h-reg-i","globe");setIcon("ciTestBtn","zap");setIcon("addRegBtn","plus");setIcon("h-isp-i","wifi");setIcon("ispSaveBtn","save");setIcon("h-dns-i","layers");setIcon("dnsTestBtn","zap");setIcon("dnsSaveBtn","save");setIcon("h-up-i","link");setIcon("addUpBtn","plus");setIcon("h-spd-i","gauge");setIcon("runSpdBtn","play2");setIcon("h-lat-i","radar");setIcon("latRefBtn","refresh");setIcon("h-dpi-i","shield");setIcon("dpiBtn","scan");setIcon("h-set-i","settings");setIcon("h-adv-i","sliders");setIcon("h-key-i","key");setIcon("addKeyBtn","plus");setIcon("h-bk-i","save");setIcon("expCfgBtn","download");setIcon("impCfgBtn","upload");setIcon("mkBkBtn","save");setIcon("h-log-i","log");setIcon("logRefBtn","refresh")}' +
'function show(){$("login").style.display="none";$("shell").classList.add("on");$("whoami").textContent=(S.me.isRoot?"root ":"")+S.me.username;renderNav();renderStaticIcons();renderLogo();fc();refreshAll();startPolling()}' +
'function renderLogo(){const l=S.config&&S.config.customLogo;const c=$("brandLogo");const lo=$("loginOtter");if(!c)return;if(l){c.innerHTML=\'<img src="\'+l+\'" class="om">\';if(lo)lo.innerHTML=\'<img src="\'+l+\'" style="width:76px;height:76px;border-radius:20px;object-fit:cover">\'}else{c.innerHTML=\'<svg class="om" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="bf" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#ec4899"/></linearGradient></defs><ellipse cx="50" cy="55" rx="34" ry="34" fill="url(#bf)"/><circle cx="39" cy="52" r="4.5" fill="#0a0e1a"/><circle cx="61" cy="52" r="4.5" fill="#0a0e1a"/><ellipse cx="50" cy="66" rx="13" ry="10" fill="#fff" opacity=".9"/></svg>\'}}' +
'function lo(){sessionStorage.removeItem("hp_token");sessionStorage.removeItem("hp_user");location.reload()}' +
'function tg(){$("sb").classList.toggle("on");$("ov").classList.toggle("on")}' +
'function tab(t){document.querySelectorAll(".tp").forEach(p=>p.classList.remove("on"));const el=$("tab-"+t);if(el)el.classList.add("on");document.querySelectorAll(".nv").forEach(n=>n.classList.remove("on"));const nv=document.querySelector(\'.nv[data-tab="\'+t+\'"]\');if(nv)nv.classList.add("on");if(window.innerWidth<=900)tg();' +
'if(t==="apikeys")lk();if(t==="traffic"){lhist();lcompare()}if(t==="managers")lm();if(t==="sessions")lsess();if(t==="nodes")lnodes();if(t==="regions")lregions();if(t==="backup")lbackup();if(t==="groups")lgroups();if(t==="anomalies")lanom();if(t==="cron")lcron();if(t==="webhooks")lwh();if(t==="banned")lbanned();if(t==="crisis")lcrisis();if(t==="isp")lisp();if(t==="weather")lweather();if(t==="predictive")lpredictive();if(t==="suggestions")lsug();if(t==="workflows")lwf();if(t==="dns")ldns();if(t==="upstreams")lup();if(t==="speedtest")lspeed();if(t==="latency")llatency();if(t==="inbounds")linbounds()}' +
'function startPolling(){if(S.pollTimer)clearInterval(S.pollTimer);S.pollTimer=setInterval(()=>{if(document.hidden)return;const t=document.querySelector(".tp.on");if(!t)return;if(t.id==="tab-overview")ls()},15000)}' +
'function refreshAll(){ls();lu2();ll();lgroups()}' +
'function fc(){const c=S.config||{};const m={c1:"name",c2:"apiRoute",c3:"masterKey",c4:"mode",c5:"socketPorts",c6:"customDns",c7:"maintenanceHost",c8:"cleanIps",c9:"customLogo",c10:"customTitleColor",a1:"cfAccountId",a2:"cfApiToken",a3:"cfWorkerName",a4:"tgToken",a5:"tgChatId",a6:"tgAdminId",a7:"backupRelay",a8:"nat64Prefix",a9:"activeCarrier",a10:"activeFragment",a11:"iranRouting"};Object.keys(m).forEach(k=>{if(!$(k))return;if($(k).type==="checkbox")$(k).checked=!!c[m[k]];else $(k).value=c[m[k]]||""});' +
'const fs=$("a10");if(fs){fs.innerHTML="";(c.fragmentPresets||[]).forEach(f=>{const o=document.createElement("option");o.value=f.id;o.textContent=f.name;if(f.id===c.activeFragment)o.selected=true;fs.appendChild(o)})}' +
'const st=$("sst");if(st){st.textContent=c.isPaused?"متوقف":"فعال";st.style.color=c.isPaused?"var(--danger)":"var(--ok)"}}' +
'async function sc(){const p={name:$("c1").value,masterKey:$("c3").value,mode:$("c4").value,socketPorts:$("c5").value,customDns:$("c6").value,maintenanceHost:$("c7").value,cleanIps:$("c8").value,customLogo:$("c9").value,customTitleColor:$("c10").value,cfAccountId:$("a1").value,cfApiToken:$("a2").value,cfWorkerName:$("a3").value,tgToken:$("a4").value,tgChatId:$("a5").value,tgAdminId:$("a6").value,backupRelay:$("a7").value,nat64Prefix:$("a8").value,activeCarrier:$("a9").value,activeFragment:$("a10").value,iranRouting:$("a11").checked};const r=await ap("/api/sync",{method:"POST",body:JSON.stringify({config:p})});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.config=Object.assign({},S.config,p);fc();renderLogo()}else ts("خطا","error")}' +
'async function clearLogo(){if(!confirm("حذف؟"))return;const r=await ap("/api/logo",{method:"POST",body:JSON.stringify({action:"clear"})});if(r.data.ok||r.data.success){ts("حذف","ok");S.config.customLogo="";renderLogo()}}' +
/* Stats */
'async function ls(){const r=await ap("/api/stats");if(!(r.data.ok||r.data.success))return;const s=r.data.data||r.data.stats;S.stats=s;$("st1").textContent=s.users.total;$("st2").textContent=s.users.active;$("st3").textContent=s.users.paused;$("st4").textContent=s.users.expired;$("st5").innerHTML=s.traffic.totalGB+" <small>GB</small>";$("st6").innerHTML=s.traffic.dailyGB+" <small>GB</small>";$("st7").textContent=s.system.activeConnections;$("st8").textContent=Math.floor(s.system.uptimeSeconds/3600)+"h";' +
'let tp="";(s.system.topUsers||[]).forEach((u,i)=>{const pct=u.gb>0?Math.min(100,(u.gb/Math.max(1,s.traffic.totalGB))*100):0;const medal=i===0?"trophy":i===1?"chart":"check";tp+=\'<div style="padding:10px;border-radius:12px;background:rgba(148,163,184,.05);margin-bottom:6px;display:flex;align-items:center;gap:10px">\'+icon(medal)+\'<div style="flex:1"><div style="font-weight:700;font-size:13px">\'+u.name+\'</div><div class="prg"><div style="width:\'+pct.toFixed(1)+\'%"></div></div></div><div style="font-weight:800;color:var(--c2)">\'+u.gb+\' GB</div></div>\'});$("topUsers").innerHTML=tp||\'<div class="empty">\'+icon("info")+\'داده نیست</div>\';setTimeout(()=>{c1();c2()},100)}' +
/* Users */
'async function lu2(){const r=await ap("/api/users");if(!(r.data.ok||r.data.success))return;S.users=r.data.data||r.data.users||[];ru()}' +
'function bd(s){const m={active:["bdg-ok","check","فعال"],paused:["bdg-w","pause","متوقف"],expired:["bdg-d","x","منقضی"],"auto-disabled":["bdg-d","ban","غیرفعال"]};const v=m[s]||["bdg-m","info",s];return \'<span class="bdg \'+v[0]+\'">\'+icon(v[1])+v[2]+\'</span>\'}' +
'function fb(b){if(!b)return"0 GB";const g=b/1073741824;if(g<1)return(b/1048576).toFixed(1)+" MB";return g.toFixed(2)+" GB"}' +
'function ru(){const q=($("userSearch")?.value||"").toLowerCase();let u=S.users;if(q)u=u.filter(x=>x.name.toLowerCase().includes(q)||x.id.toLowerCase().includes(q));if(!u.length){$("ub").innerHTML=\'<tr><td colspan="5" class="empty">\'+icon("users")+\'خالی</td></tr>\';return}let h="";u.forEach(x=>{const us=x.usage?fb(x.usage.total):"0 GB",lm=x.limitTotalReq?fb(x.limitTotalReq*1073741824/6000):"∞",ex=x.expiryMs?new Date(x.expiryMs).toLocaleDateString("fa-IR"):"∞";let pct=0;if(x.limitTotalReq&&x.usage&&x.usage.total){const lb=x.limitTotalReq*1073741824/6000;pct=Math.min(100,(x.usage.total/lb)*100)}const pc=pct>90?"d":pct>70?"w":"";const grp=(S.config.userGroups||[]).find(g=>g.id===(x.groupId||"default"));const tagHtml=(x.tags||[]).map(t=>\'<span class="tag-mini">\'+t+\'</span>\').join("");h+=\'<tr><td><div style="font-weight:800">\'+(x.name||"—")+\'</div>\'+(grp?\'<span class="tag-mini" style="background:\'+grp.color+\'22;color:\'+grp.color+\'">\'+grp.name+\'</span>\':"")+tagHtml+\'</td><td>\'+bd(x.status)+\'</td><td><div style="font-weight:700;font-size:12px">\'+us+\'</div><div style="font-size:10px;color:var(--muted)">/ \'+lm+\'</div><div class="prg \'+pc+\'"><div style="width:\'+pct.toFixed(1)+\'%"></div></div></td><td style="font-size:12px">\'+ex+\'</td><td style="text-align:left">\'+iconBtn("link","sun("+x.id+")","ساب")+iconBtn("pause",x.isPaused?"tu":"tu","toggle",x.id)+iconBtn("edit","eu","ویرایش",x.id)+iconBtn("trash","du","حذف",x.id,\'btn-d\')+\'</td></tr>\'});$("ub").innerHTML=h}' +
'function iconBtn(ic,handler,title,arg,cls){const fn=handler.startsWith("sun")?\'onclick="sun(\\\'\'+arg+\'\\\')"\':handler==="tu"?\'onclick="tu(\\\'\'+arg+\'\\\')"\':handler==="eu"?\'onclick="eu(\\\'\'+arg+\'\\\')"\':handler==="du"?\'onclick="du(\\\'\'+arg+\'\\\')"\':"";return \'<button class="btn \'+(cls||"btn-g")+\' btn-s" \'+fn+\' style="margin-left:4px" title="\'+title+\'">\'+icon(ic)+\'</button>\'}' +
'function sun(id){const u=S.users.find(x=>x.id===id);if(!u)return;window.open(location.origin+"/"+AR+"?sub="+encodeURIComponent(u.name),"_blank")}' +
'function ou(){S.editU=null;$("umt").textContent="کاربر جدید";["u1","u2","u3","u4","u5","u7","u10","u11"].forEach(k=>{if($(k))$(k).value=""});$("u8").value="none";refreshGroupSelect();$("um").style.display="flex"}' +
'function cu(){$("um").style.display="none"}' +
'function refreshGroupSelect(){const s=$("u6");if(!s)return;s.innerHTML="";(S.config.userGroups||[]).forEach(g=>{const o=document.createElement("option");o.value=g.id;o.textContent=g.name;s.appendChild(o)})}' +
'function eu(id){const u=S.users.find(x=>x.id===id);if(!u)return;S.editU=u;$("umt").textContent="ویرایش: "+u.name;$("u1").value=u.name||"";$("u2").value=u.limitTotalReq?(u.limitTotalReq/6000).toFixed(2):"";$("u3").value=u.limitDailyReq?(u.limitDailyReq/6000).toFixed(2):"";$("u4").value=u.expiryMs?Math.max(0,Math.ceil((u.expiryMs-Date.now())/86400000)):"";$("u5").value=u.notes||"";$("u7").value=u.maxConfigs||"";$("u9").value=u.isp||"";$("u10").value=u.bandwidthKbps||"";$("u11").value=(u.tags||[]).join(",");const c=(S.config.autoResetCycles||{})[u.id];$("u8").value=c?c.type:"none";refreshGroupSelect();$("u6").value=u.groupId||"default";$("um").style.display="flex"}' +
'async function su2(){const n=$("u1").value.trim();if(!n){ts("نام الزامی","warn");return}const tagsArr=$("u11").value.split(",").map(t=>t.trim()).filter(Boolean);const p={name:n,groupId:$("u6").value,isp:$("u9").value||null,tags:tagsArr,trafficLimit:$("u2").value||0,dailyLimit:$("u3").value||0,expiryDays:$("u4").value||0,notes:$("u5").value,maxConfigs:$("u7").value||0,bandwidthKbps:$("u10").value||0,autoReset:{type:$("u8").value}};let r;if(S.editU)r=await ap("/api/users?id="+encodeURIComponent(S.editU.id),{method:"PUT",body:JSON.stringify(p)});else r=await ap("/api/users",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره","ok");cu();lu2();ls()}else ts("خطا","error")}' +
'async function tu(id){const r=await ap("/api/users?id="+encodeURIComponent(id)+"&action=toggle",{method:"POST"});if(r.data.ok||r.data.success){ts("✓","ok");lu2()}}' +
'async function du(id){if(!confirm("حذف؟"))return;const r=await ap("/api/users?id="+encodeURIComponent(id),{method:"DELETE"});if(r.data.ok||r.data.success){ts("حذف","ok");lu2();ls()}}' +
'function exportCsv(){window.open("/"+AR+"/api/users/bulk","_blank")}' +
'function openImport(){$("csvData").value="";$("im").style.display="flex"}' +
'function ci(){$("im").style.display="none"}' +
'async function doImport(){const c=$("csvData").value.trim();if(!c){ts("خالی","warn");return}const r=await ap("/api/users/bulk",{method:"POST",body:JSON.stringify({csv:c})});if(r.data.ok||r.data.success){ts((r.data.created||0)+" اضافه شد","ok");ci();lu2()}}' +
/* Groups */
'async function lgroups(){const r=await ap("/api/groups");if(!(r.data.ok||r.data.success))return;S.groups=r.data.data||r.data.groups||[];S.config.userGroups=S.groups;rg()}' +
'function rg(){const g=S.groups;if(!g.length){$("groupsGrid").innerHTML=\'<div class="empty">\'+icon("group")+\'خالی</div>\';return}let h="";g.forEach(x=>{h+=\'<div class="node-card"><div style="font-size:15px;font-weight:900;margin-bottom:8px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:\'+x.color+\';margin-left:6px"></span>\'+x.name+\'</div><div style="font-size:11px;color:var(--muted);line-height:1.8">\'+x.limitTotalGb+\' GB · \'+x.expiryDays+\' روز</div><div style="display:flex;gap:6px;margin-top:10px">\'+(x.id!=="default"?iconBtn("edit","eg",x.id)+iconBtn("trash","dg",x.id,"btn-d"):"")+\'</div></div>\'});$("groupsGrid").innerHTML=h}' +
'function og(){S.editG=null;$("gmt").textContent="گروه";["g1","g2","g3","g4","g5","g6"].forEach(k=>$(k).value="");$("gml").style.display="flex"}' +
'function cg(){$("gml").style.display="none"}' +
'function eg(id){const g=S.groups.find(x=>x.id===id);if(!g)return;S.editG=g;$("gmt").textContent="ویرایش";$("g1").value=g.name;$("g2").value=g.limitTotalGb||"";$("g3").value=g.limitDailyGb||"";$("g4").value=g.expiryDays||"";$("g5").value=g.maxConfigs||"";$("g6").value=g.connLimit||"";$("gml").style.display="flex"}' +
'async function sg2(){const n=$("g1").value.trim();if(!n)return;const p={action:S.editG?"update":"create",id:S.editG?S.editG.id:null,name:n,limitTotalGb:$("g2").value||0,limitDailyGb:$("g3").value||0,expiryDays:$("g4").value||0,maxConfigs:$("g5").value||0,connLimit:$("g6").value||0,color:S.editG?S.editG.color:"#"+Math.floor(Math.random()*16777215).toString(16).padStart(6,"0")};const r=await ap("/api/groups",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره","ok");cg();lgroups()}}' +
'async function dg(id){if(!confirm("حذف؟"))return;const r=await ap("/api/groups",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lgroups()}}' +
/* Managers / Sessions */
'async function lm(){const r=await ap("/api/managers");if(!(r.data.ok||r.data.success)){$("mb").innerHTML=\'<tr><td colspan="5" class="empty">دسترسی نیست</td></tr>\';return}S.managers=r.data.data||r.data.managers||[];rm()}' +
'function rm(){const m=S.managers;if(!m.length){$("mb").innerHTML=\'<tr><td colspan="5" class="empty">خالی</td></tr>\';return}let h="";m.forEach(x=>{const pm=x.isRoot?icon("crown")+" Root":(x.permissions||[]).length+" دسترسی";const st=x.isActive!==false?\'<span class="bdg bdg-ok">\'+icon("check")+\'فعال</span>\':\'<span class="bdg bdg-d">\'+icon("x")+\'غیرفعال</span>\';const ll=x.lastLogin?new Date(x.lastLogin).toLocaleDateString("fa-IR"):"—";h+=\'<tr><td style="font-weight:800">\'+x.username+\'</td><td style="font-size:12px">\'+pm+\'</td><td>\'+st+\'</td><td style="font-size:12px">\'+ll+\'</td><td style="text-align:left">\';if(!x.isRoot)h+=iconBtn("edit","em",x.id)+iconBtn("trash","dm",x.id,"btn-d");else h+="—";h+=\'</td></tr>\'});$("mb").innerHTML=h}' +
'const ALLP=["users","settings","advanced","managers","apikeys","logs","stats","subscriptions","nodes","backup","groups","cron","webhooks","regions","inbounds"];' +
'function renderPerms(sel){const c=$("mp");c.innerHTML="";ALLP.forEach(p=>{const e=document.createElement("div");e.className="perm-chip"+(sel.includes(p)?" on":"");e.textContent=p;e.dataset.perm=p;e.onclick=()=>e.classList.toggle("on");c.appendChild(e)})}' +
'function om(){S.editM=null;$("mmt").textContent="مدیر جدید";$("m1").value="";$("m2").value="";$("m1").disabled=false;renderPerms(["users"]);$("mm2").style.display="flex"}' +
'function cm(){$("mm2").style.display="none"}' +
'function em(id){const m=S.managers.find(x=>x.id===id);if(!m||m.isRoot)return;S.editM=m;$("mmt").textContent="ویرایش";$("m1").value=m.username;$("m1").disabled=true;$("m2").value="";renderPerms(m.permissions||[]);$("mm2").style.display="flex"}' +
'async function sm(){const u=$("m1").value.trim(),p=$("m2").value,perms=Array.from(document.querySelectorAll(".perm-chip.on")).map(e=>e.dataset.perm);if(!u||!p){ts("نام و رمز الزامی","warn");return}let r;if(S.editM)r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"update",id:S.editM.id,password:p,permissions:perms})});else r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"create",username:u,password:p,permissions:perms})});if(r.data.ok||r.data.success){ts("ذخیره","ok");cm();lm()}else ts(r.data.error||"خطا","error")}' +
'async function dm(id){if(!confirm("حذف؟"))return;const r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lm()}}' +
'async function lsess(){const r=await ap("/api/sessions");const b=$("sessBody");if(!(r.data.ok||r.data.success)){b.innerHTML=\'<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>\';return}const ss=r.data.data||r.data.sessions||[];if(!ss.length){b.innerHTML=\'<tr><td colspan="4" class="empty">خالی</td></tr>\';return}let h="";ss.forEach(s=>{h+=\'<tr><td style="font-weight:700">\'+s.username+(s.isRoot?icon("crown"):"")+(s.current?\' <span class="bdg bdg-ok">\'+icon("check")+\'فعلی</span>\':"")+\'</td><td class="mono">\'+s.ip+\'</td><td style="font-size:11px">\'+new Date(s.createdAt).toLocaleString("fa-IR")+\'</td><td style="text-align:left">\'+(s.current?"—":iconBtn("x","rs",s.fullToken,"btn-d"))+\'</td></tr>\'});b.innerHTML=h}' +
'async function rs(t){if(!confirm("قطع؟"))return;const r=await ap("/api/sessions",{method:"POST",body:JSON.stringify({action:"revoke",token:t})});if(r.data.ok||r.data.success){ts("قطع","ok");lsess()}}' +
'async function revokeAll(){if(!confirm("قطع همه؟"))return;const r=await ap("/api/sessions",{method:"POST",body:JSON.stringify({action:"revokeAll"})});if(r.data.ok||r.data.success){ts("قطع","ok");lsess()}}' +
/* Nodes */
'async function lnodes(){const r=await ap("/api/nodes");if(!(r.data.ok||r.data.success))return;S.nodes=r.data.data||r.data||[];rn()}' +
'function rn(){const n=S.nodes;if(!n.length){$("nodesGrid").innerHTML=\'<div class="empty">\'+icon("server")+\'نودی نیست</div>\';return}let h="";n.forEach(x=>{const hh=x.lastHealth||{};const st=hh.status==="online"?icon("check")+" آنلاین":hh.status==="offline"?icon("x")+" آفلاین":hh.status?icon("alert")+" خطا":icon("info")+" تست‌نشده";h+=\'<div class="node-card"><div style="font-weight:800;font-size:13px;margin-bottom:6px">\'+(x.name||x.url)+\'</div><div class="mono" style="font-size:10px;margin-bottom:8px;word-break:break-all">\'+x.url+\'</div><div style="font-size:12px">\'+st+(hh.latency>=0?" · "+hh.latency+"ms":"")+\'</div>\'+iconBtn("trash","dnode",x.url,"btn-d")+\'</div>\'});$("nodesGrid").innerHTML=h}' +
'function onNode(){["n1","n2","n3","n4"].forEach(k=>$(k).value="");$("nm").style.display="flex"}' +
'function cn(){$("nm").style.display="none"}' +
'async function sn(){const url=$("n2").value.trim();if(!url){ts("آدرس الزامی","warn");return}const r=await ap("/api/nodes",{method:"POST",body:JSON.stringify({action:"add",url,apiKey:$("n3").value,name:$("n1").value,group:$("n4").value||"default"})});if(r.data.ok||r.data.success){ts("اضافه","ok");cn();lnodes()}}' +
'async function dnode(url){if(!confirm("حذف؟"))return;const r=await ap("/api/nodes",{method:"POST",body:JSON.stringify({action:"remove",url})});if(r.data.ok||r.data.success){ts("حذف","ok");lnodes()}}' +
'async function healthAll(){ts("تست...","info");const r=await ap("/api/nodes/health");if(r.data.ok||r.data.success){ts("انجام","ok");lnodes()}}' +
/* Regions / ISP / DNS / Upstreams */
'async function lregions(){const r=await ap("/api/regions");if(!(r.data.ok||r.data.success))return;const d=r.data.data||r.data;S.regions=d.regions||[];S.activeRegions=d.active||[];rr();lcleanResults()}' +
'function rr(){const r=S.regions;if(!r.length){$("regionsGrid").innerHTML=\'<div class="empty">\'+icon("globe")+\'خالی</div>\';return}let h="";r.forEach(x=>{const a=S.activeRegions.includes(x.id);h+=\'<div class="node-card\'+(a?" active":"")+\'" onclick="togRegion(\\\'\'+x.id+\'\\\')" style="cursor:pointer;border-color:\'+(a?"rgba(6,182,212,.5)":"var(--border)")+\'"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="font-size:24px">\'+x.flag+\'</span><div style="flex:1"><div style="font-weight:800;font-size:14px">\'+x.name+\'</div><div style="font-size:10px;color:var(--muted)">\'+x.ips.length+\' آی‌پی</div></div>\'+(a?\'<span class="bdg bdg-ok">\'+icon("check")+\'</span>\':"")+\'</div>\'+iconBtn("trash","dregion",x.id,"btn-d")+\'</div>\'});$("regionsGrid").innerHTML=h}' +
'async function togRegion(id){const r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"toggle",id})});if(r.data.ok||r.data.success){S.activeRegions=r.data.active;rr()}}' +
'function oregion(){$("r1").value="";$("r2").value="";$("r3").value="";$("rm").style.display="flex"}' +
'function cr(){$("rm").style.display="none"}' +
'async function sr2(){const n=$("r1").value.trim(),f=$("r2").value.trim()||"🌐",ips=$("r3").value.trim();if(!n||!ips)return;const r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"add",name:n,flag:f,ips})});if(r.data.ok||r.data.success){ts("اضافه","ok");cr();lregions()}}' +
'async function dregion(id){if(!confirm("حذف؟"))return;const r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lregions()}}' +
'async function lcleanResults(){const r=await ap("/api/cleanip/results");if(!(r.data.ok||r.data.success))return;const c=r.data.data||r.data.cache||{};$("autoClean").checked=!!S.config.autoCleanIpTest;if(c.testedAt)$("cleanInfo").textContent="آخرین: "+new Date(c.testedAt).toLocaleString("fa-IR");else $("cleanInfo").textContent="تست نشده";const full=c.full||[];if(!full.length){$("cleanBody").innerHTML=\'<tr><td colspan="2" class="empty">داده نیست</td></tr>\';return}let h="";full.slice(0,15).forEach(c2=>{const col=c2.latency<200?"var(--ok)":c2.latency<500?"var(--warn)":"var(--danger)";h+=\'<tr><td class="mono">\'+c2.ip+\'</td><td style="font-weight:800;color:\'+col+\'">\'+c2.latency+\' ms</td></tr>\'});$("cleanBody").innerHTML=h}' +
'async function runCleanIp(){ts("تست...","info");const r=await ap("/api/cleanip/test",{method:"POST"});if(r.data.ok||r.data.success){ts("تمام","ok");lcleanResults()}}' +
'async function toggleAutoClean(){const v=$("autoClean").checked;await ap("/api/sync",{method:"POST",body:JSON.stringify({config:{autoCleanIpTest:v}})});S.config.autoCleanIpTest=v;ts(v?"فعال":"خاموش","ok")}' +
'async function lisp(){const r=await ap("/api/isp-templates");if(!(r.data.ok||r.data.success))return;S.ispTemplates=r.data.data||{};const t=S.ispTemplates;const keys=Object.keys(t);if(!keys.length){$("ispGrid").innerHTML=\'<div class="empty">خالی</div>\';return}let h="";keys.forEach(k=>{const x=t[k];h+=\'<div class="node-card"><div style="font-weight:800;margin-bottom:8px">\'+x.name+\' <span class="tag-mini">\'+k+\'</span></div><div class="fg"><div class="fr"><div class="fd"><label>Fragment</label><input id="isp_\'+k+\'_frag" value="\'+(x.fragment||"")+\'"></div><div class="fd"><label>Ports</label><input id="isp_\'+k+\'_ports" value="\'+(x.ports||"443")+\'"></div></div><div class="fr"><div class="fd"><label>Agent</label><input id="isp_\'+k+\'_agent" value="\'+(x.agent||"chrome")+\'"></div><div class="fd"><label>Extra SNI</label><input id="isp_\'+k+\'_sni" value="\'+(x.extraSni||"")+\'"></div></div></div></div>\'});$("ispGrid").innerHTML=h}' +
'async function saveIsp(){const t={};Object.keys(S.ispTemplates).forEach(k=>{t[k]={name:S.ispTemplates[k].name,fragment:$("isp_"+k+"_frag").value,ports:$("isp_"+k+"_ports").value,agent:$("isp_"+k+"_agent").value,extraSni:$("isp_"+k+"_sni").value}});const r=await ap("/api/isp-templates",{method:"POST",body:JSON.stringify({templates:t})});if(r.data.ok||r.data.success){ts("ذخیره","ok");S.ispTemplates=t}}' +
'async function ldns(){const r=await ap("/api/dns-pool");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};S.dnsPool=d.pool||[];S.dnsStrategy=d.strategy||"weighted";$("dnsStrategy").value=S.dnsStrategy;let h="";S.dnsPool.forEach((x,i)=>{h+=\'<div class="node-card"><div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><label class="switch"><input type="checkbox" \'+(x.enabled?"checked":"")+\' onchange="togDns(\'+i+\',this.checked)"><span class="sl2"></span></label><div style="flex:1"><div style="font-weight:800">\'+x.name+\'</div><div class="mono" style="font-size:10px;word-break:break-all">\'+x.url+\'</div></div><input type="number" value="\'+(x.weight||100)+\'" onchange="S.dnsPool[\'+i+\'].weight=parseInt(this.value)||100" style="width:70px;padding:6px;border-radius:8px;background:rgba(10,14,26,.7);border:1px solid var(--border);color:var(--text)"></div></div>\'});$("dnsGrid").innerHTML=h}' +
'function togDns(i,v){S.dnsPool[i].enabled=v}' +
'async function saveDns(){const r=await ap("/api/dns-pool",{method:"POST",body:JSON.stringify({action:"update",pool:S.dnsPool,strategy:$("dnsStrategy").value})});if(r.data.ok||r.data.success){ts("ذخیره","ok");S.dnsStrategy=$("dnsStrategy").value}}' +
'async function dnsTest(){ts("تست...","info");const r=await ap("/api/dns-pool/actions",{method:"POST",body:JSON.stringify({action:"test"})});if(r.data.ok||r.data.success){let m="نتایج:\\n";(r.data.data||[]).forEach(x=>{m+=x.name+": "+(x.ok?"✓ "+x.latency+"ms":"✗")+"\\n"});alert(m)}}' +
'async function lup(){const r=await ap("/api/upstreams");if(!(r.data.ok||r.data.success))return;S.upstreams=r.data.data||[];let h="";if(!S.upstreams.length){$("upstreamGrid").innerHTML=\'<div class="empty">خالی</div>\';return}S.upstreams.forEach(x=>{h+=\'<div class="node-card"><div style="font-weight:800;margin-bottom:6px">\'+x.name+(x.enabled?\' <span class="bdg bdg-ok">\'+icon("check")+\'</span>\':\' <span class="bdg bdg-d">\'+icon("x")+\'</span>\')+\'</div><div class="mono" style="font-size:10px;word-break:break-all">\'+x.uri.slice(0,60)+\'...</div><div style="display:flex;gap:6px;margin-top:10px"><button class="btn btn-g btn-s" onclick="togUp(\\\'\'+x.id+\'\\\')">\'+(x.enabled?"غیرفعال":"فعال")+\'</button>\'+iconBtn("trash","dup",x.id,"btn-d")+\'</div></div>\'});$("upstreamGrid").innerHTML=h}' +
'function oupstream(){$("up1").value="";$("up2").value="";$("upm").style.display="flex"}' +
'function cup(){$("upm").style.display="none"}' +
'async function sup(){const n=$("up1").value.trim(),u=$("up2").value.trim();if(!u)return;const r=await ap("/api/upstreams",{method:"POST",body:JSON.stringify({action:"add",name:n,uri:u})});if(r.data.ok||r.data.success){ts("اضافه","ok");cup();lup()}}' +
'async function togUp(id){const r=await ap("/api/upstreams",{method:"POST",body:JSON.stringify({action:"toggle",id})});if(r.data.ok||r.data.success)lup()}' +
'async function dup(id){if(!confirm("حذف؟"))return;const r=await ap("/api/upstreams",{method:"POST",body:JSON.stringify({action:"remove",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lup()}}' +
'async function lspeed(){const r=await ap("/api/speedtest");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};const res=d.results||[];if(!res.length){$("speedBody").innerHTML=\'<tr><td colspan="3" class="empty">تست نشده</td></tr>\';return}let h="";res.forEach(x=>{const col=x.latency<200?"var(--ok)":x.latency<500?"var(--warn)":"var(--danger)";h+=\'<tr><td>\'+x.host+\'</td><td style="font-weight:800;color:\'+col+\'">\'+(x.latency>=0?x.latency+" ms":"—")+\'</td><td>\'+(x.status==="ok"?icon("check"):icon("x"))+\'</td></tr>\'});$("speedBody").innerHTML=h}' +
'async function runSpeed(){ts("تست...","info");const r=await ap("/api/speedtest",{method:"POST",body:JSON.stringify({})});if(r.data.ok||r.data.success){ts("انجام","ok");lspeed()}}' +
'async function llatency(){const r=await ap("/api/latency-map");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};let h="";Object.keys(d).forEach(k=>{const x=d[k];const pct=x.avgLatency?Math.min(100,Math.max(0,(x.avgLatency/500)*100)):0;const col=x.avgLatency<200?"var(--ok)":x.avgLatency<500?"var(--warn)":"var(--danger)";h+=\'<div class="node-card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><div style="font-weight:800">\'+x.flag+\' \'+x.name+\'</div><div>\'+(x.active?\'<span class="bdg bdg-ok">\'+icon("check")+\'فعال</span>\':\'<span class="bdg bdg-m">غیرفعال</span>\')+\'</div></div><div style="font-size:11px;color:var(--muted)">\'+x.ipCount+\' آی‌پی · \'+(x.avgLatency?x.avgLatency+" ms":"—")+\'</div>\'+(x.avgLatency?\'<div class="latency-bar"><div style="width:\'+pct+\'%;background:\'+col+\'"></div></div>\':"")+\'</div>\'});$("latencyGrid").innerHTML=h||\'<div class="empty">خالی</div>\'}' +
'async function runDpi(){const r=await ap("/api/dpi");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};const ic=d.mode==="high"?"crisis":d.mode==="medium"?"alert":"check";const col=d.mode==="high"?"var(--danger)":d.mode==="medium"?"var(--warn)":"var(--ok)";$("dpiBox").innerHTML=\'<div style="text-align:center;padding:20px"><div style="font-size:64px;color:\'+col+\'">\'+icon(ic)+\'</div><div style="font-size:24px;font-weight:900;color:\'+col+\'">\'+d.mode.toUpperCase()+\'</div><div style="font-size:14px;color:var(--muted);margin-top:8px">امتیاز: \'+d.score+\'</div><div style="font-size:12px;color:var(--muted);margin-top:16px">\'+(d.reasons||[]).join(" · ")+\'</div><div style="font-size:11px;color:var(--muted);margin-top:8px">ASN: \'+d.asn+\' · \'+d.country+\'</div></div>\'}' +
/* Workflows / Cron / Webhooks / Banned / Crisis */
'async function lwf(){const r=await ap("/api/workflows");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};S.workflows=d.workflows||[];S.workflowTriggers=d.triggers||[];S.workflowActions=d.actions||[];let h="";if(!S.workflows.length){$("wfGrid").innerHTML=\'<div class="empty">خالی</div>\';return}S.workflows.forEach(x=>{h+=\'<div class="node-card"><div style="font-weight:800;margin-bottom:6px">\'+x.name+(x.enabled?\' <span class="bdg bdg-ok">\'+icon("check")+\'</span>\':\' <span class="bdg bdg-d">\'+icon("x")+\'</span>\')+\'</div><div style="font-size:11px;color:var(--muted)">\'+x.trigger+\' · \'+(x.actions||[]).length+\' action</div>\'+iconBtn("trash","dwf",x.id,"btn-d")+\'</div>\'});$("wfGrid").innerHTML=h}' +
'function owf(){S.editWf=null;const s=$("wf2");s.innerHTML="";S.workflowTriggers.forEach(t=>{const o=document.createElement("option");o.value=t.id;o.textContent=t.label;s.appendChild(o)});$("wf1").value="";$("wf3").value=\'[{"type":"send.telegram","params":{"message":"سلام {name}"}}]\';$("wfm").style.display="flex"}' +
'function cwf(){$("wfm").style.display="none"}' +
'async function swf(){const n=$("wf1").value.trim();if(!n)return;let ac=[];try{ac=JSON.parse($("wf3").value||"[]")}catch(e){ts("JSON نامعتبر","warn");return}const p={action:S.editWf?"update":"create",id:S.editWf?S.editWf.id:null,name:n,trigger:$("wf2").value,actions:ac,enabled:true};const r=await ap("/api/workflows",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره","ok");cwf();lwf()}}' +
'async function dwf(id){if(!confirm("حذف؟"))return;const r=await ap("/api/workflows",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lwf()}}' +
'async function lcron(){const r=await ap("/api/cron");if(!(r.data.ok||r.data.success))return;S.cronJobs=r.data.data||[];S.cronActions=r.data.actions||[];rc()}' +
'function rc(){const j=S.cronJobs;if(!j.length){$("cronGrid").innerHTML=\'<div class="empty">خالی</div>\';return}let h="";j.forEach(x=>{const st=x.lastStatus==="ok"?\'<span class="bdg bdg-ok">\'+icon("check")+\'</span>\':x.lastStatus==="error"?\'<span class="bdg bdg-d">\'+icon("x")+\'</span>\':"";h+=\'<div class="node-card"><div style="font-weight:800;margin-bottom:6px">\'+x.name+\' \'+st+\'</div><div style="font-size:11px;color:var(--muted);line-height:1.7">\'+x.action+\'<br>هر \'+x.intervalMinutes+\' دقیقه</div><div style="display:flex;gap:6px;margin-top:10px">\'+iconBtn("play2","runCron",x.id)+\'</button>\'+iconBtn("trash","dcron",x.id,"btn-d")+\'</div></div>\'});$("cronGrid").innerHTML=h}' +
'function ocron(){S.editCron=null;$("comt").textContent="Cron جدید";$("cj1").value="";$("cj4").value=60;$("cj5").checked=true;$("cj3").value="{}";const s=$("cj2");s.innerHTML="";S.cronActions.forEach(a=>{const o=document.createElement("option");o.value=a.id;o.textContent=a.label;s.appendChild(o)});$("com").style.display="flex"}' +
'function ccj(){$("com").style.display="none"}' +
'async function scj(){const n=$("cj1").value.trim();if(!n)return;let params={};try{params=JSON.parse($("cj3").value||"{}")}catch(e){return}const p={action:S.editCron?"update":"create",id:S.editCron?S.editCron.id:null,name:n,jobAction:$("cj2").value,params,intervalMinutes:$("cj4").value||60,enabled:$("cj5").checked};const r=await ap("/api/cron",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره","ok");ccj();lcron()}}' +
'async function dcron(id){if(!confirm("حذف؟"))return;const r=await ap("/api/cron",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lcron()}}' +
'async function runCron(id){ts("اجرا...","info");const r=await ap("/api/cron",{method:"POST",body:JSON.stringify({action:"run",id})});if(r.data.ok||r.data.success){ts("انجام","ok");lcron()}}' +
'async function lwh(){const r=await ap("/api/webhooks");if(!(r.data.ok||r.data.success))return;S.webhooks=r.data.data||[];S.webhookEvents=r.data.events||[];rw()}' +
'function rw(){const w=S.webhooks;if(!w.length){$("whGrid").innerHTML=\'<div class="empty">خالی</div>\';return}let h="";w.forEach(x=>{h+=\'<div class="node-card"><div style="font-weight:800;font-size:12px;margin-bottom:6px;word-break:break-all">\'+x.url+\'</div><div style="font-size:10px;color:var(--muted)">\'+(x.events||[]).join(", ")+\'</div><div style="margin-top:8px;display:flex;gap:8px;align-items:center"><label class="switch"><input type="checkbox" \'+(x.enabled?"checked":"")+\' onchange="togWh(\\\'\'+x.id+\'\\\',this.checked)"><span class="sl2"></span></label><button class="btn btn-g btn-s" onclick="testWh(\\\'\'+x.id+\'\\\')">\'+icon("zap")+\'</button>\'+iconBtn("trash","dwh",x.id,"btn-d")+\'</div></div>\'});$("whGrid").innerHTML=h}' +
'function owh(){S.editWh=null;$("wh1").value="";const c=$("whEvents");c.innerHTML="";S.webhookEvents.forEach(e=>{const d=document.createElement("div");d.className="perm-chip";d.textContent=e;d.dataset.ev=e;d.onclick=()=>d.classList.toggle("on");c.appendChild(d)});$("whm").style.display="flex"}' +
'function cwh(){$("whm").style.display="none"}' +
'async function swh(){const url=$("wh1").value.trim();if(!url)return;const ev=Array.from(document.querySelectorAll("#whEvents .perm-chip.on")).map(e=>e.dataset.ev);const r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"create",url,events:ev})});if(r.data.ok||r.data.success){ts("ذخیره","ok");cwh();lwh()}}' +
'async function togWh(id,en){await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"update",id,enabled:en})})}' +
'async function dwh(id){if(!confirm("حذف؟"))return;const r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"delete",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lwh()}}' +
'async function testWh(id){ts("تست...","info");const r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"test",id})});if(r.data.ok||r.data.success)ts("موفق "+(r.data.status||200),"ok");else ts("خطا","error")}' +
'async function lbanned(){const r=await ap("/api/banned");if(!(r.data.ok||r.data.success))return;S.banned=r.data.data||[];rb()}' +
'function rb(){const b=S.banned;if(!b.length){$("banBody").innerHTML=\'<tr><td colspan="4" class="empty">خالی</td></tr>\';return}let h="";b.forEach(x=>{h+=\'<tr><td class="mono">\'+x.ip+\'</td><td style="font-size:12px">\'+(x.reason||"—")+\'</td><td style="font-size:11px">\'+new Date(x.bannedAt).toLocaleString("fa-IR")+\'</td><td style="text-align:left">\'+iconBtn("check","unbanOne",x.ip)+\'</td></tr>\'});$("banBody").innerHTML=h}' +
'function oban(){$("b1").value="";$("b2").value="";$("bam").style.display="flex"}' +
'function cban(){$("bam").style.display="none"}' +
'async function doban(){const ip=$("b1").value.trim();if(!ip)return;const r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"ban",ip,reason:$("b2").value})});if(r.data.ok||r.data.success){ts("Ban","ok");cban();lbanned()}}' +
'async function unbanOne(ip){const r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"unban",ip})});if(r.data.ok||r.data.success){ts("رفع","ok");lbanned()}}' +
'async function clearBanned(){if(!confirm("پاک همه؟"))return;const r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"clear"})});if(r.data.ok||r.data.success){ts("پاک","ok");lbanned()}}' +
'async function lcrisis(){const r=await ap("/api/crisis");if(!(r.data.ok||r.data.success))return;S.crisisPresets=r.data.presets||[];S.crisisHistory=r.data.history||[];let h="";S.crisisPresets.forEach(x=>{h+=\'<div class="node-card"><div style="font-weight:800;font-size:13px;margin-bottom:6px">\'+x.title+\'</div><div style="font-size:11px;color:var(--muted);line-height:1.6">\'+x.text.slice(0,100)+\'...</div><button class="btn btn-p btn-s" style="margin-top:8px" onclick="sendPreset(\\\'\'+x.id+\'\\\')">ارسال</button></div>\'});$("crisisPresets").innerHTML=h||\'<div class="empty">خالی</div>\';let hh="";(S.crisisHistory||[]).slice(0,10).forEach(x=>{hh+=\'<div style="padding:10px;border-radius:10px;background:rgba(148,163,184,.04);margin-bottom:6px"><div style="font-size:11px;color:var(--muted)">\'+new Date(x.ts).toLocaleString("fa-IR")+\'</div><div style="font-size:12px;margin-top:4px">\'+x.message.slice(0,80)+\'</div><div style="font-size:10px;margin-top:4px">\'+icon("check")+x.sent+\' · \'+icon("x")+x.failed+\'</div></div>\'});$("crisisHistory").innerHTML=hh||\'<div class="empty">خالی</div>\'}' +
'async function sendPreset(id){const p=S.crisisPresets.find(x=>x.id===id);if(!p||!confirm("ارسال؟"))return;const r=await ap("/api/crisis",{method:"POST",body:JSON.stringify({action:"send",presetId:id})});if(r.data.success||r.data.ok){ts("ارسال به "+r.data.sent,"ok");lcrisis()}}' +
'async function sendCrisis(){const m=$("crisisMsg").value.trim();if(!m||!confirm("ارسال؟"))return;const r=await ap("/api/crisis",{method:"POST",body:JSON.stringify({action:"send",message:m})});if(r.data.success||r.data.ok){ts("ارسال به "+r.data.sent,"ok");$("crisisMsg").value="";lcrisis()}}' +
/* Weather / Predict / Suggest */
'async function lweather(){const r=await ap("/api/network-weather");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};const ic=d.status==="storm"?"storm":d.status==="rainy"?"rain":d.status==="cloudy"?"cloud":"sun";$("weatherBox").innerHTML=\'<div class="weather"><div class="weather-icon" style="color:var(--c2)">\'+icon(ic)+\'</div><div style="flex:1"><div style="font-size:20px;font-weight:900">\'+d.status.toUpperCase()+\'</div><div style="font-size:13px;color:var(--muted);margin-top:6px">سلامت: \'+d.health+\'% · کاربران: \'+d.active+\'/\'+d.total+\'</div><div style="font-size:12px;color:var(--muted);margin-top:4px">نودها: \'+d.nodesOnline+\'/\'+d.nodesTotal+\'</div>\'+(d.cfUsage!==null?\'<div style="font-size:12px;color:var(--muted);margin-top:4px">CF: \'+d.cfUsage+\' (\'+d.cfPct+\'%)</div>\':"")+\'<div class="prg" style="margin-top:10px"><div style="width:\'+d.health+\'%"></div></div></div></div>\'}' +
'async function lpredictive(){const r=await ap("/api/predictive");if(!(r.data.ok||r.data.success))return;const d=r.data.data||{};$("predictiveBox").innerHTML=\'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px"><div><div style="font-size:11px;color:var(--muted)">میانگین روزانه</div><div style="font-size:22px;font-weight:900;color:var(--c2);margin-top:6px">\'+d.avg.toFixed(2)+\' GB</div></div><div><div style="font-size:11px;color:var(--muted)">روند</div><div style="font-size:22px;font-weight:900;color:\'+(d.trend>0?"var(--danger)":"var(--ok)")+\';margin-top:6px">\'+(d.trend>0?"+":"")+d.trend.toFixed(3)+\'</div></div><div><div style="font-size:11px;color:var(--muted)">پیش‌بینی هفته</div><div style="font-size:22px;font-weight:900;color:var(--info);margin-top:6px">\'+d.nextWeekTotal+\' GB</div></div></div>\';if(S.charts.chPred)S.charts.chPred.destroy();const cv=$("chPred");if(!cv)return;S.charts.chPred=new Chart(cv.getContext("2d"),{type:"line",data:{labels:(d.predictions||[]).map(x=>x.date.slice(5)),datasets:[{label:"GB",data:(d.predictions||[]).map(x=>x.gb),borderColor:"#ec4899",backgroundColor:"rgba(236,72,153,.15)",fill:true,tension:.4,borderWidth:3}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#b8c1d9"}}},scales:{x:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"}},y:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"},beginAtZero:true}}}})}' +
'async function lsug(){const r=await ap("/api/suggestions");if(!(r.data.ok||r.data.success))return;const a=r.data.data||r.data.suggestions||[];if(!a.length){$("sugList").innerHTML=\'<div class="empty">\'+icon("bulb")+\'هیچ پیشنهادی</div>\';return}let h="";a.forEach(x=>{const ic=x.icon==="isp"?"wifi":x.icon==="globe"?"globe":x.icon==="target"?"radar":x.icon==="save"?"save":x.icon==="alert"?"alert":x.icon==="clock"?"clock":x.icon==="webhook"?"webhook":x.icon==="workflows"?"workflow":"bulb";const col=x.level==="warn"?"var(--warn)":"var(--info)";h+=\'<div class="suggestion">\'+icon(ic)+\'<div style="flex:1"><div style="font-weight:800;font-size:14px;color:\'+col+\'">\'+x.title+\'</div><div style="font-size:12px;color:var(--muted);margin-top:4px">\'+x.desc+\'</div>\'+(x.action?\'<button class="btn btn-g btn-s" style="margin-top:8px" onclick="handleSug(\\\'\'+x.action+\'\\\')">برو</button>\':"")+\'</div></div>\'});$("sugList").innerHTML=h}' +
'function handleSug(a){if(a.startsWith("tab:"))tab(a.slice(4))}' +
/* Anomalies / Charts */
'async function lanom(){const r=await ap("/api/anomalies");if(!(r.data.ok||r.data.success))return;const a=r.data.data||r.data.anomalies||[];const el=$("anomList");if(!a.length){el.innerHTML=\'<div class="empty">\'+icon("check")+\'هیچ هشدار</div>\';return}let h="";a.forEach(x=>{h+=\'<div style="padding:14px;border-radius:12px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap"><div><div style="font-weight:800">\'+x.name+\'</div><div style="font-size:11px;color:var(--muted);margin-top:4px">امروز: \'+(x.today/6000).toFixed(2)+\' GB · میانگین: \'+(x.avg/6000).toFixed(2)+\' GB</div></div><span class="bdg bdg-d">×\'+x.ratio+\'</span></div>\'});el.innerHTML=h}' +
'function setDays(d,el){S.days=d;document.querySelectorAll("#tab-traffic .pill").forEach(p=>p.classList.remove("on"));el.classList.add("on");lhist()}' +
'async function lhist(){const r=await ap("/api/history?days="+S.days);if(!(r.data.ok||r.data.success))return;const s=r.data.series||r.data.data||[];if(S.charts.ch3)S.charts.ch3.destroy();const cv=$("ch3");if(!cv)return;const ctx=cv.getContext("2d");const g=ctx.createLinearGradient(0,0,0,300);g.addColorStop(0,"rgba(6,182,212,.6)");g.addColorStop(1,"rgba(6,182,212,0)");S.charts.ch3=new Chart(ctx,{type:"line",data:{labels:s.map(x=>x.date.slice(5)),datasets:[{label:"GB",data:s.map(x=>x.gb),borderColor:"#06b6d4",backgroundColor:g,fill:true,tension:.4,borderWidth:3,pointBackgroundColor:"#8b5cf6",pointRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#b8c1d9"}}},scales:{x:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"}},y:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"},beginAtZero:true}}}})}' +
'function lcompare(){if(S.charts.ch4)S.charts.ch4.destroy();const cv=$("ch4");if(!cv)return;const u=S.users.slice(0,10);S.charts.ch4=new Chart(cv.getContext("2d"),{type:"bar",data:{labels:u.map(x=>x.name),datasets:[{label:"مصرف",data:u.map(x=>x.usage?x.usage.total/1073741824:0),backgroundColor:"rgba(139,92,246,.85)",borderRadius:6},{label:"محدودیت",data:u.map(x=>x.limitTotalReq?x.limitTotalReq/6000:0),backgroundColor:"rgba(6,182,212,.45)",borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#b8c1d9"}}},scales:{x:{ticks:{color:"#7c88a6"},grid:{display:false}},y:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"},beginAtZero:true}}}})}' +
'async function runCompare(){const ids=$("cmpIds").value.split(",").map(s=>s.trim()).filter(Boolean);const days=$("cmpDays").value||14;if(!ids.length)return;const r=await ap("/api/stats/compare?ids="+ids.join(",")+"&days="+days);if(!(r.data.ok||r.data.success))return;const s=r.data.series||{};if(S.charts.ch5)S.charts.ch5.destroy();const cv=$("ch5");if(!cv)return;const colors=["#06b6d4","#8b5cf6","#ec4899","#f59e0b","#10b981"];const ds=Object.keys(s).map((n,i)=>({label:n,data:s[n].map(x=>x.gb),borderColor:colors[i%colors.length],backgroundColor:colors[i%colors.length]+"22",fill:false,tension:.3,borderWidth:2}));const lb=(Object.values(s)[0]||[]).map(x=>x.date.slice(5));S.charts.ch5=new Chart(cv.getContext("2d"),{type:"line",data:{labels:lb,datasets:ds},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#b8c1d9"}}},scales:{x:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"}},y:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"},beginAtZero:true}}}})}' +
'function c1(){if(S.charts.c1)S.charts.c1.destroy();const cv=$("ch1");if(!cv)return;const u=S.users.slice(0,8);const ctx=cv.getContext("2d");const g=ctx.createLinearGradient(0,0,0,300);g.addColorStop(0,"rgba(139,92,246,.9)");g.addColorStop(1,"rgba(236,72,153,.15)");S.charts.c1=new Chart(ctx,{type:"bar",data:{labels:u.map(x=>x.name||"U"),datasets:[{label:"GB",data:u.map(x=>x.usage?x.usage.total/1073741824:0),backgroundColor:g,borderRadius:8}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#b8c1d9"}}},scales:{x:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"}},y:{ticks:{color:"#7c88a6"},grid:{color:"rgba(148,163,184,.06)"},beginAtZero:true}}}})}' +
'function c2(){if(S.charts.c2)S.charts.c2.destroy();const cv=$("ch2");if(!cv)return;const s=S.stats||{traffic:{totalGB:"0",dailyGB:"0"}};const t=parseFloat(s.traffic.totalGB)||0,d=parseFloat(s.traffic.dailyGB)||0;S.charts.c2=new Chart(cv.getContext("2d"),{type:"doughnut",data:{labels:["امروز","قبل"],datasets:[{data:[d,Math.max(0,t-d)],backgroundColor:["rgba(139,92,246,.95)","rgba(6,182,212,.3)"],borderColor:"rgba(5,7,13,1)",borderWidth:4}]},options:{responsive:true,maintainAspectRatio:false,cutout:"68%",plugins:{legend:{position:"bottom",labels:{color:"#b8c1d9",padding:14,usePointStyle:true}}}}})}' +
/* API Keys / Backup / Logs */
'async function lk(){const r=await ap("/api/keys");const b=$("kb");if(!(r.data.ok||r.data.success)){b.innerHTML=\'<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>\';return}const k=r.data.data||r.data.keys||[];if(!k.length){b.innerHTML=\'<tr><td colspan="4" class="empty">خالی</td></tr>\';return}let h="";k.forEach(x=>{h+=\'<tr><td>\'+(x.name||"—")+\'</td><td class="mono">\'+(x.keyPreview||"—")+\'</td><td style="font-size:12px">\'+(x.createdAt?new Date(x.createdAt).toLocaleDateString("fa-IR"):"—")+\'</td><td style="text-align:left">\'+iconBtn("trash","rk",x.id,"btn-d")+\'</td></tr>\'});b.innerHTML=h}' +
'async function ck(){const n=prompt("نام کلید:");if(!n)return;const r=await ap("/api/keys",{method:"POST",body:JSON.stringify({action:"create",name:n})});if(r.data.ok||r.data.success){ts("ساخته","ok");const k=r.data.data||r.data.key||{};alert("کلید:\\n\\n"+k.key);lk()}}' +
'async function rk(id){if(!confirm("حذف؟"))return;const r=await ap("/api/keys",{method:"POST",body:JSON.stringify({action:"revoke",id})});if(r.data.ok||r.data.success){ts("حذف","ok");lk()}}' +
'async function lbackup(){const r=await ap("/api/backup");if(!(r.data.ok||r.data.success)){$("backupBody").innerHTML=\'<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>\';return}const b=r.data.data||r.data.backups||[];if(!b.length){$("backupBody").innerHTML=\'<tr><td colspan="4" class="empty">خالی</td></tr>\';return}let h="";b.forEach(x=>{const kb=(x.size/1024).toFixed(1);const n=x.key.split("/").pop();h+=\'<tr><td class="mono" style="font-size:10px">\'+n+\'</td><td>\'+kb+\' KB</td><td style="font-size:11px">\'+new Date(x.uploaded).toLocaleString("fa-IR")+\'</td><td style="text-align:left">\'+iconBtn("download","restoreB",x.key)+\'</button>\'+iconBtn("trash","delB",x.key,"btn-d")+\'</td></tr>\'});$("backupBody").innerHTML=h}' +
'async function makeBackup(){const r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"create",encrypt:false})});if(r.data.ok||r.data.success){ts("ساخته شد","ok");lbackup()}else ts("خطا","error")}' +
'async function restoreB(key){if(!confirm("بازیابی؟"))return;const r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"restore",key})});if(r.data.ok||r.data.success){ts("بازیابی","ok");setTimeout(()=>location.reload(),1000)}else ts(r.data.error||"خطا","error")}' +
'async function delB(key){if(!confirm("حذف؟"))return;const r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"delete",key})});if(r.data.ok||r.data.success){ts("حذف","ok");lbackup()}}' +
'function exportConfig(){window.open("/"+AR+"/api/config/export","_blank")}' +
'function openImportConfig(){$("jsonData").value="";$("imc").style.display="flex"}' +
'function cic(){$("imc").style.display="none"}' +
'async function doImportConfig(){try{const d=JSON.parse($("jsonData").value);const r=await ap("/api/config/import",{method:"POST",body:JSON.stringify({data:d})});if(r.data.ok||r.data.success){ts("ورود","ok");cic();setTimeout(()=>location.reload(),1000)}else ts(r.data.error||"خطا","error")}catch(e){ts("JSON نامعتبر","error")}}' +
'async function ll(){const r=await ap("/api/logs",{method:"POST",body:JSON.stringify({})});const c=$("lc");if(!(r.data.ok||r.data.success)){c.innerHTML=\'<div class="empty">دسترسی نیست</div>\';return}const l=r.data.logs||[];if(!l.length){c.innerHTML=\'<div class="empty">لاگی نیست</div>\';return}let h="";l.slice(0,50).forEach(x=>{h+=\'<div style="padding:12px 14px;border-radius:12px;background:rgba(148,163,184,.04);border:1px solid var(--border)"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><span style="font-weight:800;color:var(--c2);font-size:12px">\'+x.type+\'</span><span style="font-size:10px;color:var(--muted)">\'+new Date(x.ts).toLocaleString("fa-IR")+\'</span></div><div style="font-size:12px;color:var(--text-2);margin-top:6px">\'+(x.detail||"")+\'</div></div>\'});c.innerHTML=h}' +
/* ═══ INBOUND CONFIGS ═══ */
'async function linbounds(){const r=await ap("/api/inbounds");if(!(r.data.ok||r.data.success)){ts("دسترسی ندارید","warn");return}const d=r.data.data||{};S.inbound=d.config||{};S.inboundUsers=d.users||[];const cfg=S.inbound;const g=cfg.global||{};$("inb-template").value=g.nameTemplate||"{FLAG} {PREFIX}-{INDEX}";$("inb-prefix").value=g.prefix||S.config.namePrefix||"Hamed";$("inb-maxlen").value=g.maxNameLength||60;$("inb-ascii").checked=!!g.asciiOnly;renderInboundTags(cfg.availableTags||[]);renderEntries(cfg.extraEntries||[]);renderUserOverrides(S.inboundUsers,cfg.perUser||{});updateInbPreview()}' +
'function renderInboundTags(tags){const c=$("inb-tags");c.innerHTML="";tags.forEach(t=>{const e=document.createElement("div");e.className="tag-chip";e.textContent="{"+t.tag+"}";e.title=t.desc+" · مثال: "+t.example;e.onclick=()=>{const el=$("inb-template");el.value=el.value+" {"+t.tag+"}";updateInbPreview()};c.appendChild(e)})}' +
'function renderEntries(entries){const c=$("entriesList");if(!entries.length){c.innerHTML=\'<div class="empty" style="padding:20px">هنوز ورودی‌ای نیست</div>\';return}let h="";entries.forEach(e=>{h+=\'<div class="entry-row"><label class="switch"><input type="checkbox" \'+(e.enabled?"checked":"")+\' onchange="togEntry(\\\'\'+e.id+\'\\\',this.checked)"><span class="sl2"></span></label><div class="txt">\'+(e.flagPrefix?e.flagPrefix+" ":"")+e.text+\'</div><div style="font-size:10px;color:var(--muted)">\'+(e.position==="end"?"انتها":"ابتدا")+\'</div>\'+iconBtn("trash","delEntry",e.id,"btn-d")+\'</div>\'});c.innerHTML=h}' +
'function renderUserOverrides(users,perUser){const b=$("inbUserBody");if(!users.length){b.innerHTML=\'<tr><td colspan="4" class="empty">کاربری نیست</td></tr>\';return}let h="";users.forEach(u=>{const ov=perUser[u.id];const has=!!ov;h+=\'<tr><td style="font-weight:700">\'+u.name+\'</td><td class="mono" style="font-size:10px">\'+(has&&ov.nameTemplate?ov.nameTemplate:"—")+\'</td><td>\'+(has?\'<span class="bdg bdg-ok">\'+icon("check")+\'فعال</span>\':\'<span class="bdg bdg-m">سراسری</span>\')+\'</td><td style="text-align:left"><button class="btn btn-g btn-s" onclick="openUserInbound(\\\'\'+u.id+\'\\\')">\'+icon("edit")+\'</button></td></tr>\'});b.innerHTML=h}' +
'function updateInbPreview(){const t=$("inb-template").value;const p=$("inb-prefix").value||"Hamed";let preview=t.replace(/\{FLAG\}/g,"🇩🇪").replace(/\{PREFIX\}/g,p).replace(/\{INDEX\}/g,"1").replace(/\{USER\}/g,"ali").replace(/\{PORT\}/g,"443").replace(/\{REGION\}/g,"آلمان").replace(/\{PROTOCOL\}/g,"VLESS").replace(/\{COUNTRY\}/g,"Germany").replace(/\{CITY\}/g,"Frankfurt").replace(/\{ISP\}/g,"Cloudflare").replace(/\{IP\}/g,"188.114.96.1").replace(/\{HOST\}/g,"panel.workers.dev").replace(/\{DATE\}/g,new Date().toISOString().split("T")[0]).replace(/\{TAG\}/g,"VIP").replace(/\{WORKER\}/g,"hamed-panel").trim();$("inb-preview").textContent=preview||"بدون نام"}' +
'function previewInbound(){updateInbPreview();ts("پیش‌نمایش بروزرسانی شد","ok")}' +
'async function saveInboundGlobal(){const g={nameTemplate:$("inb-template").value,prefix:$("inb-prefix").value,maxNameLength:parseInt($("inb-maxlen").value)||60,asciiOnly:$("inb-ascii").checked};const entries=(S.inbound.extraEntries||[]).map(e=>({...e}));const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateGlobal",global:g,extraEntries:entries})});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.inbound.global=g}}' +
'async function addEntry(){const text=$("newEntryText").value.trim();if(!text){ts("متن الزامی","warn");return}const flagPrefix=$("newEntryFlag").value.trim();const position=$("newEntryPos").value;const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"addEntry",text,flagPrefix,position,type:"static",enabled:true})});if(r.data.ok||r.data.success){ts("اضافه شد","ok");$("newEntryText").value="";$("newEntryFlag").value="";linbounds()}}' +
'async function delEntry(id){if(!confirm("حذف؟"))return;const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"removeEntry",id})});if(r.data.ok||r.data.success){ts("حذف","ok");linbounds()}}' +
'async function togEntry(id,en){const e=(S.inbound.extraEntries||[]).find(x=>x.id===id);if(!e)return;e.enabled=en;const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateEntry",id,data:{enabled:en}})});if(r.data.ok||r.data.success)S.inbound.extraEntries=(S.inbound.extraEntries||[]).map(x=>x.id===id?e:x)}' +
'async function applyGlobalToAll(){if(!confirm("اعمال تنظیمات سراسری به همه کاربران؟ این کار override قبلی را پاک می‌کند."))return;const r=await ap("/api/inbounds/actions",{method:"POST",body:JSON.stringify({action:"applyGlobal"})});if(r.data.ok||r.data.success){ts("اعمال به "+r.data.applied+" کاربر","ok");linbounds()}}' +
'function openUserInbound(id){const u=S.inboundUsers.find(x=>x.id===id);if(!u)return;S.editUserInbound=id;const ov=(S.inbound.perUser||{})[id]||{};$("iuomTitle").textContent="Override: "+u.name;$("iuo-template").value=ov.nameTemplate||"";const ents=(ov.extraEntries||[]).map(e=>e.text).join("\\n");$("iuo-entries").value=ents;$("iuom").style.display="flex"}' +
'function ciuo(){$("iuom").style.display="none";S.editUserInbound=null}' +
'async function saveUserInbound(){if(!S.editUserInbound)return;const tpl=$("iuo-template").value;const rawEntries=$("iuo-entries").value.split("\\n").map(s=>s.trim()).filter(Boolean);const extraEntries=rawEntries.map((t,i)=>({id:"ue_"+Date.now()+"_"+i,text:t,type:"static",enabled:true,position:"start",flagPrefix:""}));const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateUser",userId:S.editUserInbound,nameTemplate:tpl,extraEntries,enabled:true})});if(r.data.ok||r.data.success){ts("ذخیره","ok");ciuo();linbounds()}}' +
'async function removeUserInbound(){if(!S.editUserInbound||!confirm("حذف override؟"))return;const r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"removeUser",userId:S.editUserInbound})});if(r.data.ok||r.data.success){ts("حذف","ok");ciuo();linbounds()}}' +
/* CMDK */
'const cmds=[{l:"داشبورد",i:"home",a:()=>tab("overview")},{l:"وضعیت شبکه",i:"sun",a:()=>tab("weather")},{l:"کاربران",i:"users",a:()=>tab("users")},{l:"گروه‌ها",i:"group",a:()=>tab("groups")},{l:"ترافیک",i:"chart",a:()=>tab("traffic")},{l:"هشدارها",i:"alert",a:()=>tab("anomalies")},{l:"پیش‌بینی",i:"predict",a:()=>tab("predictive")},{l:"پیشنهادات",i:"bulb",a:()=>tab("suggestions")},{l:"اینباند کانفیگ",i:"tag",a:()=>tab("inbounds")},{l:"مدیران",i:"crown",a:()=>tab("managers")},{l:"نشست‌ها",i:"activity",a:()=>tab("sessions")},{l:"نودها",i:"server",a:()=>tab("nodes")},{l:"IPهای بسته",i:"ban",a:()=>tab("banned")},{l:"Workflows",i:"workflow",a:()=>tab("workflows")},{l:"Cron",i:"clock",a:()=>tab("cron")},{l:"Webhooks",i:"webhook",a:()=>tab("webhooks")},{l:"بحران",i:"crisis",a:()=>tab("crisis")},{l:"مناطق IP",i:"globe",a:()=>tab("regions")},{l:"ISP",i:"wifi",a:()=>tab("isp")},{l:"DNS",i:"layers",a:()=>tab("dns")},{l:"Upstreams",i:"link",a:()=>tab("upstreams")},{l:"SpeedTest",i:"gauge",a:()=>tab("speedtest")},{l:"Latency",i:"radar",a:()=>tab("latency")},{l:"DPI",i:"shield",a:()=>tab("dpi")},{l:"تنظیمات",i:"settings",a:()=>tab("settings")},{l:"پیشرفته",i:"sliders",a:()=>tab("advanced")},{l:"API Keys",i:"key",a:()=>tab("apikeys")},{l:"پشتیبان",i:"save",a:()=>tab("backup")},{l:"لاگ‌ها",i:"log",a:()=>tab("logs")},{l:"کاربر جدید",i:"plus",a:()=>ou()},{l:"خروج",i:"logout",a:()=>lo()}];' +
'function ckl(q){const c=$("ckl");c.innerHTML="";cmds.filter(x=>!q||x.l.includes(q)).forEach((x,i)=>{const d=document.createElement("div");d.className="ri"+(i===0?" on":"");d.innerHTML=icon(x.i)+x.l;d.onclick=()=>{x.a();$("cmdk").classList.remove("on")};c.appendChild(d)})}' +
'function init(){$("lu").value="admin";$("lp").focus();$("lb").addEventListener("click",login);$("lp").addEventListener("keydown",e=>{if(e.key==="Enter")login()});$("lu").addEventListener("keydown",e=>{if(e.key==="Enter")$("lp").focus()});' +
'const tpl=$("inb-template");if(tpl)tpl.addEventListener("input",updateInbPreview);' +
'const saved=sessionStorage.getItem("hp_token");if(saved){S.token=saved;ap("/api/me").then(r=>{const data=(r.data&&r.data.data)||r.data.user||{};if((r.data.ok||r.data.success)&&data.username){S.me=data;S.config=data.config||{};show()}else{sessionStorage.removeItem("hp_token");sessionStorage.removeItem("hp_user")}}).catch(()=>{sessionStorage.removeItem("hp_token");sessionStorage.removeItem("hp_user")})}' +
'document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key==="k"){e.preventDefault();$("cmdk").classList.toggle("on");if($("cmdk").classList.contains("on")){$("ck2").value="";$("ck2").focus();ckl("")}}else if(e.key==="Escape"){["cmdk","um","gml","mm2","nm","rm","com","whm","bam","im","imc","wfm","upm","iuom"].forEach(id=>{const el=$(id);if(el){el.style.display="none";el.classList.remove("on")}})}});' +
'$("ck2").addEventListener("input",e=>ckl(e.target.value));$("ck2").addEventListener("keydown",e=>{if(e.key==="Enter"){const a=$("ckl").querySelector(".ri.on");if(a)a.click()}});$("cmdk").addEventListener("click",e=>{if(e.target===$("cmdk"))$("cmdk").classList.remove("on")})}' +
'init();' +
'</script></body></html>';

/* ═══════════════════════════════════════════════════════════════
   SUBSCRIPTION HTML — v1.0.6
   ═══════════════════════════════════════════════════════════════ */
const SUBSCRIPTION_HTML = '<!DOCTYPE html><html lang="fa" dir="rtl"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
'<title>__PANEL_NAME__ · Subscription</title><meta name="theme-color" content="#05070d">' +
'<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'%3E%3Ctext y=\'.9em\' font-size=\'90\'%3E%F0%9F%A6%A6%3C/text%3E%3C/svg%3E">' +
'<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
'<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">' +
'<style>' +
':root{--bg:#05070d;--panel:#0a0e1a;--border:rgba(148,163,184,.12);--border-2:rgba(148,163,184,.22);--text:#e8ecf6;--text-2:#b8c1d9;--muted:#7c88a6;--muted-2:#4d5a78;--c1:#06b6d4;--c2:#8b5cf6;--c3:#ec4899;--ok:#10b981;--warn:#f59e0b;--danger:#ef4444;--info:#38bdf8;--grad:linear-gradient(135deg,#06b6d4 0%,#8b5cf6 50%,#ec4899 100%);--ease:cubic-bezier(.2,.9,.3,1)}' +
'*{box-sizing:border-box;margin:0;padding:0}html,body{background:var(--bg);color:var(--text);font-family:\'Vazirmatn\',system-ui,sans-serif;-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden;line-height:1.5}' +
'.au{position:fixed;inset:0;z-index:-2;overflow:hidden;pointer-events:none}' +
'.au::before,.au::after{content:"";position:absolute;border-radius:50%;filter:blur(120px);opacity:.5;animation:af 22s ease-in-out infinite}' +
'.au::before{width:800px;height:800px;top:-300px;right:-200px;background:radial-gradient(circle,#06b6d4 0%,transparent 70%)}' +
'.au::after{width:700px;height:700px;bottom:-300px;left:-200px;background:radial-gradient(circle,#ec4899 0%,transparent 70%);animation-delay:-11s}' +
'@keyframes af{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(80px,-60px) scale(1.15)}66%{transform:translate(-60px,60px) scale(.9)}}' +
'.w{max-width:680px;margin:0 auto;padding:32px 18px 60px;position:relative;z-index:1}' +
'.hr{text-align:center;padding:40px 24px 32px;background:linear-gradient(180deg,rgba(20,26,44,.9),rgba(10,14,26,.85));backdrop-filter:blur(20px);border:1px solid var(--border-2);border-radius:28px;margin-bottom:18px;position:relative;overflow:hidden;animation:su .6s}' +
'.hr::before{content:"";position:absolute;top:-100px;right:-100px;width:280px;height:280px;background:radial-gradient(circle,rgba(139,92,246,.35),transparent 70%);pointer-events:none}' +
'@keyframes su{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}' +
'.om{width:100px;height:100px;margin:0 auto 18px;position:relative;display:flex;align-items:center;justify-content:center}' +
'.om::before{content:"";position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,#06b6d4,#8b5cf6,#ec4899,#f59e0b,#06b6d4);animation:sp 8s linear infinite;filter:blur(14px);opacity:.55}' +
'.om::after{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--panel);border:1px solid var(--border-2)}' +
'.om svg,.om img{position:relative;z-index:2;width:70px;height:70px;border-radius:20px;object-fit:cover;filter:drop-shadow(0 0 20px rgba(139,92,246,.6))}' +
'@keyframes sp{to{transform:rotate(360deg)}}' +
'.tg{background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:900}' +
'.ub{display:inline-flex;align-items:center;gap:8px;padding:9px 18px;border-radius:999px;background:rgba(6,182,212,.15);border:1px solid rgba(6,182,212,.35);margin-top:16px;font-weight:800;font-size:13px}' +
'.sp{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:999px;font-size:12px;font-weight:800;margin-top:10px}' +
'.st-a{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.35)}' +
'.st-p{background:rgba(245,158,11,.15);color:#fcd34d;border:1px solid rgba(245,158,11,.35)}' +
'.st-e{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.35)}' +
'.frg{margin-top:10px;padding:8px 14px;border-radius:12px;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.3);font-size:11px;color:#c7d2fe}' +
'.frg code{background:rgba(0,0,0,.3);padding:2px 6px;border-radius:6px;font-family:\'JetBrains Mono\',monospace}' +
'.cd{background:linear-gradient(180deg,rgba(20,26,44,.8),rgba(12,16,28,.7));backdrop-filter:blur(18px);border:1px solid var(--border);border-radius:24px;padding:24px;margin-bottom:18px;animation:su .6s backwards}' +
'.cd:nth-child(2){animation-delay:.1s}.cd:nth-child(3){animation-delay:.2s}.cd:nth-child(4){animation-delay:.3s}.cd:nth-child(5){animation-delay:.4s}' +
'.stt{font-size:15px;font-weight:900;margin-bottom:18px;display:flex;align-items:center;gap:10px;padding-bottom:14px;border-bottom:1px solid var(--border)}' +
'.mt{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:480px){.mt{grid-template-columns:1fr 1fr;gap:8px}}' +
'.mc2{padding:16px;border-radius:16px;background:rgba(10,14,26,.6);border:1px solid var(--border);transition:.25s}' +
'.mc2:hover{border-color:rgba(139,92,246,.3);transform:translateY(-2px)}' +
'.ml{font-size:10px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}' +
'.mv{font-size:20px;font-weight:900;letter-spacing:-.02em}' +
'.mv small{font-size:12px;color:var(--muted);font-weight:600}' +
'.ms{font-size:10px;color:var(--muted-2);margin-top:6px}' +
'.pg{height:8px;border-radius:999px;background:rgba(148,163,184,.12);overflow:hidden;margin-top:10px}' +
'.pg>div{height:100%;background:var(--grad);border-radius:999px;transition:width 1.2s var(--ease)}' +
'.pg.w>div{background:linear-gradient(90deg,#f59e0b,#f97316)}.pg.d>div{background:linear-gradient(90deg,#ef4444,#dc2626)}' +
'.lb{display:flex;align-items:center;gap:10px;padding:14px;border-radius:14px;background:rgba(10,14,26,.65);border:1px solid var(--border);margin-bottom:10px;transition:.2s}' +
'.lb:hover{border-color:rgba(139,92,246,.3)}' +
'.lb code{flex:1;font-size:11px;color:var(--text-2);font-family:\'JetBrains Mono\',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;direction:ltr;text-align:left}' +
'.cb{padding:8px 14px;border-radius:10px;background:rgba(6,182,212,.15);color:#67e8f9;border:1px solid rgba(6,182,212,.35);cursor:pointer;font-family:inherit;font-size:12px;font-weight:800;transition:.2s}' +
'.cb:hover{background:rgba(6,182,212,.28);color:#fff}' +
'.cb.ok{background:rgba(16,185,129,.25);color:#6ee7b7;border-color:rgba(16,185,129,.5)}' +
'.qw{text-align:center;padding:22px;border-radius:18px;background:rgba(10,14,26,.45);border:1px solid var(--border);margin-bottom:16px}' +
'.qi{width:190px;height:190px;border-radius:14px;background:#fff;padding:10px;box-shadow:0 10px 40px -10px rgba(139,92,246,.5)}' +
'.ba{display:flex;align-items:center;gap:10px;padding:14px 18px;border-radius:14px;background:rgba(148,163,184,.06);color:var(--text);border:1px solid var(--border);text-decoration:none;font-weight:700;font-size:13px;transition:.22s;margin-bottom:8px}' +
'.ba:hover{background:rgba(6,182,212,.15);border-color:rgba(6,182,212,.4);color:#fff;transform:translateX(-4px)}' +
'.ft{text-align:center;padding:24px 0 8px;font-size:11px;color:var(--muted-2);line-height:1.9}' +
'.tt{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:14px 22px;border-radius:14px;background:rgba(20,26,44,.98);border:1px solid var(--border-2);color:var(--text);font-size:13px;font-weight:700;box-shadow:0 20px 50px -10px rgba(0,0,0,.7);z-index:1000;animation:ti .35s}' +
'@keyframes ti{from{opacity:0;transform:translate(-50%,20px)}to{opacity:1;transform:translate(-50%,0)}}' +
'.made-by{margin-top:14px;padding:10px 14px;border-radius:12px;background:linear-gradient(135deg,rgba(6,182,212,.1),rgba(236,72,153,.06));border:1px dashed rgba(139,92,246,.4);font-size:11px;color:#c7d2fe;font-weight:700;text-align:center;letter-spacing:.5px}' +
'</style></head><body>' +
'<div class="au"></div>' +
'<div class="w">' +
'<div class="hr"><div class="om" id="logoWrap">__CUSTOM_LOGO_BLOCK__' +
'<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" id="defaultLogo">' +
'<defs><linearGradient id="fs1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#ec4899"/></linearGradient>' +
'<linearGradient id="fs2" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#06b6d4"/><stop offset="100%" stop-color="#8b5cf6"/></linearGradient></defs>' +
'<circle cx="26" cy="30" r="10" fill="url(#fs2)"/><circle cx="74" cy="30" r="10" fill="url(#fs2)"/>' +
'<circle cx="26" cy="30" r="5" fill="#0a0e1a"/><circle cx="74" cy="30" r="5" fill="#0a0e1a"/>' +
'<ellipse cx="50" cy="55" rx="34" ry="34" fill="url(#fs1)"/>' +
'<circle cx="39" cy="52" r="4.5" fill="#0a0e1a"/><circle cx="61" cy="52" r="4.5" fill="#0a0e1a"/>' +
'<circle cx="40.5" cy="50.5" r="1.6" fill="#fff"/><circle cx="62.5" cy="50.5" r="1.6" fill="#fff"/>' +
'<ellipse cx="50" cy="66" rx="13" ry="10" fill="#fff" opacity=".9"/><ellipse cx="50" cy="62" rx="3.5" ry="2.5" fill="#0a0e1a"/>' +
'</svg></div>' +
'<h1 class="tg" style="font-size:26px">__PANEL_NAME__</h1>' +
'<p style="color:var(--muted);font-size:13px;margin-top:6px">Telemetry Gateway</p>' +
'<div class="ub"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span>__USER_NAME__</span></div>' +
'<div id="sp"></div>__FRAGMENT_BADGE__</div>' +
'<div class="cd"><div class="stt">📊 وضعیت اشتراک</div><div class="mt">' +
'<div class="mc2"><div class="ml">📥 ترافیک کل</div><div class="mv">__TOTAL_GB__ <small>/ __LIMIT_TOTAL_GB__ GB</small></div><div class="ms">__TOTAL_PERCENT__</div><div class="pg" id="pt"><div style="width:__TOTAL_PERCENT__"></div></div></div>' +
'<div class="mc2"><div class="ml">📅 امروز</div><div class="mv">__DAILY_GB__ <small>/ __LIMIT_DAILY_GB__ GB</small></div><div class="ms">__DAILY_PERCENT__</div><div class="pg" id="pd"><div style="width:__DAILY_PERCENT__"></div></div></div>' +
'<div class="mc2"><div class="ml">⏰ انقضا</div><div class="mv" style="font-size:16px">__EXPIRY_DATE__</div><div class="ms">__DAYS_LEFT__ روز</div></div>' +
'<div class="mc2"><div class="ml">🆔 شناسه</div><div class="mv" style="font-size:10px;font-family:\'JetBrains Mono\',monospace;direction:ltr;text-align:left;word-break:break-all">__USER_ID__</div></div>' +
'</div></div>' +
'<div class="cd"><div class="stt">🔗 لینک‌های اشتراک</div>' +
'<div class="qw"><img id="qi" class="qi" src="" alt="QR"><div style="font-size:11px;color:var(--muted);margin-top:12px">اسکن کنید یا کپی نمایید</div></div>' +
'<div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-weight:800">🎯 لینک اصلی:</div>' +
'<div class="lb"><code>__SYNC_NORMAL__</code><button class="cb" onclick="cl(\'__SYNC_NORMAL__\',this)">📋 کپی</button></div>' +
'<div style="font-size:12px;color:var(--muted);margin-bottom:8px;margin-top:14px;font-weight:800">📄 لینک خام (V2Ray):</div>' +
'<div class="lb"><code>__SYNC_RAW__</code><button class="cb" onclick="cl(\'__SYNC_RAW__\',this)">📋 کپی</button></div>' +
'</div>' +
'<div class="cd"><div class="stt">📱 اپلیکیشن‌های پیشنهادی</div>' +
'<a class="ba" href="https://github.com/KaringX/karing/releases" target="_blank" rel="noopener"><span>🎯</span> Karing</a>' +
'<a class="ba" href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" rel="noopener"><span>📦</span> NekoBox</a>' +
'<a class="ba" href="https://github.com/2dust/v2rayNG/releases" target="_blank" rel="noopener"><span>🅰️</span> v2rayNG</a>' +
'<a class="ba" href="https://github.com/MetaCubeX/ClashMetaForAndroid/releases" target="_blank" rel="noopener"><span>⚔️</span> Clash Meta</a>' +
'<a class="ba" href="https://apps.apple.com/app/shadowrocket/id932747118" target="_blank" rel="noopener"><span>🚀</span> Shadowrocket</a>' +
'</div>' +
'<div class="made-by">🦦 THIS PANEL MADE BY HAMED TEAM</div>' +
'<div class="ft">© 2025 __PANEL_NAME__ · v__CURRENT_VERSION__</div>' +
'</div><div id="tb"></div>' +
'<script>(function(){const s="__STATUS_CODE__",m={active:["st-a","🟢 فعال"],paused:["st-p","⏸️ متوقف"],expired:["st-e","🔴 منقضی"],limit:["st-e","🚫 محدودیت"],dailyLimit:["st-p","⚠️ روزانه"]},v=m[s]||m.active;document.getElementById("sp").innerHTML=\'<span class="sp \'+v[0]+\'">\'+v[1]+\'</span>\';const tp=parseFloat("__TOTAL_PERCENT__")||0,dp=parseFloat("__DAILY_PERCENT__")||0;if(tp>=90)document.getElementById("pt").classList.add("d");else if(tp>=70)document.getElementById("pt").classList.add("w");if(dp>=90)document.getElementById("pd").classList.add("d");else if(dp>=70)document.getElementById("pd").classList.add("w");const lh="__CUSTOM_LOGO_BLOCK__";if(lh){const d=document.getElementById("defaultLogo");if(d)d.style.display="none"}document.getElementById("qi").src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&bgcolor=ffffff&color=080b12&data="+encodeURIComponent("__SYNC_NORMAL__");window.cl=function(t,b){navigator.clipboard.writeText(t).then(()=>{const o=b.innerHTML;b.innerHTML="✓ کپی شد";b.classList.add("ok");st("لینک کپی شد");setTimeout(()=>{b.innerHTML=o;b.classList.remove("ok")},1800)}).catch(()=>{const a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();try{document.execCommand("copy");st("کپی شد")}catch(e){}a.remove()})};function st(m){const t=document.createElement("div");t.className="tt";t.textContent=m;document.getElementById("tb").appendChild(t);setTimeout(()=>{t.style.opacity="0";t.style.transition=".3s";setTimeout(()=>t.remove(),300)},2200)}})();</script>' +
'</body></html>';