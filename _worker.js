import { connect } from "cloudflare:sockets";

/* ═══════════════════════════════════════════════════════════════
   HAMED PANEL v1.0.8 — Aurora Liquid Edition
   Bugs fixed: sidebar clipping, scroll, workflows, cron, webhooks,
               inbound custom cards, CSV export, session restore
   ═══════════════════════════════════════════════════════════════ */

const CURRENT_VERSION = "1.0.8";
const AUTH_PANEL_VERSION = "1.0";
const PANEL_BRAND = "Hamed Panel";
const SESSION_TTL_MS = 24 * 3600 * 1000;
const AUTH_MAX_ATTEMPTS = 5;
const AUTH_WINDOW_MS = 5 * 60 * 1000;
const BAN_DURATION_MS = 60 * 60 * 1000;
const HISTORY_DAYS = 30;
const MAX_CONFIG_NAME_LEN = 100;
const CAPTCHA_TTL_MS = 5 * 60 * 1000;
const ALL_PERMISSIONS = ["users","settings","advanced","managers","apikeys","logs","stats","subscriptions","nodes","backup","groups","cron","webhooks","regions","inbounds"];
const SENSITIVE_FIELDS = ["cfApiToken","tgToken","syncApiKey"];

const CARRIERS = {
  mci:{name:"همراه اول",nat64:"2a00:1a00:1::/96",fragment:"1-3-1-2"},
  irancell:{name:"ایرانسل",nat64:"2a10:cc40::/96",fragment:"1-3-1-2"},
  rightel:{name:"رایتل",nat64:"2a03:7b00::/96",fragment:"1-1-1-1"},
  mokhaberat:{name:"مخابرات",nat64:"2a03:5a00::/96",fragment:"1-2-1-1"},
  shatel:{name:"شاتل",nat64:"2a03:5a00::/96",fragment:"1-2-1-1"}
};

const IRAN_DOMAINS_PRESET = ["ir","gov.ir","ac.ir","edu.ir","bank","shaparak.ir","aparat.com","digikala.com","divar.ir","snapp.ir","tapsi.ir","bmi.ir","mci.ir","irancell.ir","rightel.ir","varzesh3.com","farsnews.ir","tasnimnews.com","zoomit.ir","khabaronline.ir","mehrnews.com","irna.ir","iscanews.ir","eghtesadnews.com","alibaba.ir","flightio.com","digistyle.com","modiseh.com","bamilo.com","snappfood.ir","snapptrip.com","cafebazaar.ir","myket.ir","sibapp.com","farsroid.com","nikkan.ir"];

const CF_HTTPS_PORTS = ["443","8443","2053","2083","2087","2096"];
const CF_HTTP_PORTS = ["80","8080","8880","2052","2082","2086","2095"];
const CF_ALL_PORTS = [...CF_HTTP_PORTS, ...CF_HTTPS_PORTS];

/* ═══════════ RELAY ENGINE v2.0 ═══════════ */
const RELAY_PROXY_DOMAINS = [
  "ProxyIP.CMLiussss.net",
  "ProxyIP.US.KG",
  "ProxyIP.CM.RF.TW",
  "ProxyIP.Dynu.net",
  "ts.hpc.tw",
  "proxyip.fly.dev",
  "ProxyIP.XYZ",
  "proxyip.510111.xyz"
];

let relayHealthCache = new Map();

function recordRelayAttempt(host, success, latencyMs) {
  if (!host) return;
  const key = String(host).split(":")[0];
  const e = relayHealthCache.get(key) || { ok: 0, fail: 0, lastCheck: 0, avgLatency: 0 };
  if (success) {
    e.ok++;
    if (latencyMs > 0) e.avgLatency = e.avgLatency === 0 ? latencyMs : Math.round(e.avgLatency * 0.7 + latencyMs * 0.3);
  } else {
    e.fail++;
  }
  e.lastCheck = Date.now();
  if (e.ok + e.fail > 100) { e.ok = Math.round(e.ok / 2); e.fail = Math.round(e.fail / 2); }
  relayHealthCache.set(key, e);
}

function rankRelays(hosts) {
  if (!hosts || hosts.length === 0) return [];
  return hosts.slice().sort(function (a, b) {
    const ka = String(a).split(":")[0];
    const kb = String(b).split(":")[0];
    const ea = relayHealthCache.get(ka) || { ok: 0, fail: 0, avgLatency: 9999 };
    const eb = relayHealthCache.get(kb) || { ok: 0, fail: 0, avgLatency: 9999 };
    const sa = (ea.ok + 1) / (ea.fail + 1);
    const sb = (eb.ok + 1) / (eb.fail + 1);
    if (Math.abs(sa - sb) > 0.5) return sb - sa;
    return (ea.avgLatency || 9999) - (eb.avgLatency || 9999);
  });
}

function isProxyDomain(host) {
  if (!host) return false;
  return !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(host).split(":")[0]);
}

function buildRelayPool(p) {
  const pool = { server: [], relay: [] };
  if (!p) return pool;

  if (p.relayIps && String(p.relayIps).trim()) {
    const custom = getProxyIpsArray(p.relayIps);
    custom.forEach(function (ip) {
      if (isProxyDomain(ip)) pool.relay.push(ip);
      else pool.server.push(ip);
    });
  }

  if (p.relayPresetId && p.relayPresetId !== "auto") {
    const preset = (sysConfig.relayIpPresets || RELAY_IP_PRESETS).find(function (r) { return r.id === p.relayPresetId; });
    if (preset) {
      if (preset.serverIps && preset.serverIps.length > 0) preset.serverIps.forEach(function (ip) { pool.server.push(ip); });
      else if (preset.ips && preset.ips.length > 0) preset.ips.forEach(function (ip) { if (!isProxyDomain(ip)) pool.server.push(ip); });
      if (preset.relayIps && preset.relayIps.length > 0) preset.relayIps.forEach(function (ip) { pool.relay.push(ip); });
    }
  }

  if (sysConfig.backupRelay) {
    getProxyIpsArray(sysConfig.backupRelay).forEach(function (ip) {
      if (isProxyDomain(ip)) pool.relay.push(ip);
      else pool.server.push(ip);
    });
  }

  RELAY_PROXY_DOMAINS.forEach(function (d) { if (pool.relay.indexOf(d) === -1) pool.relay.push(d); });

  if (pool.server.length === 0) {
    parseIpList(sysConfig.cleanIps).slice(0, 5).forEach(function (ip) { pool.server.push(ip); });
  }

  pool.server = Array.from(new Set(pool.server));
  pool.relay = Array.from(new Set(pool.relay));
  return pool;
}

function getEffectivePips(p) {
  const nat64 = getEffectiveNat64(p.nat64);
  const pool = buildRelayPool(p);
  let pips = pool.relay.slice();
  if (pips.length === 0) pips = RELAY_PROXY_DOMAINS.slice(0, 3);
  if (nat64) {
    const expanded = [];
    pips.forEach(function (ip) {
      expanded.push(ip);
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        const n = ipv4ToNat64(ip, nat64);
        if (n) expanded.push(n);
      }
    });
    pips = expanded;
  }
  return rankRelays(pips);
}

function getRelayRegionServerIps(p) {
  const pool = buildRelayPool(p);
  if (pool.server.length > 0) return pool.server.slice();
  return null;
}

/* ═══════════ RELAY PRESETS v2.0 ═══════════ */
const RELAY_IP_PRESETS = [
  {id:"auto",name:"اتوماتیک",flag:"⚡",serverIps:[],relayIps:["ProxyIP.CMLiussss.net","ProxyIP.US.KG","ProxyIP.CM.RF.TW","ProxyIP.Dynu.net","ts.hpc.tw"],ips:["ProxyIP.CMLiussss.net","ProxyIP.US.KG","ProxyIP.CM.RF.TW","ProxyIP.Dynu.net","ts.hpc.tw"]},
  {id:"de",name:"آلمان",flag:"🇩🇪",serverIps:["188.114.96.1","188.114.97.1","188.114.98.1","188.114.99.1","188.114.100.1","188.114.101.1","188.114.102.1","188.114.103.1","188.114.104.1","188.114.105.1","188.114.106.1","188.114.107.1","188.114.108.1","188.114.109.1","188.114.110.1","188.114.111.1","188.114.96.2","188.114.97.2","188.114.98.2","188.114.99.2","188.114.96.20","188.114.97.20","188.114.98.20","188.114.99.20","188.114.100.20","188.114.101.20","188.114.102.20","188.114.103.20"],relayIps:["ProxyIP.CMLiussss.net","ProxyIP.US.KG","ts.hpc.tw"],ips:["188.114.96.1","188.114.97.1","188.114.98.1","188.114.99.1","188.114.100.1","188.114.101.1","188.114.102.1","188.114.103.1","188.114.104.1","188.114.105.1","188.114.106.1","188.114.107.1","188.114.108.1","188.114.109.1","188.114.110.1","188.114.111.1","188.114.96.2","188.114.97.2","188.114.98.2","188.114.99.2"]},
  {id:"us",name:"آمریکا",flag:"🇺🇸",serverIps:["104.16.0.1","104.16.1.1","104.16.2.1","104.17.0.1","104.17.1.1","104.18.0.1","104.18.1.1","104.19.0.1","104.19.1.1","104.20.0.1","104.20.1.1","104.21.0.1","104.21.1.1","104.22.0.1","104.22.1.1","104.23.0.1","104.24.0.1","104.25.0.1","104.26.0.1","104.27.0.1","172.64.0.1","172.65.0.1","172.66.0.1","172.67.0.1","162.159.36.1","162.159.46.1","162.159.128.1","162.159.129.1","162.159.130.1","162.159.131.1","162.159.132.1","162.159.133.1","162.159.134.1","162.159.135.1","162.159.136.1","162.159.137.1","162.159.138.1","162.159.152.1","162.159.153.1"],relayIps:["ProxyIP.CMLiussss.net","ProxyIP.US.KG","ProxyIP.Dynu.net"],ips:["104.16.0.1","104.16.1.1","104.16.2.1","104.17.0.1","104.17.1.1","104.18.0.1","104.18.1.1","104.19.0.1","104.19.1.1","104.20.0.1","104.20.1.1","104.21.0.1","104.21.1.1","104.22.0.1","104.22.1.1","104.23.0.1","104.24.0.1","104.25.0.1","104.26.0.1","104.27.0.1","172.64.0.1","172.65.0.1","172.66.0.1","172.67.0.1"]},
  {id:"ae",name:"امارات",flag:"🇦🇪",serverIps:["197.234.240.1","197.234.240.2","197.234.240.3","197.234.241.1","197.234.241.2","197.234.241.3","197.234.242.1","197.234.242.2","197.234.242.3","197.234.243.1","197.234.243.2","197.234.243.3"],relayIps:["ProxyIP.CMLiussss.net","ProxyIP.US.KG"],ips:["197.234.240.1","197.234.240.2","197.234.240.3","197.234.241.1","197.234.241.2","197.234.242.1","197.234.242.2","197.234.242.3","197.234.243.1","197.234.243.2","197.234.243.3"]},
  {id:"fr",name:"فرانسه",flag:"🇫🇷",serverIps:["188.114.96.20","188.114.97.20","188.114.98.20","188.114.99.20","188.114.100.20","188.114.101.20"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.96.20","188.114.97.20","188.114.98.20","188.114.99.20","188.114.100.20","188.114.101.20"]},
  {id:"nl",name:"هلند",flag:"🇳🇱",serverIps:["188.114.100.20","188.114.101.20","188.114.102.20","188.114.103.20","188.114.104.20","188.114.105.20"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.100.20","188.114.101.20","188.114.102.20","188.114.103.20","188.114.104.20","188.114.105.20"]},
  {id:"uk",name:"انگلستان",flag:"🇬🇧",serverIps:["188.114.104.20","188.114.105.20","188.114.106.20","188.114.107.20","188.114.108.20"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.104.20","188.114.105.20","188.114.106.20","188.114.107.20","188.114.108.20"]},
  {id:"tr",name:"ترکیه",flag:"🇹🇷",serverIps:["188.114.108.20","188.114.109.20","188.114.110.20","188.114.111.20","188.114.96.30","188.114.97.30"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.108.20","188.114.109.20","188.114.110.20","188.114.111.20","188.114.96.30","188.114.97.30"]},
  {id:"in",name:"هند",flag:"🇮🇳",serverIps:["103.21.244.1","103.21.244.2","103.21.244.3","103.21.244.20","103.21.244.21","103.22.200.1","103.22.200.2","103.22.200.20","103.22.200.21","103.31.4.1","103.31.4.2"],relayIps:["ProxyIP.CMLiussss.net"],ips:["103.21.244.1","103.21.244.2","103.21.244.3","103.21.244.20","103.21.244.21","103.22.200.1","103.22.200.2","103.22.200.20","103.22.200.21","103.31.4.1","103.31.4.2"]},
  {id:"sg",name:"سنگاپور",flag:"🇸🇬",serverIps:["103.21.244.30","103.21.244.31","103.21.244.32","103.22.200.30","103.22.200.31","103.22.200.32","103.31.4.30","103.31.4.31"],relayIps:["ProxyIP.CMLiussss.net"],ips:["103.21.244.30","103.21.244.31","103.21.244.32","103.22.200.30","103.22.200.31","103.22.200.32","103.31.4.30","103.31.4.31"]},
  {id:"ca",name:"کانادا",flag:"🇨🇦",serverIps:["104.16.100.1","104.17.100.1","104.18.100.1","104.19.100.1","104.20.100.1","104.21.100.1"],relayIps:["ProxyIP.US.KG"],ips:["104.16.100.1","104.17.100.1","104.18.100.1","104.19.100.1","104.20.100.1","104.21.100.1"]},
  {id:"jp",name:"ژاپن",flag:"🇯🇵",serverIps:["104.22.100.1","104.23.100.1","104.24.100.1","104.25.100.1","104.26.100.1","104.27.100.1"],relayIps:["ts.hpc.tw"],ips:["104.22.100.1","104.23.100.1","104.24.100.1","104.25.100.1","104.26.100.1","104.27.100.1"]},
  {id:"au",name:"استرالیا",flag:"🇦🇺",serverIps:["172.64.100.1","172.65.100.1","172.66.100.1","172.67.100.1","172.64.100.2","172.65.100.2"],relayIps:["ProxyIP.CMLiussss.net"],ips:["172.64.100.1","172.65.100.1","172.66.100.1","172.67.100.1","172.64.100.2","172.65.100.2"]},
  {id:"br",name:"برزیل",flag:"🇧🇷",serverIps:["104.16.200.1","104.17.200.1","104.18.200.1","104.19.200.1","104.20.200.1"],relayIps:["ProxyIP.US.KG"],ips:["104.16.200.1","104.17.200.1","104.18.200.1","104.19.200.1","104.20.200.1"]},
  {id:"ru",name:"روسیه",flag:"🇷🇺",serverIps:["188.114.96.100","188.114.97.100","188.114.98.100","188.114.99.100","188.114.100.100"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.96.100","188.114.97.100","188.114.98.100","188.114.99.100","188.114.100.100"]},
  {id:"se",name:"سوئد",flag:"🇸🇪",serverIps:["188.114.101.100","188.114.102.100","188.114.103.100","188.114.104.100"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.101.100","188.114.102.100","188.114.103.100","188.114.104.100"]},
  {id:"fi",name:"فینلاند",flag:"🇫🇮",serverIps:["188.114.105.100","188.114.106.100","188.114.107.100","188.114.108.100"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.105.100","188.114.106.100","188.114.107.100","188.114.108.100"]},
  {id:"ch",name:"سوئیس",flag:"🇨🇭",serverIps:["188.114.109.100","188.114.110.100","188.114.111.100","188.114.96.110"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.109.100","188.114.110.100","188.114.111.100","188.114.96.110"]},
  {id:"es",name:"اسپانیا",flag:"🇪🇸",serverIps:["188.114.97.110","188.114.98.110","188.114.99.110","188.114.100.110"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.97.110","188.114.98.110","188.114.99.110","188.114.100.110"]},
  {id:"it",name:"ایتالیا",flag:"🇮🇹",serverIps:["188.114.101.110","188.114.102.110","188.114.103.110","188.114.104.110"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.101.110","188.114.102.110","188.114.103.110","188.114.104.110"]},
  {id:"pl",name:"لهستان",flag:"🇵🇱",serverIps:["188.114.105.110","188.114.106.110","188.114.107.110","188.114.108.110"],relayIps:["ProxyIP.CMLiussss.net"],ips:["188.114.105.110","188.114.106.110","188.114.107.110","188.114.108.110"]},
  {id:"kr",name:"کره جنوبی",flag:"🇰🇷",serverIps:["104.16.150.1","104.17.150.1","104.18.150.1","104.19.150.1"],relayIps:["ts.hpc.tw"],ips:["104.16.150.1","104.17.150.1","104.18.150.1","104.19.150.1"]},
  {id:"hk",name:"هنگ‌کنگ",flag:"🇭🇰",serverIps:["104.20.150.1","104.21.150.1","104.22.150.1","104.23.150.1"],relayIps:["ts.hpc.tw"],ips:["104.20.150.1","104.21.150.1","104.22.150.1","104.23.150.1"]}
];

const DEFAULT_REGIONS = RELAY_IP_PRESETS.filter(function (r) { return r.id !== "auto"; });
const getAlpha = function () { return String.fromCharCode(118, 108, 101, 115, 115); };
const getBeta = function () { return String.fromCharCode(116, 114, 111, 106, 97, 110); };
const getGamma = function () { return String.fromCharCode(99, 108, 97, 115, 104); };

const OTTER_SVG = '<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">'
+ '<defs>'
+ '<linearGradient id="otterBodyGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#ec4899"/></linearGradient>'
+ '<linearGradient id="otterEarGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#06b6d4"/><stop offset="100%" stop-color="#8b5cf6"/></linearGradient>'
+ '</defs>'
+ '<circle cx="26" cy="30" r="10" fill="url(#otterEarGrad)"/><circle cx="74" cy="30" r="10" fill="url(#otterEarGrad)"/>'
+ '<circle cx="26" cy="30" r="5" fill="#0a0e1a"/><circle cx="74" cy="30" r="5" fill="#0a0e1a"/>'
+ '<ellipse cx="50" cy="55" rx="34" ry="34" fill="url(#otterBodyGrad)"/>'
+ '<circle cx="39" cy="52" r="4.5" fill="#0a0e1a"/><circle cx="61" cy="52" r="4.5" fill="#0a0e1a"/>'
+ '<circle cx="40.5" cy="50.5" r="1.6" fill="#fff"/><circle cx="62.5" cy="50.5" r="1.6" fill="#fff"/>'
+ '<ellipse cx="50" cy="66" rx="13" ry="10" fill="#fff" opacity=".9"/><ellipse cx="50" cy="62" rx="3.5" ry="2.5" fill="#0a0e1a"/>'
+ '</svg>';

const safeBtoa = function (str) {
  try {
    const bytes = new TextEncoder().encode(str);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  } catch (e) { return btoa(str); }
};

function parsePorts(raw, fallback) {
  const list = String(raw || "").split(/[\r\n,;\s]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  const valid = list.filter(function (p) { return /^\d{1,5}$/.test(p) && parseInt(p) > 0 && parseInt(p) <= 65535; });
  return valid.length > 0 ? Array.from(new Set(valid)) : (fallback || ["443"]);
}
function parseIpList(raw) {
  if (!raw) return [];
  return String(raw).split(/[\r\n,;]+/).map(function (s) {
    const t = s.trim();
    if (!t) return "";
    return t.split("#")[0].trim();
  }).filter(Boolean);
}
function getEffectivePorts(p, ispTemplate) {
  if (p && p.userPorts && String(p.userPorts).trim()) {
    const pp = parsePorts(p.userPorts);
    if (pp.length > 0) return pp;
  }
  if (p && p.isp && ispTemplate && ispTemplate.ports && String(ispTemplate.ports).trim()) {
    const ip = parsePorts(ispTemplate.ports);
    if (ip.length > 0) return ip;
  }
  return parsePorts(sysConfig.socketPorts, ["443"]);
}

/* ═══════════ SYSTEM DEFAULTS ═══════════ */
const SYSTEM_DEFAULTS = {
  name: "", apiRoute: "sub",
  maintenanceHost: "https://www.ubuntu.com, https://www.docker.com",
  backupRelay: "", customRelay: "", masterKey: "admin", metricNode: "time.is",
  cleanIps: "", slaveNodes: "", deviceId: "", mode: "alpha", agent: "chrome",
  socketPorts: CF_HTTPS_PORTS.join(","),
  customDns: "https://cloudflare-dns.com/dns-query",
  resolveIp: "1.1.1.1", enableOpt1: false, enableOpt2: false,
  tgToken: "", tgChatId: "", tgAdminId: "", cfAccountId: "", cfApiToken: "",
  cfWorkerName: "", isPaused: false, silentAlerts: false,
  githubRepo: "THE-SAZ/hamed-panel", nameStrategy: "default", namePrefix: "Hamed",
  tgBotLang: "fa", users: [], subUserAgent: "", customPanelUrl: "",
  limitTotalReq: 0, expiryMs: 0, linkedPanels: [], hubPanelUrl: "",
  syncApiKey: "", panelApiKeys: [], nat64Prefix: "", enableDirectConfigs: false,
  customRouting: "", upstreamUri: "", autoUpdate: false, autoUpdateFormat: "encoded",
  captchaEnabled: true,
  userGroups: [
    { id: "default", name: "پیش‌فرض", limitTotalGb: 0, limitDailyGb: 0, expiryDays: 0, maxConfigs: 0, connLimit: 0, color: "#8b5cf6" },
    { id: "vip", name: "VIP", limitTotalGb: 100, limitDailyGb: 20, expiryDays: 30, maxConfigs: 5, connLimit: 3, color: "#f59e0b" },
    { id: "test", name: "تست", limitTotalGb: 5, limitDailyGb: 2, expiryDays: 3, maxConfigs: 2, connLimit: 2, color: "#06b6d4" }
  ],
  fragmentPresets: [
    { id: "off", name: "خاموش", value: "" },
    { id: "mci", name: "همراه اول", value: "1-3-1-2" },
    { id: "irancell", name: "ایرانسل", value: "1-3-1-2" },
    { id: "rightel", name: "رایتل", value: "1-1-1-1" },
    { id: "mokhaberat", name: "مخابرات", value: "1-2-1-1" },
    { id: "shatel", name: "شاتل", value: "1-2-1-1" },
    { id: "aggressive", name: "تهاجمی", value: "5-10-5-10" },
    { id: "light", name: "سبک", value: "1-1-1-1" },
    { id: "heavy", name: "سنگین", value: "10-20-10-20" }
  ],
  activeFragment: "off", activeCarrier: "",
  autoCleanIpTest: false, autoCleanIpTopN: 5,
  autoCleanIpCache: { ips: [], testedAt: 0 },
  cleanIpRegions: DEFAULT_REGIONS,
  activeCleanRegions: ["de", "us", "ae"],
  cleanRegionMode: "round-robin",
  relayIpPresets: RELAY_IP_PRESETS,
  ispTemplates: {
    mci: { name: "همراه اول", fragment: "1-3-1-2", ports: "", agent: "chrome", extraSni: "" },
    irancell: { name: "ایرانسل", fragment: "1-3-1-2", ports: "", agent: "chrome", extraSni: "" },
    rightel: { name: "رایتل", fragment: "1-1-1-1", ports: "", agent: "chrome", extraSni: "" },
    mokhaberat: { name: "مخابرات", fragment: "1-2-1-1", ports: "", agent: "chrome", extraSni: "" },
    shatel: { name: "شاتل", fragment: "1-2-1-1", ports: "", agent: "chrome", extraSni: "" },
    default: { name: "پیش‌فرض", fragment: "", ports: "", agent: "chrome", extraSni: "" }
  },
  iranRouting: true,
  autoResetCycles: {},
  historyEnabled: true,
  anomalyThreshold: 5,
  customLogo: "", customTitleColor: "",
  cronJobs: [], webhooks: [], bannedIps: [],
  crisisPresets: [
    { id: "cut", title: "⚠️ قطعی سراسری", text: "⚠️ توجه: در حال حاضر اینترنت سراسری دچار اختلال است." },
    { id: "slow", title: "🐢 کندی سرعت", text: "🐢 ممکن است سرعت اینترنت شما کاهش یابد." },
    { id: "update", title: "🔄 بروزرسانی سرور", text: "🔄 سرورها در حال بروزرسانی هستند." }
  ],
  crisisHistory: [],
  workflows: [], workflowRuns: [],
  cfUsageAlert: { enabled: true, thresholdPct: 80, lastAlert: 0 },
  autoFailover: { enabled: true, maxRetries: 3, timeoutMs: 8000, healthCheckIntervalMin: 15 },
  smartSuggestionsEnabled: true,
  predictiveDays: 7,
  multiUpstream: [],
  dnsPool: [
    { url: "https://cloudflare-dns.com/dns-query", name: "Cloudflare", weight: 100, enabled: true },
    { url: "https://dns.google/dns-query", name: "Google", weight: 100, enabled: true },
    { url: "https://dns.quad9.net/dns-query", name: "Quad9", weight: 50, enabled: true },
    { url: "https://doh.shecan.ir/dns-query", name: "Shecan", weight: 80, enabled: true },
    { url: "https://dns.adguard-dns.com/dns-query", name: "AdGuard", weight: 50, enabled: true },
    { url: "https://dns.electrotm.org/dns-query", name: "Electrotm", weight: 40, enabled: true },
    { url: "https://dns.begzar.ir/dns-query", name: "Begzar", weight: 40, enabled: true }
  ],
  dnsPoolStrategy: "weighted",
  latencyMap: { byRegion: {}, lastUpdate: 0 },
  dpiDetection: { lastCheck: 0, score: 0, mode: "unknown" },
  speedTestCache: { results: [], lastUpdate: 0 },
  nodeFailoverState: {},
  autoBanEnabled: false,
  _migratedToSub: false,
  _migratedV107: false,
  _migratedV108: false,
  _migratedV200: false,
  advanced: {
    http3: false, tcpFastOpen: true, mux: false, muxConcurrency: 8,
    xtls: false, earlyData: false, earlyDataHeader: "Sec-WebSocket-Protocol",
    customPath: "", customSni: "", customHost: "", padding: false,
    alpn: "", ech: false, keepAlive: 30, udpRelay: true, tlsFragment: true
  },
  inboundConfigs: {
    enabled: true,
    global: { nameTemplate: "{FLAG} {PREFIX}-{INDEX}", applyToAll: true, maxNameLength: 60, asciiOnly: false, prefix: "Hamed", useRelayGeo: true },
    extraEntries: [{ id: "made-by", text: "THIS PANEL MADE BY HAMED TEAM", type: "static", enabled: true, position: "start", flagPrefix: "🦦" }],
    customInbounds: [],
    availableTags: [
      { tag: "FLAG", desc: "پرچم کشور IP", example: "🇩🇪" },
      { tag: "COUNTRY", desc: "نام کشور", example: "Germany" },
      { tag: "CITY", desc: "نام شهر", example: "Frankfurt" },
      { tag: "ISP", desc: "نام ISP", example: "Cloudflare" },
      { tag: "PROTOCOL", desc: "پروتکل", example: "VLESS" },
      { tag: "USER", desc: "نام کاربر", example: "ali" },
      { tag: "PORT", desc: "پورت کانفیگ", example: "443" },
      { tag: "PREFIX", desc: "پیشوند تنظیمات", example: "Hamed" },
      { tag: "IP", desc: "آی‌پی کانفیگ", example: "188.114.96.1" },
      { tag: "HOST", desc: "هاست تنظیمات", example: "panel.workers.dev" },
      { tag: "DATE", desc: "تاریخ امروز", example: "2025-09-13" },
      { tag: "INDEX", desc: "شماره کانفیگ", example: "1" },
      { tag: "REGION", desc: "نام منطقه IP", example: "آلمان" },
      { tag: "TAG", desc: "برچسب کاربر", example: "VIP" },
      { tag: "WORKER", desc: "نام Worker", example: "hamed-panel" },
      { tag: "RELAY", desc: "پرچم Relay", example: "🇩🇪" },
      { tag: "PANEL", desc: "نام پنل", example: "Hamed Panel" },
      { tag: "VERSION", desc: "نسخه پنل", example: "1.0.8" }
    ],
    perUser: {}
  },
  managers: [
    { id: "root-admin", username: "admin", passwordHash: null, salt: "builtin-salt-v1", permissions: ["all"], isRoot: true, isActive: true, createdAt: 0, lastLogin: null, createdBy: "system" }
  ],
  fakeConfigs: [
    { name: "📊 {usage}", enabled: true },
    { name: "📅 {expiry}", enabled: true }
  ]
};

/* ═══════════ GLOBAL STATE ═══════════ */
let sysConfig = Object.assign({}, SYSTEM_DEFAULTS);
let isolateStartTime = 0;
let activeConnections = 0;
let activeConns = new Map();
let activeDeviceId = "";
let configRegistry = new Map();
let sysUsageCache = { users: {} };
let sysHistoryCache = { days: {} };
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

/* ═══════════ CRYPTO ═══════════ */
async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(String(salt) + ":" + String(password) + ":hamed-v108");
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
function generateSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
function generateSessionToken() {
  return "sess_" + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
function generateId(prefix) { return (prefix || "id") + "_" + crypto.randomUUID().slice(0, 8); }

async function hmacSign(secret, message) {
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
    return Array.from(new Uint8Array(sig)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  } catch (e) { return ""; }
}

let _encKeyCache = null, _encKeyCacheSrc = null;
async function getEncryptionKey(masterKey) {
  if (_encKeyCache && _encKeyCacheSrc === masterKey) return _encKeyCache;
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(masterKey || "default"), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("hamed-panel-enc-v108"), iterations: 50000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  _encKeyCache = key; _encKeyCacheSrc = masterKey;
  return key;
}
async function encryptField(pt, mk) {
  if (!pt) return "";
  if (typeof pt === "string" && pt.startsWith("enc:")) return pt;
  try {
    const key = await getEncryptionKey(mk);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(String(pt)));
    const combined = new Uint8Array(iv.length + ct.byteLength);
    combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
    let bin = "";
    for (let i = 0; i < combined.length; i++) bin += String.fromCharCode(combined[i]);
    return "enc:" + btoa(bin);
  } catch (e) { return pt; }
}
async function decryptField(ct, mk) {
  if (!ct) return "";
  if (typeof ct !== "string" || !ct.startsWith("enc:")) return ct;
  try {
    const key = await getEncryptionKey(mk);
    const raw = atob(ct.slice(4));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const iv = bytes.slice(0, 12), data = bytes.slice(12);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder().decode(pt);
  } catch (e) { return ""; }
}
async function encryptSensitiveInConfig(cfg, mk) {
  if (!cfg) return cfg;
  const out = Object.assign({}, cfg);
  for (const f of SENSITIVE_FIELDS) {
    if (out[f] && !String(out[f]).startsWith("enc:")) out[f] = await encryptField(out[f], mk);
  }
  return out;
}
async function decryptSensitiveInConfig(cfg, mk) {
  if (!cfg) return cfg;
  const out = Object.assign({}, cfg);
  for (const f of SENSITIVE_FIELDS) {
    if (out[f] && String(out[f]).startsWith("enc:")) out[f] = await decryptField(out[f], mk);
  }
  return out;
}

/* ═══════════ STORAGE ═══════════ */
async function d1Init(env) {
  if (env.IOT_DB && !env.IOT_DB_INITIALIZED) {
    try {
      await env.IOT_DB.prepare("CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT)").run();
      env.IOT_DB_INITIALIZED = true;
    } catch (e) { env.IOT_DB_INITIALIZED = true; }
  }
}
async function d1Get(env, key) {
  if (!env.IOT_DB) return null;
  await d1Init(env);
  try {
    const res = await env.IOT_DB.prepare("SELECT value FROM kv_store WHERE key = ?").bind(key).all();
    const results = res.results;
    if (results && results.length > 0) return results[0].value;
  } catch (e) {}
  return null;
}
async function d1Put(env, key, value) {
  if (!env.IOT_DB) return;
  await d1Init(env);
  try {
    if (value === "" || value === null || value === undefined) {
      await env.IOT_DB.prepare("DELETE FROM kv_store WHERE key = ?").bind(key).run();
      return;
    }
    await env.IOT_DB.prepare("INSERT INTO kv_store (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value).run();
  } catch (e) {}
}
async function d1List(env, prefix) {
  if (!env.IOT_DB) return [];
  await d1Init(env);
  try {
    const res = await env.IOT_DB.prepare("SELECT key, value FROM kv_store WHERE key LIKE ?").bind(prefix + "%").all();
    return res.results || [];
  } catch (e) { return []; }
}
async function cachedD1Put(env, key, value) {
  await d1Put(env, key, value);
  if (key === "sys_config") sysConfigCacheTime = 0;
  else if (key === "sys_usage") sysUsageCacheTime = 0;
  else if (key === "sys_history") sysHistoryCacheTime = 0;
  else if (key === "backup_ip") backupIpCacheTime = 0;
}
async function sessPut(env, key, value, ttl) {
  if (env.SESSIONS_KV) {
    try { await env.SESSIONS_KV.put(key, value, ttl ? { expirationTtl: ttl } : undefined); return; } catch (e) {}
  }
  await d1Put(env, key, value);
}
async function sessGet(env, key) {
  if (env.SESSIONS_KV) {
    try { const v = await env.SESSIONS_KV.get(key); if (v !== null) return v; } catch (e) {}
  }
  return await d1Get(env, key);
}
async function sessDel(env, key) {
  if (env.SESSIONS_KV) { try { await env.SESSIONS_KV.delete(key); } catch (e) {} }
  await d1Put(env, key, "");
}

/* ═══════════ SHA-224 (Trojan) ═══════════ */
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
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let j = 0; j < 64; j++) {
      if (j < 16) W[j] = words[i + j];
      else {
        let w15 = W[j - 15], w2 = W[j - 2];
        let s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
        let s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
      }
      let S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      let ch = (e & f) ^ (~e & g);
      let temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
      let S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H.slice(0, 7).map(function (v) { return v.toString(16).padStart(8, "0"); }).join("");
}
const trojanHashCache = new Map();
function getTrojanHash(uuid) {
  if (trojanHashCache.has(uuid)) return trojanHashCache.get(uuid);
  const h = sha224Hex(uuid);
  trojanHashCache.set(uuid, h);
  return h;
}

/* ═══════════ UUID FINGERPRINT ═══════════ */
function getUserFingerprint(userId) {
  const s = String(userId || "").toLowerCase();
  let h1 = 0x811c9dc5 >>> 0, h2 = 0x811c9dc5 >>> 0, h3 = 0x811c9dc5 >>> 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
    h2 = Math.imul(h2 ^ (c + 7), 16777619) >>> 0;
    h3 = Math.imul(h3 ^ (c + 13), 16777619) >>> 0;
  }
  return h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0") + h3.toString(16).padStart(8, "0");
}
function registerConfigEntry(uuid, userId, relayIp) {
  const e = { userId: userId, relayIp: relayIp || "" };
  configRegistry.set(uuid.replace(/-/g, "").toLowerCase(), e);
  configRegistry.set(getTrojanHash(uuid), e);
}
function lookupConfigEntry(uuidHex) { return configRegistry.get(uuidHex.toLowerCase()) || null; }
function generateConfigUuid(originalUuid, relayIpIndex) {
  const base24 = getUserFingerprint(originalUuid);
  const relay = (relayIpIndex >>> 0).toString(16).padStart(8, "0");
  const full = base24 + relay;
  return full.substring(0, 8) + "-" + full.substring(8, 12) + "-" + full.substring(12, 16) + "-" + full.substring(16, 20) + "-" + full.substring(20, 32);
}
function decodeConfigUuid(uuid) {
  const c = uuid.replace(/-/g, "").toLowerCase();
  if (c.length !== 32) return null;
  return { userFingerprint: c.substring(0, 24), relayIpIndex: parseInt(c.substring(24, 32), 16) };
}
function isPanelApiKey(key) {
  if (!key || !Array.isArray(sysConfig.panelApiKeys)) return false;
  return sysConfig.panelApiKeys.some(function (k) { return k.key === key; });
}
function generateApiKey(name) {
  const id = generateId("key");
  const raw = "hamed_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 10);
  return { id: id, name: name || "Unnamed Key", key: raw, createdAt: Date.now(), lastUsed: null };
}

/* ═══════════ RELAY HELPERS ═══════════ */
function getProxyIpsArray(s) {
  if (!s) return [];
  return String(s).split(/[\r\n,;]+/).map(function (x) {
    const t = x.trim();
    if (!t) return "";
    const hp = t.split("#")[0].split("@")[0];
    if (hp.indexOf(":") !== -1 && hp.indexOf("]") === -1) return hp.split(":")[0];
    if (hp.charAt(0) === "[" && hp.indexOf("]") !== -1) return hp.split("]")[0].replace("[", "");
    return hp;
  }).filter(Boolean);
}
function ipv4ToNat64(ipv4, prefix) {
  if (!prefix || !ipv4) return null;
  const p = ipv4.split(".");
  if (p.length !== 4) return null;
  const hex = p.map(function (x) { return parseInt(x).toString(16).padStart(2, "0"); }).join("");
  const suffix = hex.match(/.{1,4}/g).join(":");
  return prefix.replace(/\/\d+$/, "").replace(/:$/, "") + "::" + suffix;
}
function getProxyIpsWithNat64(s, nat64Prefix) {
  let ips = getProxyIpsArray(s);
  if (nat64Prefix) {
    const prefixes = String(nat64Prefix).split(/[\r\n,;]+/).map(function (x) { return x.trim(); }).filter(Boolean);
    const nat64Ips = [];
    prefixes.forEach(function (pre) {
      ips.forEach(function (ip) {
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
          const n = ipv4ToNat64(ip, pre);
          if (n) nat64Ips.push(n);
        }
      });
    });
    ips = ips.concat(nat64Ips);
  }
  return ips;
}
function getEffectiveNat64(userNat64) {
  const parts = [];
  if (userNat64) parts.push.apply(parts, String(userNat64).split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean));
  if (sysConfig.nat64Prefix) parts.push.apply(parts, String(sysConfig.nat64Prefix).split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean));
  else if (sysConfig.activeCarrier && CARRIERS[sysConfig.activeCarrier]) parts.push(CARRIERS[sysConfig.activeCarrier].nat64);
  return Array.from(new Set(parts)).join(",") || null;
}
function getRelayRegionInfo(p) {
  if (!p) return null;
  if (p.relayPresetId && p.relayPresetId !== "auto") {
    const preset = (sysConfig.relayIpPresets || RELAY_IP_PRESETS).find(function (r) { return r.id === p.relayPresetId; });
    if (preset && preset.id !== "auto") return { id: preset.id, name: preset.name, flag: preset.flag };
  }
  if (p.proxyIpGeo && p.proxyIpGeo.flag && p.proxyIpGeo.flag !== "🌐") {
    return { id: "custom", name: p.proxyIpGeo.country || "Relay", flag: p.proxyIpGeo.flag };
  }
  return null;
}

/* ═══════════ GEO ═══════════ */
const ipGeoCache = new Map();
function getGeoInfo(ip) {
  if (!ip) return { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
  const clean = ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim();
  return ipGeoCache.get(ip) || ipGeoCache.get(clean) || { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
}
async function fetchIpGeoData(ip) {
  if (!ip) return null;
  try {
    const cleanIp = ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim();
    const r = await fetch("http://ip-api.com/json/" + cleanIp + "?fields=status,country,countryCode,city,isp,org", { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    if (d && d.status === "success") {
      const cp = d.countryCode.toUpperCase().split("").map(function (c) { return 127397 + c.charCodeAt(); });
      return { flag: String.fromCodePoint.apply(String, cp), country: d.country || "Unknown", countryCode: d.countryCode || "", city: d.city || "", isp: d.isp || d.org || "" };
    }
  } catch (e) {}
  return null;
}
async function resolveUserProxyIpGeo(user) {
  try {
    const src = user.relayIps || user.proxyIp;
    if (!src) {
      if (user.relayPresetId) {
        const preset = (sysConfig.relayIpPresets || RELAY_IP_PRESETS).find(function (r) { return r.id === user.relayPresetId; });
        if (preset && preset.serverIps && preset.serverIps.length > 0) {
          const geo = await fetchIpGeoData(preset.serverIps[0]);
          user.proxyIpGeo = geo || null;
          return;
        }
      }
      user.proxyIpGeo = null;
      return;
    }
    const pips = getProxyIpsArray(src);
    if (pips.length === 0) { user.proxyIpGeo = null; return; }
    const geo = await fetchIpGeoData(pips[0]);
    user.proxyIpGeo = geo || { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" };
  } catch (e) { user.proxyIpGeo = null; }
}
async function preloadIpFlags(profiles, hostNames) {
  try {
    const uniqueIps = new Set();
    profiles.forEach(function (p) {
      hostNames.forEach(function (h) {
        getCleanIps(h, p.cleanIp).forEach(function (ip) { uniqueIps.add(ip); });
      });
      if (p.proxyIp) getProxyIpsArray(p.proxyIp).forEach(function (ip) { uniqueIps.add(ip); });
      const pool = buildRelayPool(p);
      pool.server.forEach(function (ip) { uniqueIps.add(ip); });
    });
    const uncached = Array.from(uniqueIps).filter(function (ip) {
      return !ipGeoCache.has(ip) && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip.split(":")[0]);
    });
    for (let i = 0; i < uncached.length; i += 100) {
      const batch = uncached.slice(i, i + 100);
      const queries = batch.map(function (ip) {
        return { query: ip.split(":")[0].replace(/[\[\]]/g, "").split("#")[0].trim(), fields: "status,country,countryCode,city,isp,org" };
      });
      try {
        const r = await fetch("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(queries), signal: AbortSignal.timeout(5000)
        });
        const results = await r.json();
        batch.forEach(function (ip, idx) {
          const d = results[idx];
          if (d && d.status === "success") {
            const cp = d.countryCode.toUpperCase().split("").map(function (c) { return 127397 + c.charCodeAt(); });
            ipGeoCache.set(ip, { flag: String.fromCodePoint.apply(String, cp), country: d.country || "Unknown", countryCode: d.countryCode || "", city: d.city || "", isp: d.isp || d.org || "" });
          } else ipGeoCache.set(ip, { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" });
        });
      } catch (e) {
        batch.forEach(function (ip) { if (!ipGeoCache.has(ip)) ipGeoCache.set(ip, { flag: "🌐", country: "Unknown", countryCode: "", city: "", isp: "" }); });
      }
    }
  } catch (e) {}
}

/* ═══════════ PROFILE HELPERS ═══════════ */
function getAllProfiles(targetSub) {
  let list = [{ id: activeDeviceId, name: "Default" }];
  if (sysConfig.users && sysConfig.users.length > 0) {
    const now = Date.now();
    sysConfig.users.forEach(function (u) {
      let skip = false;
      if (u.expiryMs && now > u.expiryMs) skip = true;
      if (u.isPaused) skip = true;
      const c = u.id.replace(/-/g, "").toLowerCase();
      const sysU = sysUsageCache && sysUsageCache.users ? sysUsageCache.users[c] : null;
      if (u.limitTotalReq && sysU && sysU.reqs >= u.limitTotalReq) skip = true;
      if (!skip) {
        list.push({
          id: u.id, name: u.name, isp: u.isp || null, tags: u.tags || [],
          bandwidthKbps: u.bandwidthKbps || null, proxyIp: u.proxyIp,
          proxyIpGeo: u.proxyIpGeo || null, cleanIp: u.cleanIp || null,
          userMode: u.userMode || null, userPorts: u.userPorts || null,
          maxConfigs: u.maxConfigs || null, userNodes: u.userNodes || null,
          nat64: u.nat64 || null, connLimit: u.connLimit || null,
          userPanelUrl: u.userPanelUrl || null,
          relayIps: u.relayIps || "", relayMode: u.relayMode || "single",
          relayPresetId: u.relayPresetId || ""
        });
        registerConfigEntry(u.id, u.id, u.proxyIp || "");
      }
    });
  }
  if (targetSub) list = list.filter(function (p) { return p.name.toLowerCase() === targetSub.toLowerCase() || p.id === targetSub; });
  return list;
}
function linkedPanelHost(p) {
  let raw = p && typeof p === "object" ? (p.url || "") : (p || "");
  raw = String(raw).trim();
  if (!raw) return "";
  raw = raw.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0].split("@").pop();
  if (raw.charAt(0) === "[") return raw.slice(0, raw.indexOf("]") + 1);
  return raw.split(":")[0];
}
function getGlobalNodeHosts() {
  const hosts = [];
  if (sysConfig.slaveNodes) hosts.push.apply(hosts, sysConfig.slaveNodes.split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean));
  if (Array.isArray(sysConfig.linkedPanels)) hosts.push.apply(hosts, sysConfig.linkedPanels.map(linkedPanelHost).filter(Boolean));
  return Array.from(new Set(hosts));
}
function getProfileHostNames(hostName, profile) {
  const primary = profile && profile.userPanelUrl ? profile.userPanelUrl : hostName;
  const names = [];
  if (profile && profile.userNodes && profile.userNodes.trim()) {
    names.push.apply(names, profile.userNodes.split(/[\r\n,;]+/).map(function (s) { return linkedPanelHost(s.trim()); }).filter(Boolean));
  } else {
    names.push(linkedPanelHost(primary));
    names.push.apply(names, getGlobalNodeHosts());
  }
  return Array.from(new Set(names));
}
function getCleanIpsByRegion() {
  const regions = sysConfig.cleanIpRegions || [];
  const active = sysConfig.activeCleanRegions || [];
  const out = [];
  for (const id of active) {
    const r = regions.find(function (x) { return x.id === id; });
    if (r && r.ips && r.ips.length > 0) out.push({ region: r, ips: r.ips });
  }
  return out;
}
function getCleanIps(hostName, userCleanIps) {
  const raw = userCleanIps || sysConfig.cleanIps;
  let ips = parseIpList(raw);
  if (ips.length === 0) {
    const rg = getCleanIpsByRegion();
    if (rg.length > 0) {
      const flat = [];
      rg.forEach(function (g) { flat.push.apply(flat, g.ips); });
      ips = flat;
    }
  }
  if (ips.length === 0 && sysConfig.autoCleanIpCache && sysConfig.autoCleanIpCache.ips && sysConfig.autoCleanIpCache.ips.length > 0) ips = sysConfig.autoCleanIpCache.ips;
  if (ips.length === 0) ips = [hostName.indexOf(".pages.dev") !== -1 ? sysConfig.metricNode : hostName];
  return ips;
}
function getCleanIpsWithNames(hostName, userCleanIps) {
  const raw = userCleanIps || sysConfig.cleanIps;
  let entries = raw ? String(raw).split(/[\r\n,;]+/).map(function (s) {
    const t = s.trim();
    if (!t) return null;
    const p = t.split("#");
    const ip = p[0].trim();
    const name = (p[1] || "").trim();
    return ip ? { ip: ip, name: name } : null;
  }).filter(Boolean) : [];
  if (entries.length === 0) {
    const rg = getCleanIpsByRegion();
    if (rg.length > 0) rg.forEach(function (g) {
      g.ips.forEach(function (ip) {
        entries.push({ ip: ip, name: "", regionId: g.region.id, regionName: g.region.name, regionFlag: g.region.flag });
      });
    });
  }
  if (entries.length === 0 && sysConfig.autoCleanIpCache && sysConfig.autoCleanIpCache.ips && sysConfig.autoCleanIpCache.ips.length > 0) {
    entries = sysConfig.autoCleanIpCache.ips.map(function (ip) { return { ip: ip, name: "auto" }; });
  }
  if (entries.length === 0) entries = [{ ip: hostName.indexOf(".pages.dev") !== -1 ? sysConfig.metricNode : hostName, name: "" }];
  return entries;
}
function calcEffectiveIps(ips, maxCfg, mode, ports, pipsCount) {
  if (!maxCfg) return ips;
  if (pipsCount === undefined) pipsCount = 1;
  const protoCount = mode === "both" ? 2 : 1;
  const portCount = ports.length;
  const multiplier = protoCount * portCount * Math.max(1, pipsCount);
  const needed = Math.max(1, Math.floor(maxCfg / multiplier));
  return ips.slice(0, needed);
}

/* ═══════════ CONFIG NAME ═══════════ */
function buildInboundName(type, profile, ip, port, configIndex, hostName, regionInfo, isDirect) {
  try {
    const cfg = sysConfig.inboundConfigs || {};
    if (cfg.enabled === false) return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo);
    const userOverride = cfg.perUser ? cfg.perUser[profile.id] : null;
    const globalCfg = cfg.global || {};
    const template = (userOverride && userOverride.nameTemplate && userOverride.enabled !== false) ? userOverride.nameTemplate : (globalCfg.nameTemplate || "");
    if (!template) return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo);
    const geo = getGeoInfo(ip);
    const protoLab = type === "alpha" ? "VLESS" : "Trojan";
    const today = new Date();
    const dateStr = today.getFullYear() + "-" + String(today.getMonth() + 1).padStart(2, "0") + "-" + String(today.getDate()).padStart(2, "0");
    const prefix = globalCfg.prefix || sysConfig.namePrefix || "Hamed";
    const workerName = sysConfig.cfWorkerName || sysConfig.name || hostName || "";
    const flagValue = isDirect ? "☁" : ((regionInfo && regionInfo.flag) || geo.flag || "🌐");
    const countryValue = (regionInfo && regionInfo.name) || geo.country || "";
    const regionValue = (regionInfo && regionInfo.name) || "";
    const tagsValue = (profile.tags || []).join(",");
    let name = template
      .replace(/\{FLAG\}/g, flagValue).replace(/\{COUNTRY\}/g, countryValue)
      .replace(/\{CITY\}/g, geo.city || "").replace(/\{ISP\}/g, geo.isp || "")
      .replace(/\{PROTOCOL\}/g, protoLab).replace(/\{USER\}/g, profile.name || "")
      .replace(/\{PORT\}/g, String(port)).replace(/\{PREFIX\}/g, prefix)
      .replace(/\{IP\}/g, ip || "").replace(/\{HOST\}/g, hostName || "")
      .replace(/\{DATE\}/g, dateStr).replace(/\{INDEX\}/g, String(configIndex))
      .replace(/\{REGION\}/g, regionValue).replace(/\{TAG\}/g, tagsValue)
      .replace(/\{WORKER\}/g, workerName).replace(/\{RELAY\}/g, (regionInfo && regionInfo.flag) || "🌐")
      .replace(/\{PANEL\}/g, sysConfig.name || PANEL_BRAND).replace(/\{VERSION\}/g, CURRENT_VERSION);
    name = name.trim().replace(/\s+/g, " ");
    const maxLen = globalCfg.maxNameLength || MAX_CONFIG_NAME_LEN;
    if (name.length > maxLen) name = name.slice(0, maxLen);
    if (globalCfg.asciiOnly) name = name.replace(/[^\x00-\x7F]/g, "").trim();
    return name || (type === "alpha" ? "V" : "T") + "-" + prefix + "-" + port;
  } catch (e) { return getConfigName(type, profile.name, port, hostName, ip, null, configIndex, "", isDirect, regionInfo); }
}
function getConfigName(type, profileName, port, hostName, ip, proxyIp, configIndex, ipName, isDirect, regionInfo) {
  if (proxyIp === undefined) proxyIp = null;
  if (configIndex === undefined) configIndex = 0;
  if (ipName === undefined) ipName = "";
  if (isDirect === undefined) isDirect = false;
  if (regionInfo === undefined) regionInfo = null;
  const prefix = sysConfig.namePrefix || "Hamed";
  const strategy = sysConfig.nameStrategy || "default";
  const cleanName = profileName === "Default" ? "" : "-" + profileName;
  const typeLab = type === "alpha" ? "V" : "T";
  const regionFlagOnly = regionInfo && regionInfo.flag ? regionInfo.flag + " " : "";
  if (strategy.indexOf("{") !== -1 && strategy.indexOf("}") !== -1) {
    const lookupIp = proxyIp || ip;
    const geo = getGeoInfo(lookupIp);
    const protoLab = type === "alpha" ? "VLESS" : "Trojan";
    const now = new Date();
    const dateStr = now.getFullYear() + "-" + String(now.getMonth() + 1).padStart(2, "0") + "-" + String(now.getDate()).padStart(2, "0");
    const workerName = sysConfig.cfWorkerName || sysConfig.name || hostName || "";
    const flagToUse = isDirect ? "☁" : ((regionInfo && regionInfo.flag) ? regionInfo.flag : geo.flag);
    const countryToUse = regionInfo ? regionInfo.name : geo.country;
    let name = strategy
      .replace(/{FLAG}/g, flagToUse).replace(/{COUNTRY}/g, countryToUse)
      .replace(/{CITY}/g, geo.city).replace(/{ISP}/g, geo.isp)
      .replace(/{PROTOCOL}/g, protoLab).replace(/{USER}/g, profileName)
      .replace(/{PORT}/g, port).replace(/{PREFIX}/g, prefix)
      .replace(/{IP}/g, ip || "").replace(/{IP_NAME}/g, ipName || "")
      .replace(/{HOST}/g, hostName || "").replace(/{DATE}/g, dateStr)
      .replace(/{INDEX}/g, String(configIndex)).replace(/{WORKER}/g, workerName);
    if (name.length > MAX_CONFIG_NAME_LEN) name = name.slice(0, MAX_CONFIG_NAME_LEN);
    return name;
  }
  if (strategy === "type-user-port") return regionFlagOnly + (type === "alpha" ? "vless" : "trojan") + "-" + profileName + "-" + port;
  if (strategy === "user-port") return regionFlagOnly + profileName + "-" + port;
  if (strategy === "prefix-user-port") return regionFlagOnly + prefix + cleanName + "-" + port;
  if (strategy === "ip") return regionFlagOnly + (ip || "unknown");
  return regionFlagOnly + typeLab + "-" + prefix + "-" + port + cleanName;
}
function getExtraInboundEntries(userId) {
  try {
    const cfg = sysConfig.inboundConfigs || {};
    if (cfg.enabled === false) return [];
    const userOverride = cfg.perUser ? cfg.perUser[userId] : null;
    let entries = [];
    if (userOverride && Array.isArray(userOverride.extraEntries) && userOverride.enabled !== false) entries = userOverride.extraEntries;
    else if (Array.isArray(cfg.extraEntries)) entries = cfg.extraEntries;
    return entries.filter(function (e) { return e && e.enabled && e.text; });
  } catch (e) { return []; }
}
function buildStaticInboundURI(entry) {
  const text = (entry.text || "").trim();
  if (!text) return "";
  const prefix = entry.flagPrefix ? entry.flagPrefix + " " : "";
  return "trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#" + encodeURIComponent(prefix + text);
}
function getActiveFragmentValue() {
  const id = sysConfig.activeFragment || "off";
  if (id === "off") return "";
  const presets = sysConfig.fragmentPresets || [];
  const found = presets.find(function (p) { return p.id === id; });
  return found ? found.value : "";
}
function getTransportParams(port) { return CF_HTTP_PORTS.indexOf(port.toString()) !== -1 ? "none" : "tls"; }
function getSubscriptionStats(targetSub) {
  const hasMU = sysConfig.users && sysConfig.users.length > 0;
  let id = activeDeviceId, limitTotalReq = 0;
  if (hasMU && targetSub) {
    const u = sysConfig.users.find(function (x) { return x.name.toLowerCase() === targetSub.toLowerCase() || x.id === targetSub; });
    if (u) { id = u.id; limitTotalReq = u.limitTotalReq || 0; }
  }
  const c = id.replace(/-/g, "").toLowerCase();
  const s = (sysUsageCache && sysUsageCache.users ? sysUsageCache.users[c] : null) || { reqs: 0 };
  const tg = (s.reqs / 6000).toFixed(2);
  const lg = limitTotalReq ? (limitTotalReq / 6000).toFixed(2) : "Unlimited";
  return { usedStr: "Used: " + tg + " GB / " + lg + " GB", expiryStr: "Expiry" };
}
function getFakeConfigNames(targetSub) {
  const stats = getSubscriptionStats(targetSub);
  return (sysConfig.fakeConfigs || []).filter(function (f) { return f && f.enabled && f.name; }).map(function (f) {
    return f.name.replace(/\{usage\}/g, stats.usedStr).replace(/\{expiry\}/g, stats.expiryStr);
  });
}
function parseVlessUri(uri) {
  if (!uri || typeof uri !== "string" || uri.indexOf("vless://") !== 0) return null;
  try {
    let rest = uri.slice(8);
    let fragment = "";
    const hi = rest.indexOf("#");
    if (hi !== -1) { fragment = decodeURIComponent(rest.slice(hi + 1)); rest = rest.slice(0, hi); }
    let qs = "";
    const qi = rest.indexOf("?");
    if (qi !== -1) { qs = rest.slice(qi + 1); rest = rest.slice(0, qi); }
    const params = {};
    if (qs) qs.split("&").forEach(function (pair) {
      const kv = pair.split("=");
      if (kv[0]) params[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1] || "");
    });
    const ai = rest.indexOf("@");
    if (ai === -1) return null;
    const uuid = rest.slice(0, ai);
    const hp = rest.slice(ai + 1);
    let server, port;
    if (hp.charAt(0) === "[") { const be = hp.indexOf("]"); server = hp.slice(1, be); port = parseInt(hp.slice(be + 2)) || 443; }
    else { const ci = hp.lastIndexOf(":"); server = hp.slice(0, ci); port = parseInt(hp.slice(ci + 1)) || 443; }
    return {
      uuid: uuid, server: server, port: port, name: fragment || "Upstream",
      security: params.security || "tls", sni: params.sni || params.servername || server,
      host: params.host || server, path: params.path || "/", type: params.type || "ws",
      fp: params.fp || "random", allowInsecure: params.allowInsecure === "1",
      pbk: params.pbk || "", sid: params.sid || "", flow: params.flow || "",
      encryption: params.encryption || "none", alpn: params.alpn || "", raw: uri
    };
  } catch (e) { return null; }
}
function generateHardwareId(seed) {
  const h = Array.from(new TextEncoder().encode(seed)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("").slice(0, 20).padEnd(20, "0");
  return h.slice(0, 8) + "-0000-4000-8000-" + h.slice(-12);
}
function cmpVersions(a, b) {
  const pa = String(a).replace(/^v/, "").split(".").map(Number);
  const pb = String(b).replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0, nb = pb[i] || 0;
    if (na > nb) return 1;
    if (nb > na) return -1;
  }
  return 0;
}

/* ═══════════ SESSIONS ═══════════ */
async function createSession(env, mgr, request) {
  const token = generateSessionToken();
  const ip = request.headers.get("cf-connecting-ip") || "Unknown";
  const ua = (request.headers.get("user-agent") || "").slice(0, 200);
  const sess = {
    token: token, managerId: mgr.id, username: mgr.username, isRoot: mgr.isRoot === true,
    permissions: mgr.permissions || [], expiresAt: Date.now() + SESSION_TTL_MS,
    ip: ip, ua: ua, createdAt: Date.now()
  };
  await sessPut(env, "session_" + token, JSON.stringify(sess), Math.floor(SESSION_TTL_MS / 1000));
  return sess;
}
async function validateSession(env, token) {
  if (!token || typeof token !== "string" || !token.startsWith("sess_")) return null;
  const raw = await sessGet(env, "session_" + token);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw);
    if (s.expiresAt < Date.now()) { await sessDel(env, "session_" + token); return null; }
    return s;
  } catch (e) { return null; }
}
async function destroySession(env, token) {
  if (token && token.startsWith("sess_")) await sessDel(env, "session_" + token);
}
async function listSessions(env) {
  let sessions = [];
  if (env.SESSIONS_KV) {
    try {
      const list = await env.SESSIONS_KV.list({ prefix: "session_" });
      for (const k of list.keys) {
        const v = await env.SESSIONS_KV.get(k.name);
        if (v) { try { sessions.push(JSON.parse(v)); } catch (e) {} }
      }
    } catch (e) {}
  } else {
    const rows = await d1List(env, "session_");
    for (const r of rows) { try { sessions.push(JSON.parse(r.value)); } catch (e) {} }
  }
  return sessions.filter(function (s) { return s.expiresAt > Date.now(); }).sort(function (a, b) { return b.createdAt - a.createdAt; });
}
async function cleanupExpiredSessions(env) {
  try {
    const now = Date.now();
    if (env.SESSIONS_KV) {
      const list = await env.SESSIONS_KV.list({ prefix: "session_" });
      for (const k of list.keys) {
        const v = await env.SESSIONS_KV.get(k.name);
        if (v) { try { const s = JSON.parse(v); if (s.expiresAt < now) await env.SESSIONS_KV.delete(k.name); } catch (e) {} }
      }
    } else if (env.IOT_DB) {
      const rows = await d1List(env, "session_");
      for (const r of rows) { try { const s = JSON.parse(r.value); if (s.expiresAt < now) await d1Put(env, r.key, ""); } catch (e) {} }
    }
  } catch (e) {}
}

/* ═══════════ AUTH ═══════════ */
async function ensureRootManager() {
  if (!Array.isArray(sysConfig.managers) || sysConfig.managers.length === 0) {
    sysConfig.managers = [{
      id: "root-admin", username: "admin", passwordHash: null, salt: generateSalt(),
      permissions: ["all"], isRoot: true, isActive: true, createdAt: Date.now(), lastLogin: null, createdBy: "system"
    }];
  }
  if (!sysConfig.managers.find(function (m) { return m.isRoot; })) {
    sysConfig.managers.unshift({
      id: "root-admin", username: "admin", passwordHash: null, salt: generateSalt(),
      permissions: ["all"], isRoot: true, isActive: true, createdAt: Date.now(), lastLogin: null, createdBy: "system"
    });
  }
  const root = sysConfig.managers.find(function (m) { return m.isRoot; });
  if (root && (!root.passwordHash || root.salt === "builtin-salt-v1")) {
    root.salt = (root.salt && root.salt !== "builtin-salt-v1") ? root.salt : generateSalt();
    root.passwordHash = await hashPassword(sysConfig.masterKey || "admin", root.salt);
    root.createdAt = root.createdAt || Date.now();
  }
}
async function verifyManagerCredentials(username, password) {
  await ensureRootManager();
  const mgr = sysConfig.managers.find(function (m) {
    return m.username.toLowerCase() === String(username).toLowerCase() && m.isActive !== false;
  });
  if (!mgr) return null;
  if (mgr.passwordHash) {
    const computed = await hashPassword(password, mgr.salt);
    if (computed === mgr.passwordHash) return mgr;
  }
  if (mgr.isRoot) {
    if (password === (sysConfig.masterKey || "admin")) {
      mgr.salt = generateSalt();
      mgr.passwordHash = await hashPassword(password, mgr.salt);
      return mgr;
    }
    if (!mgr.passwordHash && password === "admin") return mgr;
  }
  return null;
}
function hasPermission(ctx, perm) {
  if (!ctx) return false;
  if (ctx.isRoot) return true;
  const perms = ctx.permissions || [];
  if (perms.indexOf("all") !== -1) return true;
  return perms.indexOf(perm) !== -1;
}
async function getAuthContext(request, env, data) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "").trim() || (data && (data.key || data.session)) || "";
  if (!token) return null;
  if (token === sysConfig.masterKey) return { type: "master", isRoot: true, permissions: ["all"], username: "admin" };
  if (isPanelApiKey(token)) return { type: "apikey", isRoot: false, permissions: ALL_PERMISSIONS, username: "apikey", apiKey: token };
  if (token.startsWith("sess_")) {
    const sess = await validateSession(env, token);
    if (!sess) return null;
    return {
      type: "session", isRoot: sess.isRoot, permissions: sess.permissions || [],
      username: sess.username, managerId: sess.managerId, token: sess.token,
      ip: sess.ip, ua: sess.ua, createdAt: sess.createdAt
    };
  }
  return null;
}
async function requirePermission(request, env, data, perm) {
  try {
    const ctx = await getAuthContext(request, env, data);
    if (!ctx) return { ok: false, status: 401, error: "Unauthorized" };
    if (!hasPermission(ctx, perm)) return { ok: false, status: 403, error: "Forbidden", ctx: ctx };
    return { ok: true, ctx: ctx };
  } catch (e) { return { ok: false, status: 500, error: "Internal error" }; }
}

/* ═══════════ BANNED / RATE LIMIT ═══════════ */
async function isIpBanned(env, ip) {
  try {
    const raw = await d1Get(env, "banned_" + ip);
    if (!raw) return false;
    const b = JSON.parse(raw);
    if (b.until && b.until < Date.now()) { await d1Put(env, "banned_" + ip, ""); return false; }
    return true;
  } catch (e) { return false; }
}
async function banIp(env, ip, reason, durationMs) {
  try {
    const b = { ip: ip, reason: reason, bannedAt: Date.now(), until: Date.now() + (durationMs || BAN_DURATION_MS) };
    await d1Put(env, "banned_" + ip, JSON.stringify(b));
    if (!sysConfig.bannedIps) sysConfig.bannedIps = [];
    if (!sysConfig.bannedIps.some(function (x) { return x.ip === ip; })) {
      sysConfig.bannedIps.unshift(b);
      if (sysConfig.bannedIps.length > 200) sysConfig.bannedIps = sysConfig.bannedIps.slice(0, 200);
    }
    return b;
  } catch (e) { return null; }
}
async function unbanIp(env, ip) {
  try {
    await d1Put(env, "banned_" + ip, "");
    sysConfig.bannedIps = (sysConfig.bannedIps || []).filter(function (x) { return x.ip !== ip; });
    return true;
  } catch (e) { return false; }
}
async function listBannedIps(env) {
  const list = [];
  const rows = await d1List(env, "banned_");
  for (const r of rows) {
    try { const b = JSON.parse(r.value); if (b.until > Date.now()) list.push(b); } catch (e) {}
  }
  return list.sort(function (a, b) { return b.bannedAt - a.bannedAt; });
}

/* ═══════════ CAPTCHA ═══════════ */
async function handleCaptcha(request, env) {
  try {
    const a = Math.floor(Math.random() * 8) + 1;
    const b = Math.floor(Math.random() * 8) + 1;
    const ops = ["+", "−", "×"];
    const op = ops[Math.floor(Math.random() * ops.length)];
    let display, answer;
    if (op === "+") { display = a + " + " + b; answer = a + b; }
    else if (op === "−") { const mx = Math.max(a, b), mn = Math.min(a, b); display = mx + " − " + mn; answer = mx - mn; }
    else { display = a + " × " + b; answer = a * b; }
    const id = "cap_" + crypto.randomUUID().slice(0, 16);
    await d1Put(env, "captcha_" + id, JSON.stringify({ id: id, answer: answer, expiresAt: Date.now() + CAPTCHA_TTL_MS }));
    return new Response(JSON.stringify({ ok: true, success: true, data: { id: id, question: display + " = ?" } }), {
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 });
  }
}
async function verifyCaptcha(env, id, answer) {
  if (!id || answer === undefined || answer === null || answer === "") return { ok: false, reason: "missing" };
  const raw = await d1Get(env, "captcha_" + id);
  if (!raw) return { ok: false, reason: "invalid" };
  await d1Put(env, "captcha_" + id, "");
  try {
    const cap = JSON.parse(raw);
    if (cap.expiresAt < Date.now()) return { ok: false, reason: "expired" };
    if (Number(cap.answer) !== Number(answer)) return { ok: false, reason: "wrong" };
    return { ok: true };
  } catch (e) { return { ok: false, reason: "parse" }; }
}

/* ═══════════ HISTORY / USAGE ═══════════ */
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
  const series = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now); d.setDate(d.getDate() - i);
    const key = d.toISOString().split("T")[0];
    const val = ((sysHistoryCache.days && sysHistoryCache.days[key] && sysHistoryCache.days[key][uuid]) || 0) / 6000;
    series.push({ date: key, gb: parseFloat(val.toFixed(3)) });
  }
  return series;
}
function getTotalHistorySeries(days) {
  const series = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now); d.setDate(d.getDate() - i);
    const key = d.toISOString().split("T")[0];
    let total = 0;
    const dayData = (sysHistoryCache.days && sysHistoryCache.days[key]) || {};
    for (const u in dayData) total += dayData[u];
    series.push({ date: key, gb: parseFloat((total / 6000).toFixed(3)) });
  }
  return series;
}
function trackUsage(uuid, bytes, env, ctx) {
  if (!sysUsageCache) sysUsageCache = { users: {} };
  if (!sysUsageCache.users) sysUsageCache.users = {};
  if (!sysUsageCache.users[uuid]) sysUsageCache.users[uuid] = { reqs: 0, dReqs: 0, lastDay: todayStr() };
  let u = sysUsageCache.users[uuid];
  let today = todayStr();
  if (u.lastDay !== today) { u.dReqs = 0; u.lastDay = today; }
  if (u.reqs === undefined) u.reqs = 0;
  if (u.dReqs === undefined) u.dReqs = 0;
  if (bytes === 0) {
    u.reqs += 1; u.dReqs += 1;
    if (sysConfig.historyEnabled) recordHistory(env, uuid, 1).catch(function () {});
  }
  const now = Date.now();
  if (now - lastSysUsageSync > 30000) {
    lastSysUsageSync = now;
    if (env && env.IOT_DB) {
      let changedConfig = false;
      if (sysConfig.users && sysConfig.users.length > 0) {
        sysConfig.users.forEach(function (u2) {
          let uId = u2.id.replace(/-/g, "").toLowerCase();
          let sysU = sysUsageCache.users[uId];
          if (!u2.isPaused) {
            let reason = null;
            if (u2.expiryMs && Date.now() > u2.expiryMs) reason = "Expiration date reached";
            else if (sysU && u2.limitTotalReq && sysU.reqs >= u2.limitTotalReq) reason = "Traffic limit exceeded";
            if (reason) {
              u2.isPaused = true; u2.disabledReason = reason; u2.disabledAt = Date.now();
              changedConfig = true;
            }
          }
        });
      }
      if (changedConfig && ctx && ctx.waitUntil) ctx.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(function () {}));
      pruneHistory();
      if (ctx && ctx.waitUntil) {
        ctx.waitUntil(cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache)).catch(function () {}));
        ctx.waitUntil(cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache)).catch(function () {}));
      }
    }
  }
}

/* ═══════════ WEBHOOKS ═══════════ */
async function triggerWebhook(env, ctx, event, payload) {
  try {
    const hooks = (sysConfig.webhooks || []).filter(function (w) { return w.enabled && (w.events || []).indexOf(event) !== -1; });
    if (hooks.length === 0) return;
    const ts = Date.now();
    for (const wh of hooks) {
      const body = JSON.stringify({ event: event, timestamp: ts, version: CURRENT_VERSION, data: payload });
      const sig = await hmacSign(wh.secret || "", body);
      const p = fetch(wh.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Hamed-Event": event, "X-Hamed-Signature": "sha256=" + sig, "User-Agent": "HamedPanel/" + CURRENT_VERSION },
        body: body, signal: AbortSignal.timeout(8000)
      }).catch(function () {});
      if (ctx && ctx.waitUntil) ctx.waitUntil(p);
    }
  } catch (e) {}
}
const WEBHOOK_EVENTS = ["user.created", "user.updated", "user.deleted", "user.disabled", "panel.updated", "anomaly.detected", "crisis.sent", "auth.success", "auth.failed", "workflow.triggered"];

/* ═══════════ CRON ═══════════ */
const CRON_ACTIONS = {
  "reset-user-usage": { label: "بازنشانی مصرف", params: ["userId"] },
  "extend-user-expiry": { label: "تمدید انقضا", params: ["userId", "days"] },
  "send-telegram": { label: "پیام تلگرام", params: ["message"] },
  "clean-ip-test": { label: "تست IP تمیز", params: [] },
  "node-health-check": { label: "سلامت نودها", params: [] },
  "auto-backup": { label: "بکاپ", params: ["encrypt"] },
  "purge-history": { label: "پاکسازی تاریخچه", params: ["keepDays"] },
  "broadcast": { label: "پیام گروهی", params: ["message"] }
};
async function runCronJob(env, ctx, job) {
  try {
    const params = job.params || {};
    switch (job.action) {
      case "reset-user-usage": {
        const userId = params.userId; if (!userId) break;
        const c = userId.replace(/-/g, "").toLowerCase();
        if (!sysUsageCache.users) sysUsageCache.users = {};
        if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; }
        else sysUsageCache.users[c] = { reqs: 0, dReqs: 0, lastDay: todayStr() };
        await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
        break;
      }
      case "extend-user-expiry": {
        const userId = params.userId, days = params.days;
        const u = (sysConfig.users || []).find(function (x) { return x.id === userId; });
        if (u && days) {
          if (u.expiryMs) u.expiryMs += parseInt(days) * 86400000;
          else u.expiryMs = Date.now() + parseInt(days) * 86400000;
          await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        }
        break;
      }
      case "send-telegram": {
        if (!sysConfig.tgToken) break;
        const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
        if (!adminId) break;
        await fetch("https://api.telegram.org/bot" + sysConfig.tgToken + "/sendMessage", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: adminId, text: params.message || "Cron", parse_mode: "HTML" }),
          signal: AbortSignal.timeout(8000)
        }).catch(function () {});
        break;
      }
      case "clean-ip-test": await runCleanIpTest(env); break;
      case "node-health-check": await runNodeHealthCheck(env); break;
      case "auto-backup": await backupToR2(env, { encrypt: !!params.encrypt }); break;
      case "purge-history": {
        const keep = parseInt(params.keepDays) || 30;
        const days = Object.keys(sysHistoryCache.days || {}).sort();
        while (days.length > keep) delete sysHistoryCache.days[days.shift()];
        await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache));
        break;
      }
      case "broadcast": {
        if (!sysConfig.tgToken) break;
        const msg = params.message || ""; if (!msg) break;
        const recipients = new Set();
        if (sysConfig.tgAdminId) recipients.add(sysConfig.tgAdminId);
        if (sysConfig.tgChatId) recipients.add(sysConfig.tgChatId);
        (sysConfig.users || []).forEach(function (u) { if (u.tgChatId) recipients.add(u.tgChatId); });
        for (const id of recipients) {
          await fetch("https://api.telegram.org/bot" + sysConfig.tgToken + "/sendMessage", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: id, text: msg, parse_mode: "HTML" }),
            signal: AbortSignal.timeout(8000)
          }).catch(function () {});
        }
        break;
      }
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

/* ═══════════ HELPERS ═══════════ */
function getIspTemplate(userIsp) {
  const templates = sysConfig.ispTemplates || {};
  if (userIsp && templates[userIsp]) return templates[userIsp];
  return templates.default || { fragment: "", ports: "", agent: "chrome", extraSni: "" };
}
function applyIspTemplate(user, baseFragment) {
  const t = getIspTemplate(user && user.isp ? user.isp : null);
  if (!t) return { fragment: baseFragment, agent: sysConfig.agent || "chrome", ports: "", extraSni: "" };
  return { fragment: t.fragment || baseFragment, agent: t.agent || sysConfig.agent || "chrome", ports: t.ports || "", extraSni: t.extraSni || "" };
}
async function sendCrisisBroadcast(env, message, presetId) {
  if (!sysConfig.tgToken) return { success: false, ok: false, error: "Telegram not configured" };
  const recipients = new Set();
  if (sysConfig.tgAdminId) recipients.add(sysConfig.tgAdminId);
  if (sysConfig.tgChatId) recipients.add(sysConfig.tgChatId);
  (sysConfig.users || []).forEach(function (u) { if (u.tgChatId) recipients.add(u.tgChatId); });
  let sent = 0, failed = 0;
  for (const id of recipients) {
    try {
      const r = await fetch("https://api.telegram.org/bot" + sysConfig.tgToken + "/sendMessage", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: id, text: message, parse_mode: "HTML" }),
        signal: AbortSignal.timeout(8000)
      });
      const j = await r.json();
      if (j.ok) sent++; else failed++;
    } catch (e) { failed++; }
  }
  if (!sysConfig.crisisHistory) sysConfig.crisisHistory = [];
  sysConfig.crisisHistory.unshift({ ts: Date.now(), message: message, presetId: presetId, sent: sent, failed: failed, total: recipients.size });
  if (sysConfig.crisisHistory.length > 50) sysConfig.crisisHistory = sysConfig.crisisHistory.slice(0, 50);
  await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return { success: true, ok: true, sent: sent, failed: failed, total: recipients.size };
}
async function backupToR2(env, opts) {
  try {
    if (!env.BACKUP_BUCKET) return null;
    opts = opts || {};
    const data = { ts: new Date().toISOString(), version: CURRENT_VERSION, config: sysConfig, usage: sysUsageCache, history: sysHistoryCache };
    let payload = JSON.stringify(data);
    if (opts.encrypt) { const mk = sysConfig.masterKey || "admin"; payload = await encryptField(payload, mk); }
    const key = "backups/" + new Date().toISOString().split("T")[0] + "/config-" + Date.now() + (opts.encrypt ? ".enc" : "") + ".json";
    try { await env.BACKUP_BUCKET.put(key, payload, { httpMetadata: { contentType: "application/json" } }); } catch (e) { return null; }
    try {
      const list = await env.BACKUP_BUCKET.list({ prefix: "backups/", limit: 200 });
      if (list.objects.length > 30) {
        const sorted = list.objects.sort(function (a, b) { return new Date(a.uploaded) - new Date(b.uploaded); });
        for (const obj of sorted.slice(0, sorted.length - 30)) await env.BACKUP_BUCKET.delete(obj.key);
      }
    } catch (e) {}
    return key;
  } catch (e) { return null; }
}
async function listBackups(env) {
  if (!env.BACKUP_BUCKET) return [];
  try {
    const list = await env.BACKUP_BUCKET.list({ prefix: "backups/", limit: 100 });
    return list.objects.map(function (o) { return { key: o.key, size: o.size, uploaded: o.uploaded }; }).sort(function (a, b) { return new Date(b.uploaded) - new Date(a.uploaded); });
  } catch (e) { return []; }
}
async function restoreFromR2(env, key) {
  if (!env.BACKUP_BUCKET) return { ok: false, success: false, error: "R2 not configured" };
  try {
    const obj = await env.BACKUP_BUCKET.get(key);
    if (!obj) return { ok: false, success: false, error: "Not found" };
    let text = await obj.text();
    if (key.endsWith(".enc")) { const mk = sysConfig.masterKey || "admin"; text = await decryptField(text, mk); }
    const data = JSON.parse(text);
    if (!data.config) return { ok: false, success: false, error: "Invalid" };
    sysConfig = Object.assign({}, SYSTEM_DEFAULTS, data.config);
    if (data.usage) sysUsageCache = data.usage;
    if (data.history) sysHistoryCache = data.history;
    const toSave = await encryptSensitiveInConfig(sysConfig, sysConfig.masterKey || "admin");
    await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
    await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache));
    return { ok: true, success: true };
  } catch (e) { return { ok: false, success: false, error: e.message }; }
}
async function detectAnomalies() {
  const today = todayStr();
  const anomalies = [];
  const threshold = sysConfig.anomalyThreshold || 5;
  for (const u of (sysConfig.users || [])) {
    const idClean = u.id.replace(/-/g, "").toLowerCase();
    const todayReqs = (sysHistoryCache.days && sysHistoryCache.days[today] && sysHistoryCache.days[today][idClean]) || 0;
    if (todayReqs < 1000) continue;
    const past7 = [];
    const now = new Date();
    for (let i = 1; i <= 7; i++) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      const key = d.toISOString().split("T")[0];
      const val = (sysHistoryCache.days && sysHistoryCache.days[key] && sysHistoryCache.days[key][idClean]) || 0;
      if (val > 0) past7.push(val);
    }
    if (past7.length < 3) continue;
    const avg = past7.reduce(function (a, b) { return a + b; }, 0) / past7.length;
    if (avg > 0 && todayReqs > avg * threshold) {
      anomalies.push({ userId: u.id, name: u.name, today: todayReqs, avg: Math.round(avg), ratio: (todayReqs / avg).toFixed(1) });
    }
  }
  return anomalies;
}
function migrateSlaveNodesToLinkedPanels(cfg) {
  let modified = false;
  if (cfg && cfg.slaveNodes && cfg.slaveNodes.trim().length > 0) {
    if (!cfg.linkedPanels) cfg.linkedPanels = [];
    const nodes = cfg.slaveNodes.split(/[\r\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    const syncKey = cfg.syncApiKey || "";
    nodes.forEach(function (node) {
      const cn = node.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0].split("@").pop().split(":")[0].toLowerCase();
      const exists = cfg.linkedPanels.some(function (p) {
        return p && p.url && p.url.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0].split("@").pop().split(":")[0].toLowerCase() === cn;
      });
      if (!exists) { cfg.linkedPanels.push({ url: node, apiKey: syncKey }); modified = true; }
    });
    cfg.slaveNodes = "";
    modified = true;
  }
  return modified;
}
async function fetchCloudflareUsage(accountId, apiToken) {
  if (!accountId || !apiToken) return null;
  try {
    const start = new Date().toISOString().split("T")[0] + "T00:00:00Z";
    const query = "query($a:String!,$s:ISO8601DateTime!){viewer{accounts(filter:{accountTag:$a}){workersInvocationsAdaptive(limit:1,filter:{datetime_geq:$s}){sum{requests}}}}}";
    const r = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST", headers: { Authorization: "Bearer " + apiToken, "Content-Type": "application/json" },
      body: JSON.stringify({ query: query, variables: { a: accountId, s: start } }),
      signal: AbortSignal.timeout(8000)
    });
    const j = await r.json();
    const reqs = j && j.data && j.data.viewer && j.data.viewer.accounts && j.data.viewer.accounts[0] && j.data.viewer.accounts[0].workersInvocationsAdaptive && j.data.viewer.accounts[0].workersInvocationsAdaptive[0] && j.data.viewer.accounts[0].workersInvocationsAdaptive[0].sum && j.data.viewer.accounts[0].workersInvocationsAdaptive[0].sum.requests;
    return typeof reqs === "number" ? reqs : null;
  } catch (e) { return null; }
}
async function logActivity(env, type, detail) {
  if (!env || !env.IOT_DB) return;
  try {
    const ts = new Date().toISOString();
    let logs = [];
    const stored = await d1Get(env, "sys_logs");
    if (stored) logs = JSON.parse(stored);
    logs.unshift({ ts: ts, type: type, detail: detail });
    if (logs.length > 300) logs = logs.slice(0, 300);
    await d1Put(env, "sys_logs", JSON.stringify(logs));
  } catch (e) {}
}
async function deployWorkerToCloudflare(accountId, apiToken, workerName, code) {
  let cb = [];
  try {
    const r = await fetch("https://api.cloudflare.com/client/v4/accounts/" + accountId + "/workers/scripts/" + encodeURIComponent(workerName) + "/settings", {
      headers: { Authorization: "Bearer " + apiToken }, signal: AbortSignal.timeout(15000)
    });
    const j = await r.json();
    if (j.success && j.result && j.result.bindings) cb = j.result.bindings;
  } catch (e) {}
  const meta = { main_module: "_worker.js", compatibility_date: "2024-03-01", compatibility_flags: ["allow_eval_during_startup"], bindings: cb };
  const form = new FormData();
  form.append("metadata", new Blob([JSON.stringify(meta)], { type: "application/json" }));
  form.append("_worker.js", new Blob([code], { type: "application/javascript+module" }), "_worker.js");
  return await fetch("https://api.cloudflare.com/client/v4/accounts/" + accountId + "/workers/scripts/" + encodeURIComponent(workerName), {
    method: "PUT", headers: { Authorization: "Bearer " + apiToken }, body: form
  });
}

/* ═══════════ CONFIG LOADER ═══════════ */
let sysConfigLoading = null, sysUsageLoading = null, backupIpLoading = null, sysHistoryLoading = null;
async function loadSysConfig(env, ctx) {
  const now = Date.now();
  if (env.IOT_DB) {
    if (now - sysConfigCacheTime > CACHE_TTL_CONFIG) {
      if (!sysConfigLoading) {
        sysConfigLoading = d1Get(env, "sys_config")
          .then(async function (stored) {
            let loaded = Object.assign({}, SYSTEM_DEFAULTS, stored ? JSON.parse(stored) : null);
            if (!loaded.inboundConfigs) loaded.inboundConfigs = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs));
            if (!loaded.inboundConfigs.global) loaded.inboundConfigs.global = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs.global));
            if (!loaded.inboundConfigs.global.prefix) loaded.inboundConfigs.global.prefix = "Hamed";
            if (!loaded.inboundConfigs.customInbounds) loaded.inboundConfigs.customInbounds = [];
            if (!loaded.relayIpPresets || !Array.isArray(loaded.relayIpPresets) || loaded.relayIpPresets.length === 0) loaded.relayIpPresets = RELAY_IP_PRESETS;
            if (!loaded.advanced) loaded.advanced = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.advanced));
            if (loaded.ispTemplates) {
              for (const k of Object.keys(loaded.ispTemplates)) {
                if (loaded.ispTemplates[k] && loaded.ispTemplates[k].ports === "443") loaded.ispTemplates[k].ports = "";
              }
            }
            if (Array.isArray(loaded.socketPorts)) loaded.socketPorts = loaded.socketPorts.join(",");
            if (!loaded.socketPorts || !String(loaded.socketPorts).trim()) loaded.socketPorts = CF_HTTPS_PORTS.join(",");
            const dec = await decryptSensitiveInConfig(loaded, loaded.masterKey || "admin");
            sysConfig = Object.assign({}, loaded, dec);
            sysConfigCacheTime = Date.now();
            try { await ensureRootManager(); } catch (e) {}
            if (migrateSlaveNodesToLinkedPanels(sysConfig)) {
              const p = cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
              if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p.catch(function () {}));
              else p.catch(function () {});
            }
          })
          .catch(function () { sysConfig = Object.assign({}, SYSTEM_DEFAULTS); sysConfigCacheTime = Date.now(); })
          .finally(function () { sysConfigLoading = null; });
      }
      await sysConfigLoading;
    }
    if (now - sysUsageCacheTime > CACHE_TTL_USAGE) {
      if (!sysUsageLoading) {
        sysUsageLoading = d1Get(env, "sys_usage")
          .then(function (u) { if (u) sysUsageCache = JSON.parse(u); else sysUsageCache = { users: {} }; sysUsageCacheTime = Date.now(); })
          .catch(function () { sysUsageCache = { users: {} }; sysUsageCacheTime = Date.now(); })
          .finally(function () { sysUsageLoading = null; });
      }
      await sysUsageLoading;
    }
    if (sysConfig.historyEnabled && now - sysHistoryCacheTime > CACHE_TTL_HISTORY) {
      if (!sysHistoryLoading) {
        sysHistoryLoading = d1Get(env, "sys_history")
          .then(function (h) { if (h) sysHistoryCache = JSON.parse(h); else sysHistoryCache = { days: {} }; sysHistoryCacheTime = Date.now(); })
          .catch(function () { sysHistoryCache = { days: {} }; sysHistoryCacheTime = Date.now(); })
          .finally(function () { sysHistoryLoading = null; });
      }
      await sysHistoryLoading;
    }
  }
  if (now - backupIpCacheTime > CACHE_TTL_BACKUP_IP) {
    if (!backupIpLoading) {
      backupIpLoading = (env.IOT_DB ? d1Get(env, "backup_ip") : Promise.resolve(null))
        .then(function (v) { backupIpCache = v; backupIpCacheTime = Date.now(); })
        .catch(function () { backupIpCacheTime = Date.now(); })
        .finally(function () { backupIpLoading = null; });
    }
    await backupIpLoading;
  }
  sysConfig.customRelay = backupIpCache !== null && backupIpCache !== undefined ? backupIpCache : (env.RELAY_IP || "");
}
/* ==================== INBOUND API ==================== */
async function handleInboundsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "inbounds");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status, headers: { "Content-Type": "application/json" } });
    if (method === "GET") {
      const cfg = sysConfig.inboundConfigs || SYSTEM_DEFAULTS.inboundConfigs;
      return new Response(JSON.stringify({
        ok: true, success: true,
        data: { config: cfg, users: (sysConfig.users || []).map(function (u) { return { id: u.id, name: u.name, groupId: u.groupId, isp: u.isp || null, tags: u.tags || [] }; }) }
      }), { headers: { "Content-Type": "application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (!sysConfig.inboundConfigs) sysConfig.inboundConfigs = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs));
      if (!sysConfig.inboundConfigs.customInbounds) sysConfig.inboundConfigs.customInbounds = [];

      if (body.action === "updateGlobal") {
        sysConfig.inboundConfigs.global = Object.assign({}, sysConfig.inboundConfigs.global, body.global || {});
        if (body.extraEntries) sysConfig.inboundConfigs.extraEntries = body.extraEntries;
        if (body.enabled !== undefined) sysConfig.inboundConfigs.enabled = !!body.enabled;
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.inboundConfigs }), { headers: { "Content-Type": "application/json" } });
      }
      if (body.action === "updateUser") {
        if (!body.userId) return new Response(JSON.stringify({ ok: false, success: false, error: "userId required" }), { status: 400 });
        if (!sysConfig.inboundConfigs.perUser) sysConfig.inboundConfigs.perUser = {};
        sysConfig.inboundConfigs.perUser[body.userId] = {
          enabled: body.enabled !== false,
          nameTemplate: body.nameTemplate || "",
          extraEntries: Array.isArray(body.extraEntries) ? body.extraEntries : []
        };
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "removeUser") {
        if (body.userId && sysConfig.inboundConfigs.perUser && sysConfig.inboundConfigs.perUser[body.userId]) {
          delete sysConfig.inboundConfigs.perUser[body.userId];
          await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        }
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "addEntry") {
        if (!sysConfig.inboundConfigs.extraEntries) sysConfig.inboundConfigs.extraEntries = [];
        const e = { id: generateId("e"), text: body.text || "", type: body.type || "static", enabled: body.enabled !== false, position: body.position || "start", flagPrefix: body.flagPrefix || "" };
        sysConfig.inboundConfigs.extraEntries.push(e);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: e }), { headers: { "Content-Type": "application/json" } });
      }
      if (body.action === "removeEntry") {
        sysConfig.inboundConfigs.extraEntries = (sysConfig.inboundConfigs.extraEntries || []).filter(function (e) { return e.id !== body.id; });
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "updateEntry") {
        const list = sysConfig.inboundConfigs.extraEntries || [];
        const idx = list.findIndex(function (e) { return e.id === body.id; });
        if (idx === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
        list[idx] = Object.assign({}, list[idx], body.data);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      /* ⚡ NEW: Custom Inbound Cards */
      if (body.action === "addCustom") {
        const c = {
          id: generateId("ci"),
          name: body.name || "کارت جدید",
          enabled: body.enabled !== false,
          position: body.position || "start",
          flagPrefix: body.flagPrefix || "🚀",
          content: body.content || "",
          type: body.type || "static",
          color: body.color || "#007AFF",
          createdAt: Date.now()
        };
        sysConfig.inboundConfigs.customInbounds.push(c);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: c }), { headers: { "Content-Type": "application/json" } });
      }
      if (body.action === "removeCustom") {
        sysConfig.inboundConfigs.customInbounds = (sysConfig.inboundConfigs.customInbounds || []).filter(function (x) { return x.id !== body.id; });
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "updateCustom") {
        const list = sysConfig.inboundConfigs.customInbounds || [];
        const idx = list.findIndex(function (x) { return x.id === body.id; });
        if (idx === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
        list[idx] = Object.assign({}, list[idx], body.data || {});
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: list[idx] }));
      }
      if (body.action === "toggleCustom") {
        const c = (sysConfig.inboundConfigs.customInbounds || []).find(function (x) { return x.id === body.id; });
        if (c) { c.enabled = !c.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); }
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "reorderCustom") {
        const list = sysConfig.inboundConfigs.customInbounds || [];
        const fromIdx = list.findIndex(function (x) { return x.id === body.id; });
        if (fromIdx === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
        const item = list.splice(fromIdx, 1)[0];
        const toIdx = Math.max(0, Math.min(list.length, parseInt(body.toIndex) || 0));
        list.splice(toIdx, 0, item);
        sysConfig.inboundConfigs.customInbounds = list;
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleInboundsActions(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "inbounds");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    const body = await request.json();
    if (body.action === "applyGlobal") {
      const cfg = sysConfig.inboundConfigs || {};
      const global = cfg.global || {};
      if (!cfg.perUser) cfg.perUser = {};
      const extraEntries = (cfg.extraEntries || []).map(function (e) { return Object.assign({}, e); });
      let applied = 0;
      for (const u of (sysConfig.users || [])) {
        cfg.perUser[u.id] = { enabled: true, nameTemplate: global.nameTemplate || "{FLAG} {PREFIX}-{INDEX}", extraEntries: extraEntries };
        applied++;
      }
      sysConfig.inboundConfigs = cfg;
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok: true, success: true, applied: applied }), { headers: { "Content-Type": "application/json" } });
    }
    if (body.action === "clearUserOverrides") {
      sysConfig.inboundConfigs.perUser = {};
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok: true, success: true }), { headers: { "Content-Type": "application/json" } });
    }
    if (body.action === "preview") {
      const profile = { id: "preview", name: body.userName || "ali", tags: body.tags || ["VIP"] };
      const regionInfo = { id: "de", name: "آلمان", flag: "🇩🇪" };
      const name = buildInboundName(body.type || "alpha", profile, "188.114.96.1", 443, 1, "panel.workers.dev", regionInfo, false);
      return new Response(JSON.stringify({ ok: true, success: true, name: name }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}

/* ==================== ADVANCED API ==================== */
async function handleAdvancedApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    if (!sysConfig.advanced) sysConfig.advanced = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.advanced));
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.advanced, defaults: SYSTEM_DEFAULTS.advanced }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "reset") {
        sysConfig.advanced = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.advanced));
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.advanced }), { headers: { "Content-Type": "application/json" } });
      }
      const allowed = Object.keys(SYSTEM_DEFAULTS.advanced);
      const next = Object.assign({}, sysConfig.advanced);
      for (const k of allowed) {
        if (body[k] === undefined) continue;
        if (k === "muxConcurrency" || k === "keepAlive") {
          const n = parseInt(body[k]);
          if (!isNaN(n) && n >= 0 && n <= 1000) next[k] = n;
        } else if (typeof SYSTEM_DEFAULTS.advanced[k] === "boolean") next[k] = !!body[k];
        else next[k] = String(body[k] || "");
      }
      sysConfig.advanced = next;
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.advanced }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}

/* ==================== RELAY HEALTH API ==================== */
async function handleRelayHealth(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const list = [];
    relayHealthCache.forEach(function (v, k) {
      const total = v.ok + v.fail;
      const rate = total > 0 ? ((v.ok / total) * 100).toFixed(1) : "0";
      list.push({ host: k, ok: v.ok, fail: v.fail, rate: rate + "%", avgLatency: v.avgLatency || 0, lastCheck: v.lastCheck || 0 });
    });
    list.sort(function (a, b) { return parseFloat(b.rate) - parseFloat(a.rate); });
    return new Response(JSON.stringify({ ok: true, success: true, relays: list }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleRelayTest(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const results = [];
    const hosts = RELAY_PROXY_DOMAINS.slice(0, 8);
    for (const host of hosts) {
      const t0 = Date.now();
      try {
        const socket = connect({ hostname: host, port: 443 });
        await socket.opened;
        const latency = Date.now() - t0;
        try { socket.close(); } catch (e) {}
        results.push({ host: host, status: "online", latency: latency });
        recordRelayAttempt(host, true, latency);
      } catch (e) {
        results.push({ host: host, status: "offline", latency: -1, error: e.message });
        recordRelayAttempt(host, false, 0);
      }
    }
    results.sort(function (a, b) {
      if (a.status === "online" && b.status !== "online") return -1;
      if (a.status !== "online" && b.status === "online") return 1;
      return (a.latency || 9999) - (b.latency || 9999);
    });
    return new Response(JSON.stringify({ ok: true, success: true, results: results }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}

/* ==================== AUTH ==================== */
async function handleAuth(request, hostName, ctx, env) {
  try {
    const ip = request.headers.get("cf-connecting-ip") || "Unknown";
    let data = {};
    try { data = await request.json(); } catch (e) {
      return new Response(JSON.stringify({ ok: false, success: false, error: "Invalid JSON" }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    const rlKey = "rl_auth_" + ip;
    let rlData = { count: 0, first: Date.now() };
    try {
      const rlRaw = await d1Get(env, rlKey);
      const now = Date.now();
      if (rlRaw) rlData = JSON.parse(rlRaw);
      if (!rlData.first || now - rlData.first > AUTH_WINDOW_MS) rlData = { count: 0, first: now };
      if (rlData.count >= AUTH_MAX_ATTEMPTS * 3) return new Response(JSON.stringify({ ok: false, success: false, error: "Too many attempts" }), { status: 429, headers: { "Content-Type": "application/json" } });
    } catch (e) {}

    const username = data.username || "";
    const password = data.password || "";
    const legacyKey = data.key || "";
    let mgr = null;

    if (legacyKey) {
      if (legacyKey === sysConfig.masterKey) mgr = { username: "admin", isRoot: true, permissions: ["all"], id: "root-admin" };
      else if (isPanelApiKey(legacyKey)) mgr = { username: "apikey", isRoot: false, permissions: ALL_PERMISSIONS, id: "apikey" };
      else return new Response(JSON.stringify({ ok: false, success: false, error: "Invalid key" }), { status: 401, headers: { "Content-Type": "application/json" } });
    } else {
      if (sysConfig.captchaEnabled !== false) {
        const capCheck = await verifyCaptcha(env, data.captchaId, data.captchaAnswer);
        if (!capCheck.ok) {
          const msg = capCheck.reason === "wrong" ? "پاسخ کپچا اشتباه است"
                    : capCheck.reason === "expired" ? "کپچا منقضی شده — دوباره تلاش کنید"
                    : capCheck.reason === "missing" ? "کپچا را پر کنید"
                    : "کپچا نامعتبر است";
          return new Response(JSON.stringify({ ok: false, success: false, error: msg, needCaptcha: true }), { status: 400, headers: { "Content-Type": "application/json" } });
        }
      }
      if (!username || !password) return new Response(JSON.stringify({ ok: false, success: false, error: "نام کاربری و رمز عبور الزامی است" }), { status: 400, headers: { "Content-Type": "application/json" } });
      try { mgr = await verifyManagerCredentials(username, password); } catch (e) { mgr = null; }
      if (!mgr) {
        try { rlData.count++; await d1Put(env, rlKey, JSON.stringify(rlData)); } catch (e) {}
        if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "auth.failed", { username: username, ip: ip }).catch(function () {}));
        return new Response(JSON.stringify({ ok: false, success: false, error: "نام کاربری یا رمز عبور اشتباه است" }), { status: 401, headers: { "Content-Type": "application/json" } });
      }
    }

    if (mgr && mgr.id === "root-admin") {
      try {
        const f = sysConfig.managers.find(function (m) { return m.id === "root-admin"; });
        if (f) { f.lastLogin = Date.now(); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); }
      } catch (e) {}
    } else if (mgr && mgr.id) {
      try {
        const f = sysConfig.managers.find(function (m) { return m.id === mgr.id; });
        if (f) { f.lastLogin = Date.now(); cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(function () {}); }
      } catch (e) {}
    }

    const sess = await createSession(env, mgr, request);
    try { await d1Put(env, rlKey, ""); } catch (e) {}
    if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "auth.success", { username: mgr.username, ip: ip }).catch(function () {}));

    let exposed = Object.assign({}, sysConfig);
    if (!sess.isRoot) exposed = Object.assign({}, sysConfig, { cfApiToken: "", tgToken: "", syncApiKey: "", masterKey: "[PROTECTED]" });
    for (const f of SENSITIVE_FIELDS) {
      if (exposed[f] && String(exposed[f]).startsWith("enc:")) exposed[f] = "";
    }
    exposed.managers = undefined;
    exposed.panelApiKeys = sess.isRoot ? (sysConfig.panelApiKeys || []) : [];

    return new Response(JSON.stringify({
      ok: true, success: true,
      data: {
        session: { token: sess.token, username: sess.username, isRoot: sess.isRoot, permissions: sess.permissions, expiresAt: sess.expiresAt },
        config: exposed, version: CURRENT_VERSION, apiRoute: sysConfig.apiRoute,
        network: { ip: ip }
      }
    }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, success: false, error: "Server error: " + e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}
async function handleLogout(request, env) {
  try {
    const auth = request.headers.get("Authorization") || "";
    const token = auth.replace("Bearer ", "").trim();
    if (token) await destroySession(env, token);
    return new Response(JSON.stringify({ ok: true, success: true }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); }
}
async function handleMe(request, env) {
  try {
    const ctx = await getAuthContext(request, env, null);
    if (!ctx) return new Response(JSON.stringify({ ok: false, success: false, error: "Unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
    let exposed = Object.assign({}, sysConfig);
    if (!ctx.isRoot) exposed = Object.assign({}, sysConfig, { cfApiToken: "", tgToken: "", syncApiKey: "", masterKey: "[PROTECTED]" });
    for (const f of SENSITIVE_FIELDS) if (exposed[f] && String(exposed[f]).startsWith("enc:")) exposed[f] = "";
    exposed.managers = undefined;
    exposed.panelApiKeys = ctx.isRoot ? (sysConfig.panelApiKeys || []) : [];
    return new Response(JSON.stringify({
      ok: true, success: true,
      data: { username: ctx.username, isRoot: ctx.isRoot, permissions: ctx.permissions, type: ctx.type, config: exposed, version: CURRENT_VERSION }
    }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); }
}
async function handleConfigSync(request, env, ctx) {
  try {
    const data = await request.json();
    const authCtx = await getAuthContext(request, env, data);
    const isAuthSync = (authCtx && (authCtx.isRoot || hasPermission(authCtx, "settings"))) || (data.key === sysConfig.masterKey) || isPanelApiKey(data.key) || (data.fromMaster && data.config && data.config.masterKey && data.config.masterKey === sysConfig.masterKey);
    if (!isAuthSync) return new Response(JSON.stringify({ ok: false, success: false, error: "Unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
    if (!env.IOT_DB) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });

    let nextConfig = sysConfig;
    if (data.config) {
      const preserveApiKeys = sysConfig.panelApiKeys || [];
      const preserveManagers = sysConfig.managers || [];
      const prevMasterKey = sysConfig.masterKey || "admin";
      nextConfig = Object.assign({}, sysConfig, data.config);

      if (Array.isArray(nextConfig.socketPorts)) nextConfig.socketPorts = nextConfig.socketPorts.join(",");
      if (nextConfig.socketPorts && typeof nextConfig.socketPorts === "string") nextConfig.socketPorts = parsePorts(nextConfig.socketPorts, CF_HTTPS_PORTS).join(",");
      if (Array.isArray(nextConfig.users)) nextConfig.users = nextConfig.users.map(function (u) { return Object.assign({}, u); });
      if (preserveApiKeys.length > 0 && (!data.config.panelApiKeys || data.config.panelApiKeys.length === 0)) nextConfig.panelApiKeys = preserveApiKeys;
      if (!data.config.managers) nextConfig.managers = preserveManagers;
      if (!nextConfig.advanced) nextConfig.advanced = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.advanced));
      if (!nextConfig.inboundConfigs) nextConfig.inboundConfigs = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.inboundConfigs));
      if (!nextConfig.inboundConfigs.customInbounds) nextConfig.inboundConfigs.customInbounds = [];

      migrateSlaveNodesToLinkedPanels(nextConfig);

      if (Array.isArray(nextConfig.users)) {
        for (const u of nextConfig.users) {
          if (u.proxyIp || u.relayIps || u.relayPresetId) await resolveUserProxyIpGeo(u);
          else u.proxyIpGeo = null;
        }
      }

      const newMasterKey = nextConfig.masterKey || "admin";
      if (newMasterKey !== prevMasterKey) {
        const root = (nextConfig.managers || []).find(function (m) { return m.isRoot; });
        if (root) { root.salt = generateSalt(); root.passwordHash = await hashPassword(newMasterKey, root.salt); }
        _encKeyCache = null; _encKeyCacheSrc = null;
      }

      const toSave = await encryptSensitiveInConfig(nextConfig, newMasterKey);
      sysConfig = nextConfig;
      await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    }

    if (nextConfig.tgToken && ctx) {
      const hook = "https://" + new URL(request.url).hostname + "/" + encodeURI(nextConfig.apiRoute) + "/tg";
      ctx.waitUntil(fetch("https://api.telegram.org/bot" + nextConfig.tgToken + "/setWebhook", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: hook }), signal: AbortSignal.timeout(8000)
      }).catch(function () {}));
    }
    return new Response(JSON.stringify({ ok: true, success: true, newRoute: nextConfig.apiRoute }), { status: 200 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 400 }); }
}
async function handleSyncPanel(request, env, ctx) {
  try {
    const data = await request.json();
    if (!data || data.signal !== "panel_login") return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
    const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
    if (!adminId || adminId.toString() !== String(data.tgAdminId)) return new Response(JSON.stringify({ ok: false, success: false }), { status: 401 });
    if (env.IOT_DB) {
      const p = d1Put(env, "tg_panel_login", JSON.stringify({ name: data.panelName || data.panelHost, host: data.panelHost, apiRoute: data.panelApiRoute || sysConfig.apiRoute, isLocal: false, ts: Date.now() })).catch(function () {});
      if (ctx && ctx.waitUntil) ctx.waitUntil(p);
    }
    return new Response(JSON.stringify({ ok: true, success: true }));
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); }
}

/* ==================== LOGS ==================== */
async function handleLogs(request, env) {
  try {
    if (request.method === "POST" || request.method === "GET") {
      const data = request.method === "POST" ? await request.json().catch(function () { return {}; }) : {};
      const perm = await requirePermission(request, env, data, "logs");
      if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status, headers: { "Content-Type": "application/json" } });
      let logs = [];
      if (env.IOT_DB) { const s = await d1Get(env, "sys_logs"); if (s) logs = JSON.parse(s); }
      return new Response(JSON.stringify({ ok: true, success: true, logs: logs }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response("OK", { status: 200 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); }
}

/* ==================== USERS ==================== */
async function handleUsersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const userId = url.searchParams.get("id");
    const action = url.searchParams.get("action");
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status, headers: { "Content-Type": "application/json" } });

    if (method === "GET" && !userId) {
      const q = (url.searchParams.get("q") || "").toLowerCase();
      const groupFilter = url.searchParams.get("group");
      const ispFilter = url.searchParams.get("isp");
      let users = sysConfig.users || [];
      if (q) users = users.filter(function (u) { return u.name.toLowerCase().indexOf(q) !== -1 || u.id.toLowerCase().indexOf(q) !== -1 || (u.notes && u.notes.toLowerCase().indexOf(q) !== -1); });
      if (groupFilter) users = users.filter(function (u) { return (u.groupId || "default") === groupFilter; });
      if (ispFilter) users = users.filter(function (u) { return (u.isp || "") === ispFilter; });
      const enriched = users.map(function (u) {
        const idClean = u.id.replace(/-/g, "").toLowerCase();
        const sysU = (sysUsageCache && sysUsageCache.users && sysUsageCache.users[idClean]) || { reqs: 0, dReqs: 0, lastDay: "" };
        const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
        const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
        const isExpired = u.expiryMs && Date.now() > u.expiryMs;
        let status = "active";
        if (u.isPaused && u.disabledReason) status = "auto-disabled";
        else if (u.isPaused) status = "paused";
        else if (isExpired) status = "expired";
        return Object.assign({}, u, { usage: { total: usedBytes, limit: limitBytes, daily: sysU.dReqs || 0, dailyLimit: u.limitDailyReq || 0 }, status: status });
      });
      return new Response(JSON.stringify({ ok: true, success: true, data: enriched, users: enriched, meta: { total: enriched.length } }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "GET" && userId) {
      const u = (sysConfig.users || []).find(function (usr) { return usr.id === userId || usr.name.toLowerCase() === userId.toLowerCase(); });
      if (!u) return new Response(JSON.stringify({ ok: false, success: false, error: "Not found" }), { status: 404 });
      const idClean = u.id.replace(/-/g, "").toLowerCase();
      const sysU = (sysUsageCache && sysUsageCache.users && sysUsageCache.users[idClean]) || { reqs: 0, dReqs: 0, lastDay: "" };
      const usedBytes = Math.floor((sysU.reqs || 0) * (1073741824 / 6000));
      const limitBytes = u.limitTotalReq ? Math.floor(u.limitTotalReq * (1073741824 / 6000)) : 0;
      const isExpired = u.expiryMs && Date.now() > u.expiryMs;
      let status = "active";
      if (u.isPaused && u.disabledReason) status = "auto-disabled";
      else if (u.isPaused) status = "paused";
      else if (isExpired) status = "expired";
      const host = new URL(request.url).hostname;
      const subUrl = "https://" + host + "/" + sysConfig.apiRoute + "?sub=" + encodeURIComponent(u.name);
      return new Response(JSON.stringify({ ok: true, success: true, data: Object.assign({}, u, {
        usage: { total: usedBytes, limit: limitBytes, daily: sysU.dReqs || 0, dailyLimit: u.limitDailyReq || 0 },
        status: status, subscriptionUrl: subUrl
      }) }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "POST" && !userId) {
      const body = await request.json();
      const name = body.name, trafficLimit = body.trafficLimit, expiryDays = body.expiryDays;
      const notes = body.notes, maxConfigs = body.maxConfigs, proxyIp = body.proxyIp, cleanIp = body.cleanIp;
      const userMode = body.userMode, userPorts = body.userPorts, userNodes = body.userNodes, nat64 = body.nat64;
      const connLimit = body.connLimit, userPanelUrl = body.userPanelUrl, groupId = body.groupId;
      const autoReset = body.autoReset, isp = body.isp, bandwidthKbps = body.bandwidthKbps;
      const tags = body.tags, relayIps = body.relayIps, relayMode = body.relayMode, relayPresetId = body.relayPresetId;

      if (!name) return new Response(JSON.stringify({ ok: false, success: false, error: "Name required" }), { status: 400 });
      if ((sysConfig.users || []).some(function (u) { return u.name.toLowerCase() === String(name).toLowerCase(); })) {
        return new Response(JSON.stringify({ ok: false, success: false, error: "نام کاربری موجود است" }), { status: 409 });
      }
      const newId = generateId("u");
      const grp = (sysConfig.userGroups || []).find(function (g) { return g.id === (groupId || "default"); }) || {};
      const newUser = {
        id: newId, name: name, groupId: groupId || "default", isp: isp || null,
        tags: Array.isArray(tags) ? tags : [],
        bandwidthKbps: bandwidthKbps ? parseInt(bandwidthKbps) : null,
        limitTotalReq: trafficLimit ? Math.floor(parseFloat(trafficLimit) * 6000) : (grp.limitTotalGb ? Math.floor(grp.limitTotalGb * 6000) : null),
        limitDailyReq: body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit) * 6000) : (grp.limitDailyGb ? Math.floor(grp.limitDailyGb * 6000) : null),
        expiryMs: expiryDays ? Date.now() + parseInt(expiryDays) * 86400000 : (grp.expiryDays ? Date.now() + grp.expiryDays * 86400000 : null),
        notes: notes || "",
        maxConfigs: maxConfigs ? parseInt(maxConfigs) : (grp.maxConfigs || null),
        connLimit: connLimit ? parseInt(connLimit) : (grp.connLimit || null),
        proxyIp: proxyIp || null, cleanIp: cleanIp || null, userMode: userMode || null,
        userPorts: userPorts || null, userNodes: userNodes || null, nat64: nat64 || null,
        userPanelUrl: userPanelUrl || null,
        relayIps: typeof relayIps === "string" ? relayIps : (Array.isArray(relayIps) ? relayIps.join("\n") : ""),
        relayMode: relayMode || "single",
        relayPresetId: relayPresetId || "",
        createdAt: Date.now()
      };
      await resolveUserProxyIpGeo(newUser);
      if (!sysConfig.users) sysConfig.users = [];
      sysConfig.users.push(newUser);
      if (autoReset && autoReset.type && autoReset.type !== "none") {
        if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
        sysConfig.autoResetCycles[newId] = { type: autoReset.type, lastReset: Date.now() };
      }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      if (ctx && ctx.waitUntil) {
        ctx.waitUntil(logActivity(env, "User Created", name).catch(function () {}));
        ctx.waitUntil(triggerWebhook(env, ctx, "user.created", { userId: newId, name: name }).catch(function () {}));
        ctx.waitUntil(fireWorkflows(env, ctx, "user.created", { userId: newId, name: name, groupId: newUser.groupId }).catch(function () {}));
      }
      return new Response(JSON.stringify({ ok: true, success: true, data: newUser, user: newUser }), { status: 201, headers: { "Content-Type": "application/json" } });
    }

    if (method === "PUT" && userId) {
      const body = await request.json();
      const u = (sysConfig.users || []).find(function (x) { return x.id === userId; });
      if (!u) return new Response(JSON.stringify({ ok: false, success: false, error: "Not found" }), { status: 404 });
      if (body.name !== undefined) u.name = body.name;
      if (body.groupId !== undefined) u.groupId = body.groupId;
      if (body.isp !== undefined) u.isp = body.isp || null;
      if (body.tags !== undefined) u.tags = Array.isArray(body.tags) ? body.tags : [];
      if (body.bandwidthKbps !== undefined) u.bandwidthKbps = body.bandwidthKbps ? parseInt(body.bandwidthKbps) : null;
      if (body.trafficLimit !== undefined) u.limitTotalReq = body.trafficLimit ? Math.floor(parseFloat(body.trafficLimit) * 6000) : null;
      if (body.dailyLimit !== undefined) u.limitDailyReq = body.dailyLimit ? Math.floor(parseFloat(body.dailyLimit) * 6000) : null;
      if (body.expiryDays !== undefined) u.expiryMs = body.expiryDays ? Date.now() + parseInt(body.expiryDays) * 86400000 : null;
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
      if (body.relayIps !== undefined) u.relayIps = typeof body.relayIps === "string" ? body.relayIps : (Array.isArray(body.relayIps) ? body.relayIps.join("\n") : "");
      if (body.relayMode !== undefined) u.relayMode = body.relayMode || "single";
      if (body.relayPresetId !== undefined) u.relayPresetId = body.relayPresetId || "";
      if (body.status !== undefined) {
        if (body.status === "active") { u.isPaused = false; u.disabledReason = null; u.disabledAt = null; }
        else if (body.status === "paused") { u.isPaused = true; u.disabledReason = null; u.disabledAt = null; }
      }
      if (body.autoReset !== undefined) {
        if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
        if (body.autoReset.type && body.autoReset.type !== "none") sysConfig.autoResetCycles[userId] = { type: body.autoReset.type, lastReset: Date.now() };
        else delete sysConfig.autoResetCycles[userId];
      }
      if (body.relayIps !== undefined || body.relayPresetId !== undefined) await resolveUserProxyIpGeo(u);
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "user.updated", { userId: userId, name: u.name }).catch(function () {}));
      return new Response(JSON.stringify({ ok: true, success: true, data: u, user: u }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "DELETE" && userId) {
      const idx = (sysConfig.users || []).findIndex(function (x) { return x.id === userId; });
      if (idx === -1) return new Response(JSON.stringify({ ok: false, success: false, error: "Not found" }), { status: 404 });
      const deleted = sysConfig.users.splice(idx, 1)[0];
      if (sysConfig.autoResetCycles && sysConfig.autoResetCycles[userId]) delete sysConfig.autoResetCycles[userId];
      if (sysConfig.inboundConfigs && sysConfig.inboundConfigs.perUser && sysConfig.inboundConfigs.perUser[userId]) delete sysConfig.inboundConfigs.perUser[userId];
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "user.deleted", { userId: userId, name: deleted.name }).catch(function () {}));
      return new Response(JSON.stringify({ ok: true, success: true }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "POST" && userId && action === "toggle") {
      const u = (sysConfig.users || []).find(function (x) { return x.id === userId; });
      if (!u) return new Response(JSON.stringify({ ok: false, success: false, error: "Not found" }), { status: 404 });
      u.isPaused = !u.isPaused;
      if (!u.isPaused) { u.disabledReason = null; u.disabledAt = null; }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok: true, success: true, data: u, user: u }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "POST" && userId && action === "reset") {
      if (!sysUsageCache.users) sysUsageCache.users = {};
      const c = userId.replace(/-/g, "").toLowerCase();
      if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; }
      else sysUsageCache.users[c] = { reqs: 0, dReqs: 0, lastDay: todayStr() };
      await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
      return new Response(JSON.stringify({ ok: true, success: true }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: false, success: false, error: "Invalid" }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } }); }
}

async function handleUserBulkAction(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const body = await request.json();
    const ids = Array.isArray(body.ids) ? body.ids : [];
    const action = body.action;
    if (!ids.length || !action) return new Response(JSON.stringify({ ok: false, success: false, error: "ids and action required" }), { status: 400 });
    let affected = 0;
    const users = sysConfig.users || [];
    if (!sysUsageCache.users) sysUsageCache.users = {};
    for (const id of ids) {
      const u = users.find(function (x) { return x.id === id; });
      if (!u) continue;
      if (action === "pause") { u.isPaused = true; affected++; }
      else if (action === "resume") { u.isPaused = false; u.disabledReason = null; u.disabledAt = null; affected++; }
      else if (action === "reset") {
        const c = id.replace(/-/g, "").toLowerCase();
        if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; }
        else sysUsageCache.users[c] = { reqs: 0, dReqs: 0, lastDay: todayStr() };
        affected++;
      }
      else if (action === "extend" && body.days) { const d = parseInt(body.days) || 0; if (u.expiryMs) u.expiryMs += d * 86400000; else u.expiryMs = Date.now() + d * 86400000; affected++; }
      else if (action === "add-tag" && body.tag) { u.tags = u.tags || []; if (u.tags.indexOf(body.tag) === -1) u.tags.push(body.tag); affected++; }
      else if (action === "remove-tag" && body.tag) { u.tags = (u.tags || []).filter(function (t) { return t !== body.tag; }); affected++; }
      else if (action === "set-group" && body.groupId) { u.groupId = body.groupId; affected++; }
    }
    await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
    await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
    return new Response(JSON.stringify({ ok: true, success: true, affected: affected }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}

function parseCsvLine(line) {
  const out = []; let cur = "", inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ; }
    else if (c === "," && !inQ) { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

/* ⚡ CSV export with query-param auth (fix for window.open) */
async function handleBulkUsers(request, env, ctx) {
  try {
    const method = request.method;
    const url = new URL(request.url);

    // ⚡ FIX: Check token in query param for CSV download
    let perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) {
      const qkey = url.searchParams.get("key") || url.searchParams.get("token");
      if (qkey && (qkey === sysConfig.masterKey || isPanelApiKey(qkey))) {
        perm = { ok: true, ctx: { username: "master", isRoot: true, permissions: ["all"] } };
      }
    }
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });

    if (method === "GET") {
      let csv = "name,groupId,isp,trafficLimitGB,dailyLimitGB,expiryDays,maxConfigs,connLimit,bandwidthKbps,notes\n";
      for (const u of (sysConfig.users || [])) {
        csv += ['"' + (u.name || "").replace(/"/g, '""') + '"', u.groupId || "default", u.isp || "", u.limitTotalReq ? (u.limitTotalReq / 6000).toFixed(2) : "0", u.limitDailyReq ? (u.limitDailyReq / 6000).toFixed(2) : "0", u.expiryMs ? Math.max(0, Math.ceil((u.expiryMs - Date.now()) / 86400000)) : "0", u.maxConfigs || "0", u.connLimit || "0", u.bandwidthKbps || "0", '"' + (u.notes || "").replace(/"/g, '""') + '"'].join(",") + "\n";
      }
      return new Response("\ufeff" + csv, { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": "attachment; filename=\"hamed-users-" + new Date().toISOString().split("T")[0] + ".csv\"", "Cache-Control": "no-store" } });
    }
    if (method === "POST") {
      const body = await request.json();
      const csv = body.csv || "";
      const lines = csv.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
      if (lines.length < 2) return new Response(JSON.stringify({ ok: false, success: false, error: "Empty CSV" }), { status: 400 });
      const created = [], errors = [];
      for (let i = 1; i < lines.length; i++) {
        try {
          const cols = parseCsvLine(lines[i]);
          const name = (cols[0] || "").replace(/^"|"$/g, "").trim();
          if (!name) { errors.push("Line " + (i + 1) + ": empty"); continue; }
          if ((sysConfig.users || []).some(function (u) { return u.name.toLowerCase() === name.toLowerCase(); })) { errors.push("Line " + (i + 1) + ": duplicate"); continue; }
          const newId = generateId("u");
          const newUser = {
            id: newId, name: name, groupId: cols[1] || "default", isp: cols[2] || null,
            limitTotalReq: parseFloat(cols[3]) > 0 ? Math.floor(parseFloat(cols[3]) * 6000) : null,
            limitDailyReq: parseFloat(cols[4]) > 0 ? Math.floor(parseFloat(cols[4]) * 6000) : null,
            expiryMs: parseInt(cols[5]) > 0 ? Date.now() + parseInt(cols[5]) * 86400000 : null,
            maxConfigs: parseInt(cols[6]) > 0 ? parseInt(cols[6]) : null,
            connLimit: parseInt(cols[7]) > 0 ? parseInt(cols[7]) : null,
            bandwidthKbps: parseInt(cols[8]) > 0 ? parseInt(cols[8]) : null,
            notes: (cols[9] || "").replace(/^"|"$/g, "").trim(),
            relayIps: "", relayMode: "single", relayPresetId: "", createdAt: Date.now()
          };
          if (!sysConfig.users) sysConfig.users = [];
          sysConfig.users.push(newUser);
          created.push(name);
        } catch (e) { errors.push("Line " + (i + 1) + ": " + e.message); }
      }
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      return new Response(JSON.stringify({ ok: true, success: true, created: created.length, errors: errors }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}

/* ==================== GROUPS ==================== */
async function handleGroupsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "groups");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.userGroups || [], groups: sysConfig.userGroups || [] }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      const groups = sysConfig.userGroups || [];
      if (body.action === "create" || body.action === "update") {
        const g = {
          id: body.id || generateId("g"), name: body.name || "بدون نام",
          limitTotalGb: parseFloat(body.limitTotalGb) || 0,
          limitDailyGb: parseFloat(body.limitDailyGb) || 0,
          expiryDays: parseInt(body.expiryDays) || 0,
          maxConfigs: parseInt(body.maxConfigs) || 0,
          connLimit: parseInt(body.connLimit) || 0,
          color: body.color || "#8b5cf6"
        };
        if (body.action === "create") groups.push(g);
        else { const i = groups.findIndex(function (x) { return x.id === g.id; }); if (i === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); groups[i] = g; }
        sysConfig.userGroups = groups;
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: g }));
      }
      if (body.action === "delete") {
        if (body.id === "default") return new Response(JSON.stringify({ ok: false, success: false, error: "Cannot delete default" }), { status: 400 });
        sysConfig.userGroups = groups.filter(function (g) { return g.id !== body.id; });
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== MANAGERS ==================== */
async function handleManagersApi(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const method = request.method;
    const mgrId = url.searchParams.get("id");
    const perm = await requirePermission(request, env, null, "managers");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    await ensureRootManager();
    if (method === "GET" && !mgrId) {
      const list = (sysConfig.managers || []).map(function (m) {
        return { id: m.id, username: m.username, permissions: m.permissions || [], isRoot: m.isRoot === true, isActive: m.isActive !== false, createdAt: m.createdAt, lastLogin: m.lastLogin, createdBy: m.createdBy };
      });
      return new Response(JSON.stringify({ ok: true, success: true, data: list, managers: list }), { headers: { "Content-Type": "application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") {
        const username = body.username, password = body.password, permissions = body.permissions;
        if (!username || !password) return new Response(JSON.stringify({ ok: false, success: false, error: "نام و رمز الزامی" }), { status: 400 });
        if (String(username).length < 3) return new Response(JSON.stringify({ ok: false, success: false, error: "حداقل ۳ کاراکتر" }), { status: 400 });
        if (String(password).length < 4) return new Response(JSON.stringify({ ok: false, success: false, error: "حداقل ۴ کاراکتر" }), { status: 400 });
        if (sysConfig.managers.some(function (m) { return m.username.toLowerCase() === String(username).toLowerCase(); })) return new Response(JSON.stringify({ ok: false, success: false, error: "نام کاربری موجود" }), { status: 400 });
        const salt = generateSalt();
        const ph = await hashPassword(password, salt);
        const perms = Array.isArray(permissions) && permissions.length > 0 ? permissions.filter(function (p) { return ALL_PERMISSIONS.indexOf(p) !== -1; }) : ["users"];
        const newMgr = { id: generateId("m"), username: String(username), passwordHash: ph, salt: salt, permissions: perms, isRoot: false, isActive: true, createdAt: Date.now(), lastLogin: null, createdBy: perm.ctx.username };
        sysConfig.managers.push(newMgr);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: { id: newMgr.id, username: newMgr.username, permissions: newMgr.permissions } }), { status: 201 });
      }
      if (body.action === "update") {
        const id = body.id, password = body.password, permissions = body.permissions, isActive = body.isActive;
        const m = sysConfig.managers.find(function (x) { return x.id === id; });
        if (!m) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
        if (password && String(password).length >= 4) { m.salt = generateSalt(); m.passwordHash = await hashPassword(password, m.salt); }
        if (Array.isArray(permissions)) m.permissions = permissions.filter(function (p) { return ALL_PERMISSIONS.indexOf(p) !== -1; });
        if (isActive !== undefined) {
          if (m.isRoot && !isActive) return new Response(JSON.stringify({ ok: false, success: false, error: "Root غیرفعال نمی‌شود" }), { status: 400 });
          m.isActive = !!isActive;
        }
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "delete") {
        const idx = (sysConfig.managers || []).findIndex(function (x) { return x.id === body.id; });
        if (idx === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
        if (sysConfig.managers[idx].isRoot) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
        sysConfig.managers.splice(idx, 1);
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== STATS / HISTORY / ANOMALIES ==================== */
async function handleStatsApi(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    const users = sysConfig.users || [];
    const total = users.length;
    const active = users.filter(function (u) { return !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs); }).length;
    const autoOff = users.filter(function (u) { return u.isPaused && u.disabledReason; }).length;
    const paused = users.filter(function (u) { return u.isPaused && !u.disabledReason; }).length;
    const expired = users.filter(function (u) { return u.expiryMs && Date.now() > u.expiryMs && !u.isPaused; }).length;
    let totalReqs = 0, dailyReqs = 0;
    const today = todayStr();
    users.forEach(function (u) {
      const c = u.id.replace(/-/g, "").toLowerCase();
      const sysU = (sysUsageCache && sysUsageCache.users && sysUsageCache.users[c]) || { reqs: 0, dReqs: 0, lastDay: "" };
      totalReqs += sysU.reqs || 0;
      if (sysU.lastDay === today) dailyReqs += sysU.dReqs || 0;
    });
    const topUsers = users.map(function (u) {
      const c = u.id.replace(/-/g, "").toLowerCase();
      const s = (sysUsageCache && sysUsageCache.users && sysUsageCache.users[c]) || { reqs: 0 };
      return { name: u.name, gb: parseFloat(((s.reqs || 0) / 6000).toFixed(2)) };
    }).sort(function (a, b) { return b.gb - a.gb; }).slice(0, 5);
    const payload = {
      users: { total: total, active: active, paused: paused, expired: expired, autoDisabled: autoOff },
      traffic: { totalRequests: totalReqs, totalGB: (totalReqs / 6000).toFixed(2), dailyRequests: dailyReqs, dailyGB: (dailyReqs / 6000).toFixed(2) },
      system: { uptimeSeconds: Math.floor((Date.now() - isolateStartTime) / 1000), activeConnections: activeConnections, version: CURRENT_VERSION, isPaused: sysConfig.isPaused || false, topUsers: topUsers, ports: parsePorts(sysConfig.socketPorts, CF_HTTPS_PORTS) }
    };
    return new Response(JSON.stringify({ ok: true, success: true, data: payload, stats: payload }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleHistoryApi(request, env) {
  try {
    const url = new URL(request.url);
    const userId = url.searchParams.get("id");
    const days = Math.min(parseInt(url.searchParams.get("days") || "7"), 30);
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (userId) {
      const u = (sysConfig.users || []).find(function (x) { return x.id === userId || x.name === userId; });
      if (!u) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
      const c = u.id.replace(/-/g, "").toLowerCase();
      return new Response(JSON.stringify({ ok: true, success: true, user: u.name, series: getHistorySeries(c, days) }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ ok: true, success: true, series: getTotalHistorySeries(days) }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleCompareApi(request, env) {
  try {
    const url = new URL(request.url);
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const userIds = (url.searchParams.get("ids") || "").split(",").filter(Boolean);
    const days = Math.min(parseInt(url.searchParams.get("days") || "14"), 30);
    const series = {};
    for (const uid of userIds) {
      const u = (sysConfig.users || []).find(function (x) { return x.id === uid; });
      if (!u) continue;
      const c = u.id.replace(/-/g, "").toLowerCase();
      series[u.name] = getHistorySeries(c, days);
    }
    return new Response(JSON.stringify({ ok: true, success: true, series: series, days: days }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleAnomaliesApi(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const anomalies = await detectAnomalies();
    return new Response(JSON.stringify({ ok: true, success: true, data: anomalies, anomalies: anomalies }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== SESSIONS ==================== */
async function handleSessions(request, env) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "managers");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") {
      const sess = await listSessions(env);
      return new Response(JSON.stringify({
        ok: true, success: true,
        data: sess.map(function (s) { return { token: s.token.slice(0, 15) + "...", fullToken: s.token, username: s.username, ip: s.ip, ua: s.ua, createdAt: s.createdAt, expiresAt: s.expiresAt, isRoot: s.isRoot, current: s.token === perm.ctx.token }; }),
        sessions: sess
      }), { headers: { "Content-Type": "application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "revoke" && body.token) {
        const sess = await listSessions(env);
        const found = sess.find(function (s) { return s.token === body.token || s.token.indexOf(String(body.token).replace("...", "")) === 0; });
        if (found) { await destroySession(env, found.token); return new Response(JSON.stringify({ ok: true, success: true })); }
        return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 });
      }
      if (body.action === "revokeAll") {
        const sess = await listSessions(env);
        for (const s of sess) if (s.token !== perm.ctx.token) await destroySession(env, s.token);
        return new Response(JSON.stringify({ ok: true, success: true, revoked: sess.length - 1 }));
      }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== NODES ==================== */
async function handleNodesApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "nodes");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") {
      const nodes = [];
      if (Array.isArray(sysConfig.linkedPanels)) for (const p of sysConfig.linkedPanels) nodes.push({ url: p.url, apiKey: p.apiKey ? "[SET]" : null, name: p.name || p.url, group: p.group || "default", lastHealth: p.lastHealth || null });
      return new Response(JSON.stringify({ ok: true, success: true, data: nodes, nodes: nodes }), { headers: { "Content-Type": "application/json" } });
    }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "add") {
        if (!sysConfig.linkedPanels) sysConfig.linkedPanels = [];
        let cleanUrl = (body.url || "").trim();
        if (cleanUrl.indexOf("http") !== 0) cleanUrl = "https://" + cleanUrl;
        sysConfig.linkedPanels.push({ url: cleanUrl, apiKey: body.apiKey || "", name: body.name || cleanUrl, group: body.group || "default" });
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
      if (body.action === "remove") {
        sysConfig.linkedPanels = (sysConfig.linkedPanels || []).filter(function (p) { return p.url !== body.url; });
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true }));
      }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleNodeHealth(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "nodes");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const results = await runNodeHealthCheck(env);
    return new Response(JSON.stringify({ ok: true, success: true, data: results, results: results }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function runNodeHealthCheck(env) {
  const nodes = sysConfig.linkedPanels || [];
  const results = [];
  for (const node of nodes) {
    try {
      let clean = node.url.trim();
      if (clean.indexOf("http") !== 0) clean = "https://" + clean;
      const parsed = new URL(clean);
      const testUrl = parsed.protocol + "//" + parsed.host + "/" + encodeURI(sysConfig.apiRoute) + "/api/stats?key=" + encodeURIComponent(node.apiKey || "");
      const start = Date.now();
      const res = await fetch(testUrl, { signal: AbortSignal.timeout(8000) });
      const latency = Date.now() - start;
      const json = await res.json().catch(function () { return {}; });
      node.lastHealth = { status: res.ok && (json.ok || json.success) ? "online" : "error", latency: latency, ts: Date.now() };
      results.push({ url: node.url, status: node.lastHealth.status, latency: latency });
    } catch (e) {
      node.lastHealth = { status: "offline", latency: -1, ts: Date.now(), error: e.message };
      results.push({ url: node.url, status: "offline", latency: -1 });
    }
  }
  if (env.IOT_DB) await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return results;
}

/* ==================== REGIONS / CLEAN IP ==================== */
async function handleRegionsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: { regions: sysConfig.cleanIpRegions || [], active: sysConfig.activeCleanRegions || [], mode: sysConfig.cleanRegionMode || "round-robin" } }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "update") { sysConfig.cleanIpRegions = body.regions || []; sysConfig.activeCleanRegions = body.active || []; if (body.mode) sysConfig.cleanRegionMode = body.mode; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "add") { if (!sysConfig.cleanIpRegions) sysConfig.cleanIpRegions = []; sysConfig.cleanIpRegions.push({ id: body.id || generateId("r"), name: body.name || "جدید", flag: body.flag || "🌐", ips: parseIpList(body.ips) }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "delete") { sysConfig.cleanIpRegions = (sysConfig.cleanIpRegions || []).filter(function (r) { return r.id !== body.id; }); sysConfig.activeCleanRegions = (sysConfig.activeCleanRegions || []).filter(function (r) { return r !== body.id; }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "toggle") { const active = sysConfig.activeCleanRegions || []; if (active.indexOf(body.id) !== -1) sysConfig.activeCleanRegions = active.filter(function (x) { return x !== body.id; }); else sysConfig.activeCleanRegions = active.concat([body.id]); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, active: sysConfig.activeCleanRegions })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleCleanIpTest(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const results = await runCleanIpTest(env);
    return new Response(JSON.stringify({ ok: true, success: true, data: results, results: results }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleCleanIpResults(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.autoCleanIpCache || { ips: [], testedAt: 0 } }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function runCleanIpTest(env) {
  lastCleanIpTest = Date.now();
  const candidates = [];
  const ranges = ["104.16.0.0", "104.17.0.0", "104.18.0.0", "104.19.0.0", "104.20.0.0", "104.21.0.0", "104.22.0.0", "188.114.96.1", "188.114.97.1", "197.234.240.1", "103.21.244.1"];
  const custom = parseIpList(sysConfig.cleanIps);
  const pool = Array.from(new Set(custom.concat(ranges)));
  for (const ip of pool.slice(0, 25)) {
    try {
      const start = Date.now();
      const res = await fetch("https://" + ip + "/cdn-cgi/trace", { method: "GET", signal: AbortSignal.timeout(4000), headers: { Host: sysConfig.metricNode || "time.is" } });
      const latency = Date.now() - start;
      if (res.ok) { const txt = await res.text(); if (txt.indexOf("h=") !== -1) candidates.push({ ip: ip, latency: latency }); }
    } catch (e) {}
  }
  candidates.sort(function (a, b) { return a.latency - b.latency; });
  const top = candidates.slice(0, sysConfig.autoCleanIpTopN || 5).map(function (c) { return c.ip; });
  sysConfig.autoCleanIpCache = { ips: top, testedAt: Date.now(), full: candidates };
  if (env.IOT_DB) await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  return candidates;
}

/* ==================== BACKUP / CONFIG ==================== */
async function handleBackupApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") { const list = await listBackups(env); return new Response(JSON.stringify({ ok: true, success: true, data: list, backups: list }), { headers: { "Content-Type": "application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { const key = await backupToR2(env, { encrypt: body.encrypt }); return new Response(JSON.stringify({ ok: !!key, success: !!key, key: key }), { headers: { "Content-Type": "application/json" } }); }
      if (body.action === "restore") { const res = await restoreFromR2(env, body.key); return new Response(JSON.stringify(res)); }
      if (body.action === "delete") { if (env.BACKUP_BUCKET && body.key) { try { await env.BACKUP_BUCKET.delete(body.key); return new Response(JSON.stringify({ ok: true, success: true })); } catch (e) {} } return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleConfigExport(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const data = { version: CURRENT_VERSION, ts: new Date().toISOString(), config: sysConfig, usage: sysUsageCache, history: sysHistoryCache };
    return new Response(JSON.stringify(data, null, 2), { headers: { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=\"hamed-panel-backup-" + Date.now() + ".json\"" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleConfigImport(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "backup");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const body = await request.json();
    if (!body.data || !body.data.config) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
    const preserve = { managers: sysConfig.managers, panelApiKeys: sysConfig.panelApiKeys };
    sysConfig = Object.assign({}, SYSTEM_DEFAULTS, body.data.config, preserve);
    if (body.data.usage) sysUsageCache = body.data.usage;
    if (body.data.history) sysHistoryCache = body.data.history;
    const toSave = await encryptSensitiveInConfig(sysConfig, sysConfig.masterKey || "admin");
    await cachedD1Put(env, "sys_config", JSON.stringify(toSave));
    await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
    await cachedD1Put(env, "sys_history", JSON.stringify(sysHistoryCache));
    return new Response(JSON.stringify({ ok: true, success: true }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleBroadcast(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const body = await request.json();
    if (!body.message) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
    if (!sysConfig.tgToken) return new Response(JSON.stringify({ ok: false, success: false, error: "Telegram not configured" }), { status: 400 });
    const r = await sendCrisisBroadcast(env, body.message, "custom");
    return new Response(JSON.stringify(r), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== CRON / WEBHOOKS / BANNED / CRISIS ==================== */
async function handleCronJobsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "cron");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.cronJobs || [], jobs: sysConfig.cronJobs || [], actions: Object.keys(CRON_ACTIONS).map(function (k) { return Object.assign({ id: k }, CRON_ACTIONS[k]); }) }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.cronJobs) sysConfig.cronJobs = []; const j = { id: generateId("c"), name: body.name || "Job", action: body.jobAction || "send-telegram", params: body.params || {}, intervalMinutes: parseInt(body.intervalMinutes) || 60, enabled: body.enabled !== false, createdAt: Date.now(), lastRun: null }; sysConfig.cronJobs.push(j); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, data: j })); }
      if (body.action === "update") { const j = (sysConfig.cronJobs || []).find(function (x) { return x.id === body.id; }); if (!j) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); if (body.name !== undefined) j.name = body.name; if (body.params !== undefined) j.params = body.params; if (body.intervalMinutes !== undefined) j.intervalMinutes = parseInt(body.intervalMinutes); if (body.enabled !== undefined) j.enabled = !!body.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "delete") { sysConfig.cronJobs = (sysConfig.cronJobs || []).filter(function (x) { return x.id !== body.id; }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "run") { const j = (sysConfig.cronJobs || []).find(function (x) { return x.id === body.id; }); if (!j) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); await runCronJob(env, ctx, j); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, status: j.lastStatus })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleWebhooksApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "webhooks");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.webhooks || [], webhooks: sysConfig.webhooks || [], events: WEBHOOK_EVENTS }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.webhooks) sysConfig.webhooks = []; if (sysConfig.webhooks.length >= 10) return new Response(JSON.stringify({ ok: false, success: false, error: "Max 10" }), { status: 400 }); const w = { id: generateId("wh"), url: body.url, events: (body.events || []).filter(function (e) { return WEBHOOK_EVENTS.indexOf(e) !== -1; }), secret: body.secret || generateSalt(), enabled: body.enabled !== false, createdAt: Date.now() }; sysConfig.webhooks.push(w); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, data: w })); }
      if (body.action === "update") { const w = (sysConfig.webhooks || []).find(function (x) { return x.id === body.id; }); if (!w) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); if (body.url !== undefined) w.url = body.url; if (body.events !== undefined) w.events = body.events.filter(function (e) { return WEBHOOK_EVENTS.indexOf(e) !== -1; }); if (body.enabled !== undefined) w.enabled = !!body.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "delete") { sysConfig.webhooks = (sysConfig.webhooks || []).filter(function (x) { return x.id !== body.id; }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "test") { const w = (sysConfig.webhooks || []).find(function (x) { return x.id === body.id; }); if (!w) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); const payload = JSON.stringify({ event: "test", timestamp: Date.now(), version: CURRENT_VERSION, data: { message: "Test" } }); const sig = await hmacSign(w.secret, payload); try { const r = await fetch(w.url, { method: "POST", headers: { "Content-Type": "application/json", "X-Hamed-Event": "test", "X-Hamed-Signature": "sha256=" + sig }, body: payload, signal: AbortSignal.timeout(8000) }); return new Response(JSON.stringify({ ok: true, success: true, status: r.status })); } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message })); } }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleBannedApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") { const list = await listBannedIps(env); return new Response(JSON.stringify({ ok: true, success: true, data: list, banned: list }), { headers: { "Content-Type": "application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "ban") { await banIp(env, body.ip, body.reason || "Manual", body.durationMs); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "unban") { await unbanIp(env, body.ip); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "clear") { const list = await listBannedIps(env); for (const b of list) await unbanIp(env, b.ip); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, cleared: list.length })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleCrisisApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "users");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, presets: sysConfig.crisisPresets || [], history: sysConfig.crisisHistory || [] }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "send") { const preset = (sysConfig.crisisPresets || []).find(function (p) { return p.id === body.presetId; }); const message = body.message || (preset ? preset.text : "") || ""; if (!message) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); const r = await sendCrisisBroadcast(env, message, body.presetId || "custom"); if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "crisis.sent", { message: message, sent: r.sent }).catch(function () {})); return new Response(JSON.stringify(r), { headers: { "Content-Type": "application/json" } }); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleLogoApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, logo: sysConfig.customLogo || "", titleColor: sysConfig.customTitleColor || "" }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "set") { const logo = body.logo || ""; if (logo && logo.length > 200000) return new Response(JSON.stringify({ ok: false, success: false, error: "Too large" }), { status: 400 }); sysConfig.customLogo = logo; if (body.titleColor !== undefined) sysConfig.customTitleColor = body.titleColor; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "clear") { sysConfig.customLogo = ""; sysConfig.customTitleColor = ""; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleIspTemplatesApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.ispTemplates || {} }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") { const body = await request.json(); if (body.templates) { sysConfig.ispTemplates = body.templates; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); } }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleApiKeys(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "apikeys");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") { const keys = (sysConfig.panelApiKeys || []).map(function (k) { return { id: k.id, name: k.name, keyPreview: k.key.slice(0, 8) + "..." + k.key.slice(-4), createdAt: k.createdAt, lastUsed: k.lastUsed }; }); return new Response(JSON.stringify({ ok: true, success: true, data: keys, keys: keys }), { headers: { "Content-Type": "application/json" } }); }
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create") { if (!sysConfig.panelApiKeys) sysConfig.panelApiKeys = []; if (sysConfig.panelApiKeys.length >= 10) return new Response(JSON.stringify({ ok: false, success: false, error: "Max 10" }), { status: 400 }); const nk = generateApiKey(body.name); sysConfig.panelApiKeys.push(nk); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true, data: nk, key: nk }), { status: 201 }); }
      if (body.action === "revoke") { const idx = (sysConfig.panelApiKeys || []).findIndex(function (k) { return k.id === body.id; }); if (idx === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); sysConfig.panelApiKeys.splice(idx, 1); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleUpdateApi(request, env, ctx) {
  try {
    if (request.method !== "POST") return new Response("405", { status: 405 });
    const data = await request.json();
    const perm = await requirePermission(request, env, data, "advanced");
    if (!perm.ok || !perm.ctx.isRoot) return new Response(JSON.stringify({ ok: false, success: false, error: "Root only" }), { status: 403 });
    const accountId = sysConfig.cfAccountId, apiToken = sysConfig.cfApiToken, workerName = sysConfig.cfWorkerName;
    const repo = (sysConfig.githubRepo || "").replace(/https?:\/\/github\.com\//, "").trim();
    if (data.action === "check") {
      if (!repo) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
      let rv = null;
      try { const r = await fetch("https://raw.githubusercontent.com/" + repo + "/main/version", { signal: AbortSignal.timeout(8000) }); if (r.ok) { const t = (await r.text()).trim(); if (t && t.length <= 15) rv = t; } } catch (e) {}
      if (!rv) return new Response(JSON.stringify({ ok: false, success: false }), { status: 502 });
      return new Response(JSON.stringify({ ok: true, success: true, current: CURRENT_VERSION, latest: rv, updateAvailable: cmpVersions(CURRENT_VERSION, rv) < 0, canDeploy: !!(accountId && apiToken && workerName) }));
    }
    if (data.action === "deploy") {
      if (!accountId || !apiToken || !workerName) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
      let code = data.code;
      if (!code) { try { let r = await fetch("https://raw.githubusercontent.com/" + repo + "/main/_worker.encode.js", { signal: AbortSignal.timeout(15000) }); if (!r.ok) r = await fetch("https://raw.githubusercontent.com/" + repo + "/main/_worker.js", { signal: AbortSignal.timeout(15000) }); if (r.ok) code = await r.text(); else throw new Error("HTTP " + r.status); } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 502 }); } }
      const dr = await deployWorkerToCloudflare(accountId, apiToken, workerName, code);
      const dres = await dr.json();
      if (dres.success) { if (ctx && ctx.waitUntil) ctx.waitUntil(triggerWebhook(env, ctx, "panel.updated", { version: CURRENT_VERSION }).catch(function () {})); return new Response(JSON.stringify({ ok: true, success: true })); }
      const errMsg = dres.errors && dres.errors[0] ? dres.errors[0].message : "Unknown";
      return new Response(JSON.stringify({ ok: false, success: false, error: errMsg }), { status: 502 });
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== WORKFLOWS ==================== */
const WORKFLOW_TRIGGERS = [
  { id: "user.created", label: "کاربر ساخته شد" },
  { id: "user.disabled", label: "کاربر غیرفعال شد" },
  { id: "user.expired", label: "کاربر منقضی شد" },
  { id: "user.traffic80", label: "کاربر به ۸۰٪ ترافیک رسید" },
  { id: "user.traffic95", label: "کاربر به ۹۵٪ ترافیک رسید" },
  { id: "cron.custom", label: "تسک زمان‌بندی‌شده" }
];
const WORKFLOW_ACTIONS = [
  { id: "send.telegram", label: "ارسال پیام تلگرام", params: ["message"] },
  { id: "user.pause", label: "توقف کاربر", params: [] },
  { id: "user.resume", label: "فعال‌سازی کاربر", params: [] },
  { id: "user.extend", label: "تمدید کاربر", params: ["days"] },
  { id: "user.resetUsage", label: "بازنشانی مصرف", params: [] },
  { id: "webhook.trigger", label: "فراخوانی Webhook", params: ["event"] },
  { id: "user.addTag", label: "افزودن برچسب", params: ["tag"] }
];
async function handleWorkflowsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false, error: perm.error }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: { workflows: sysConfig.workflows || [], runs: sysConfig.workflowRuns || [], triggers: WORKFLOW_TRIGGERS, actions: WORKFLOW_ACTIONS } }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "create" || body.action === "update") {
        if (!sysConfig.workflows) sysConfig.workflows = [];
        const wf = { id: body.id || generateId("wf"), name: body.name || "Workflow", trigger: body.trigger || "user.created", conditions: body.conditions || {}, actions: body.actions || [], enabled: body.enabled !== false, createdAt: Date.now() };
        if (body.action === "create") sysConfig.workflows.push(wf);
        else { const i = sysConfig.workflows.findIndex(function (x) { return x.id === wf.id; }); if (i === -1) return new Response(JSON.stringify({ ok: false, success: false }), { status: 404 }); sysConfig.workflows[i] = wf; }
        await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
        return new Response(JSON.stringify({ ok: true, success: true, data: wf }));
      }
      if (body.action === "delete") { sysConfig.workflows = (sysConfig.workflows || []).filter(function (x) { return x.id !== body.id; }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false, error: e.message }), { status: 500 }); }
}
async function handleWorkflowsActions(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    return new Response(JSON.stringify({ ok: true, success: true, data: { triggers: WORKFLOW_TRIGGERS, actions: WORKFLOW_ACTIONS } }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function runWorkflow(env, ctx, wf, triggerCtx) {
  const results = [];
  try {
    for (const act of (wf.actions || [])) {
      try {
        if (act.type === "send.telegram") { if (!sysConfig.tgToken) continue; const recipient = sysConfig.tgAdminId || sysConfig.tgChatId; const msg = (act.params && act.params.message ? act.params.message : "").replace(/\{name\}/g, triggerCtx.name || ""); await fetch("https://api.telegram.org/bot" + sysConfig.tgToken + "/sendMessage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: recipient, text: msg, parse_mode: "HTML" }), signal: AbortSignal.timeout(8000) }).catch(function () {}); results.push({ action: act.type, ok: true }); }
        else if (act.type === "user.pause" || act.type === "user.resume") { const u = (sysConfig.users || []).find(function (x) { return x.id === triggerCtx.userId; }); if (u) { u.isPaused = act.type === "user.pause"; if (!u.isPaused) { u.disabledReason = null; u.disabledAt = null; } await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action: act.type, ok: true }); } }
        else if (act.type === "user.extend") { const u = (sysConfig.users || []).find(function (x) { return x.id === triggerCtx.userId; }); const days = parseInt(act.params && act.params.days ? act.params.days : 7) || 7; if (u) { if (u.expiryMs) u.expiryMs += days * 86400000; else u.expiryMs = Date.now() + days * 86400000; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action: act.type, ok: true }); } }
        else if (act.type === "user.resetUsage") { const c = triggerCtx.userId.replace(/-/g, "").toLowerCase(); if (!sysUsageCache.users) sysUsageCache.users = {}; if (sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; } await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache)); results.push({ action: act.type, ok: true }); }
        else if (act.type === "webhook.trigger") { await triggerWebhook(env, ctx, (act.params && act.params.event) || "custom", triggerCtx); results.push({ action: act.type, ok: true }); }
        else if (act.type === "user.addTag") { const u = (sysConfig.users || []).find(function (x) { return x.id === triggerCtx.userId; }); if (u && act.params && act.params.tag) { u.tags = u.tags || []; if (u.tags.indexOf(act.params.tag) === -1) u.tags.push(act.params.tag); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); results.push({ action: act.type, ok: true }); } }
      } catch (e) { results.push({ action: act.type, ok: false, error: e.message }); }
    }
    if (!sysConfig.workflowRuns) sysConfig.workflowRuns = [];
    sysConfig.workflowRuns.unshift({ wfId: wf.id, wfName: wf.name, trigger: triggerCtx.trigger, userId: triggerCtx.userId, ts: Date.now(), results: results });
    if (sysConfig.workflowRuns.length > 100) sysConfig.workflowRuns = sysConfig.workflowRuns.slice(0, 100);
    await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
  } catch (e) {}
  return results;
}
async function fireWorkflows(env, ctx, trigger, triggerCtx) {
  try {
    const wfs = (sysConfig.workflows || []).filter(function (w) { return w.enabled && w.trigger === trigger; });
    for (const wf of wfs) {
      let ok = true;
      if (wf.conditions) {
        if (wf.conditions.minGB !== undefined && (triggerCtx.gb || 0) < parseFloat(wf.conditions.minGB)) ok = false;
        if (wf.conditions.maxGB !== undefined && (triggerCtx.gb || 0) > parseFloat(wf.conditions.maxGB)) ok = false;
        if (wf.conditions.groupId && triggerCtx.groupId !== wf.conditions.groupId) ok = false;
      }
      if (ok && ctx && ctx.waitUntil) ctx.waitUntil(runWorkflow(env, ctx, wf, triggerCtx).catch(function () {}));
    }
  } catch (e) {}
}

/* ==================== DNS / UPSTREAMS / LATENCY / DPI / WEATHER / SUGG / PRED ==================== */
async function handleDnsPoolApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: { pool: sysConfig.dnsPool || [], strategy: sysConfig.dnsPoolStrategy || "weighted" } }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") { const body = await request.json(); if (body.action === "update") { sysConfig.dnsPool = body.pool || sysConfig.dnsPool; if (body.strategy) sysConfig.dnsPoolStrategy = body.strategy; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); } }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleDnsPoolActions(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const body = await request.json();
    if (body.action === "test") {
      const results = await Promise.all((sysConfig.dnsPool || []).filter(function (d) { return d.enabled; }).map(async function (d) {
        const start = Date.now();
        try { const u = new URL(d.url); u.searchParams.set("name", "example.com"); u.searchParams.set("type", "A"); const r = await fetch(u.toString(), { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) }); const j = await r.json().catch(function () { return {}; }); return { name: d.name, url: d.url, ok: r.ok && j.Answer, latency: Date.now() - start }; }
        catch (e) { return { name: d.name, url: d.url, ok: false, latency: -1, error: e.message }; }
      }));
      return new Response(JSON.stringify({ ok: true, success: true, data: results }));
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
function pickDnsFromPool() {
  const pool = (sysConfig.dnsPool || []).filter(function (d) { return d.enabled; });
  if (pool.length === 0) return sysConfig.customDns || "https://cloudflare-dns.com/dns-query";
  const strategy = sysConfig.dnsPoolStrategy || "weighted";
  if (strategy === "random") return pool[Math.floor(Math.random() * pool.length)].url;
  if (strategy === "weighted") { const total = pool.reduce(function (s, d) { return s + (d.weight || 1); }, 0); let r = Math.random() * total; for (const d of pool) { r -= (d.weight || 1); if (r <= 0) return d.url; } }
  return pool[0].url;
}
async function handleUpstreamsApi(request, env, ctx) {
  try {
    const method = request.method;
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    if (method === "GET") return new Response(JSON.stringify({ ok: true, success: true, data: sysConfig.multiUpstream || [] }), { headers: { "Content-Type": "application/json" } });
    if (method === "POST") {
      const body = await request.json();
      if (body.action === "add") { if (!sysConfig.multiUpstream) sysConfig.multiUpstream = []; const parsed = parseVlessUri(body.uri || ""); if (!parsed) return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 }); sysConfig.multiUpstream.push({ id: generateId("up"), name: body.name || parsed.name, uri: body.uri, enabled: true, createdAt: Date.now() }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "remove") { sysConfig.multiUpstream = (sysConfig.multiUpstream || []).filter(function (x) { return x.id !== body.id; }); await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); return new Response(JSON.stringify({ ok: true, success: true })); }
      if (body.action === "toggle") { const u = (sysConfig.multiUpstream || []).find(function (x) { return x.id === body.id; }); if (u) { u.enabled = !u.enabled; await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)); } return new Response(JSON.stringify({ ok: true, success: true })); }
    }
    return new Response(JSON.stringify({ ok: false, success: false }), { status: 400 });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleLatencyMap(request, env, ctx) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const map = {};
    for (const region of (sysConfig.cleanIpRegions || [])) map[region.id] = { name: region.name, flag: region.flag, active: (sysConfig.activeCleanRegions || []).indexOf(region.id) !== -1, ipCount: region.ips.length, avgLatency: null };
    const cached = sysConfig.autoCleanIpCache;
    if (cached && cached.full) for (const region of (sysConfig.cleanIpRegions || [])) { const matched = cached.full.filter(function (c) { return region.ips.some(function (ip) { return c.ip.indexOf(ip.split(".").slice(0, 3).join(".")) === 0; }); }); if (matched.length > 0) map[region.id].avgLatency = Math.round(matched.reduce(function (s, m) { return s + m.latency; }, 0) / matched.length); }
    return new Response(JSON.stringify({ ok: true, success: true, data: map }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleDpiDetection(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "advanced");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const country = (request.cf && request.cf.country) || "??";
    const asn = (request.cf && request.cf.asn) || 0;
    let score = 0, reasons = [];
    if (country === "IR") { score += 30; reasons.push("Iran origin"); }
    if ([58224, 197207, 44244, 16322, 202468].indexOf(asn) !== -1) { score += 40; reasons.push("Iranian ISP ASN"); }
    const mode = score > 60 ? "high" : score > 30 ? "medium" : "low";
    return new Response(JSON.stringify({ ok: true, success: true, data: { score: score, mode: mode, reasons: reasons, asn: asn, country: country, ts: Date.now() } }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleNetworkWeather(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const users = sysConfig.users || [];
    const active = users.filter(function (u) { return !u.isPaused && (!u.expiryMs || Date.now() <= u.expiryMs); }).length;
    const total = users.length;
    const health = total === 0 ? 100 : Math.round((active / total) * 100);
    const nodesOnline = (sysConfig.linkedPanels || []).filter(function (p) { return p.lastHealth && p.lastHealth.status === "online"; }).length;
    const nodesTotal = (sysConfig.linkedPanels || []).length;
    let cfUsage = null;
    if (sysConfig.cfAccountId && sysConfig.cfApiToken) cfUsage = await fetchCloudflareUsage(sysConfig.cfAccountId, sysConfig.cfApiToken);
    const cfPct = cfUsage !== null ? (cfUsage / 100000) * 100 : 0;
    let status = "sunny", emoji = "☀️";
    if (sysConfig.isPaused) { status = "storm"; emoji = "⛈️"; }
    else if (cfPct > 80) { status = "cloudy"; emoji = "☁️"; }
    else if (health < 50) { status = "rainy"; emoji = "🌧️"; }
    else if (health < 80 || nodesOnline < nodesTotal) { status = "cloudy"; emoji = "☁️"; }
    return new Response(JSON.stringify({ ok: true, success: true, data: { status: status, emoji: emoji, health: health, active: active, total: total, nodesOnline: nodesOnline, nodesTotal: nodesTotal, cfUsage: cfUsage, cfPct: cfPct.toFixed(2), uptime: Math.floor((Date.now() - isolateStartTime) / 1000), ts: Date.now() } }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handleSuggestions(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const suggestions = [];
    const users = sysConfig.users || [];
    const noIsp = users.filter(function (u) { return !u.isp; }).length;
    if (noIsp > 3) suggestions.push({ level: "info", icon: "isp", title: "تعیین ISP", desc: noIsp + " کاربر اپراتور مشخصی ندارند.", action: "tab:users" });
    if ((sysConfig.activeCleanRegions || []).length === 0) suggestions.push({ level: "warn", icon: "globe", title: "فعال‌سازی مناطق IP", desc: "هیچ منطقه‌ای فعال نیست.", action: "tab:regions" });
    if (sysConfig.activeFragment === "off") suggestions.push({ level: "info", icon: "target", title: "فعال‌سازی Fragment", desc: "Fragment خاموش است.", action: "tab:advanced" });
    if (Date.now() - (sysConfig.lastBackup || 0) > 7 * 86400000) suggestions.push({ level: "warn", icon: "save", title: "بکاپ بگیر", desc: "بیش از ۷ روز از آخرین بکاپ گذشته.", action: "tab:backup" });
    let over90 = 0;
    for (const u of users) { const c = u.id.replace(/-/g, "").toLowerCase(); const sysU = sysUsageCache.users && sysUsageCache.users[c]; if (sysU && u.limitTotalReq && sysU.reqs >= u.limitTotalReq * 0.9) over90++; }
    if (over90 > 0) suggestions.push({ level: "warn", icon: "alert", title: over90 + " کاربر نزدیک محدودیت", desc: "چند کاربر در آستانه اتمام ترافیک.", action: "tab:users" });
    if ((sysConfig.cronJobs || []).length === 0) suggestions.push({ level: "info", icon: "clock", title: "ساخت Cron Job", desc: "هنوز تسک زمان‌بندی‌شده‌ای ندارید.", action: "tab:cron" });
    if ((sysConfig.webhooks || []).length === 0) suggestions.push({ level: "info", icon: "webhook", title: "افزودن Webhook", desc: "برای اتصال به Slack/Discord.", action: "tab:webhooks" });
    if ((sysConfig.workflows || []).length === 0) suggestions.push({ level: "info", icon: "workflows", title: "ساخت Workflow", desc: "اتوماسیون خودکار بسازید.", action: "tab:workflows" });
    return new Response(JSON.stringify({ ok: true, success: true, data: suggestions, suggestions: suggestions }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}
async function handlePredictive(request, env) {
  try {
    const perm = await requirePermission(request, env, null, "stats");
    if (!perm.ok) return new Response(JSON.stringify({ ok: false, success: false }), { status: perm.status });
    const days = sysConfig.predictiveDays || 7;
    const series = getTotalHistorySeries(30);
    const recent = series.slice(-7).map(function (s) { return s.gb; });
    const avg = recent.length > 0 ? recent.reduce(function (a, b) { return a + b; }, 0) / recent.length : 0;
    const trend = recent.length >= 2 ? (recent[recent.length - 1] - recent[0]) / recent.length : 0;
    const predictions = [];
    for (let i = 1; i <= days; i++) { const projected = Math.max(0, avg + trend * i); const d = new Date(); d.setDate(d.getDate() + i); predictions.push({ date: d.toISOString().split("T")[0], gb: parseFloat(projected.toFixed(3)) }); }
    const nextWeekTotal = predictions.reduce(function (s, p) { return s + p.gb; }, 0);
    return new Response(JSON.stringify({ ok: true, success: true, data: { predictions: predictions, avg: avg, trend: trend, nextWeekTotal: nextWeekTotal.toFixed(2), basedOnDays: recent.length } }), { headers: { "Content-Type": "application/json" } });
  } catch (e) { return new Response(JSON.stringify({ ok: false, success: false }), { status: 500 }); }
}

/* ==================== TELEGRAM ==================== */
async function handleTelegramWebhook(request, env, hostName, ctx) {
  try {
    const update = await request.json();
    const tgApi = "https://api.telegram.org/bot" + sysConfig.tgToken;
    const callerId = (update.callback_query && update.callback_query.from && update.callback_query.from.id && update.callback_query.from.id.toString()) || (update.message && update.message.from && update.message.from.id && update.message.from.id.toString());
    const adminId = sysConfig.tgAdminId || sysConfig.tgChatId;
    const isAuthorized = adminId && callerId === adminId.toString();
    if (!isAuthorized) {
      const chatId = (update.callback_query && update.callback_query.message && update.callback_query.message.chat && update.callback_query.message.chat.id) || (update.message && update.message.chat && update.message.chat.id);
      if (chatId) await fetch(tgApi + "/sendMessage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: chatId, text: "دسترسی ندارید" }), signal: AbortSignal.timeout(8000) });
      return new Response("OK");
    }
    const sendMsg = async function (chatId, text, kb) { return await fetch(tgApi + "/sendMessage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: chatId, text: text, parse_mode: "Markdown", reply_markup: kb }), signal: AbortSignal.timeout(8000) }); };
    const mainMenu = function () { const users = sysConfig.users || []; const active = users.filter(function (u) { return !u.isPaused; }).length; return { text: "🦦 *" + PANEL_BRAND + "*\n━━━━━━━━━━━━━━━━\nکاربران: " + users.length + " (" + active + " فعال)\nوضعیت: " + (sysConfig.isPaused ? "متوقف" : "فعال") + "\nنسخه: v" + CURRENT_VERSION + "\n━━━━━━━━━━━━━━━━", kb: { inline_keyboard: [[{ text: "پنل", web_app: { url: "https://" + hostName + "/panel" } }]] } }; };
    if (update.callback_query) { const cb = update.callback_query; const chatId = cb.message && cb.message.chat && cb.message.chat.id; const m = mainMenu(); await sendMsg(chatId, m.text, m.kb); await fetch(tgApi + "/answerCallbackQuery", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ callback_query_id: cb.id, text: "✓" }) }).catch(function () {}); }
    else if (update.message && update.message.text) { const chatId = update.message.chat.id; const m = mainMenu(); await sendMsg(chatId, m.text, m.kb); }
    return new Response("OK");
  } catch (e) { return new Response("OK"); }
}

/* ==================== MAINTENANCE ==================== */
async function serveMaintenancePage(request, url) {
  let list = sysConfig.maintenanceHost ? sysConfig.maintenanceHost.split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s; }) : ["https://www.ubuntu.com"];
  const ip = request.headers.get("cf-connecting-ip") || "0.0.0.0";
  const h = Array.from(ip).reduce(function (a, c) { return a + c.charCodeAt(0); }, 0);
  const target = list[h % list.length].indexOf("http") === 0 ? list[h % list.length] : "https://" + list[h % list.length];
  try {
    const turl = new URL(target);
    if (url.pathname !== "/") turl.pathname = url.pathname;
    turl.search = url.search;
    const hd = new Headers(request.headers);
    hd.set("Host", turl.hostname);
    hd.delete("cf-connecting-ip");
    hd.delete("x-forwarded-for");
    const init = { method: request.method, headers: hd, redirect: "follow" };
    if (request.method !== "GET" && request.method !== "HEAD") init.body = request.body;
    return await fetch(new Request(turl.toString(), init));
  } catch (e) { return new Response("Not Found", { status: 404 }); }
}
/* ==================== ADVANCED EXTRAS BUILDER ==================== */
function buildAdvancedExtras(ispFrag) {
  const adv = sysConfig.advanced || {};
  let s = "";
  if (adv.tcpFastOpen) s += "&tfo=1";
  if (adv.mux) s += "&mux=1&muxConcurrency=" + (adv.muxConcurrency || 8);
  if (adv.xtls) s += "&xtls=1";
  if (adv.earlyData) s += "&ed=2048&edh=" + encodeURIComponent(adv.earlyDataHeader || "Sec-WebSocket-Protocol");
  if (adv.http3) s += "&h3=1";
  if (adv.padding) s += "&padding=1";
  if (adv.keepAlive) s += "&keepAlive=" + adv.keepAlive;
  if (adv.udpRelay === false) s += "&udp=0";
  if (adv.tlsFragment === false) s += "&fragment=off";
  if (adv.alpn) s += "&alpn=" + encodeURIComponent(adv.alpn);
  if (adv.ech) s += "&ech=1";
  if (ispFrag) s += ispFrag;
  return s;
}

/* ==================== CUSTOM INBOUND RENDERER ==================== */
function renderCustomInboundContent(c, profile) {
  let txt = c.content || "";
  const today = new Date();
  const dateStr = today.getFullYear() + "-" + String(today.getMonth() + 1).padStart(2, "0") + "-" + String(today.getDate()).padStart(2, "0");
  const prefix = (sysConfig.inboundConfigs && sysConfig.inboundConfigs.global && sysConfig.inboundConfigs.global.prefix) || sysConfig.namePrefix || "Hamed";
  txt = txt.replace(/\{USER\}/g, profile ? (profile.name || "") : "")
           .replace(/\{DATE\}/g, dateStr)
           .replace(/\{PREFIX\}/g, prefix)
           .replace(/\{PANEL\}/g, sysConfig.name || PANEL_BRAND)
           .replace(/\{VERSION\}/g, CURRENT_VERSION);
  return txt;
}
function buildCustomInboundURIs(profile, position) {
  try {
    const cfg = sysConfig.inboundConfigs || {};
    if (cfg.enabled === false) return [];
    const list = (cfg.customInbounds || []).filter(function (c) {
      return c && c.enabled && c.content && (c.position || "start") === position;
    });
    return list.map(function (c) {
      const txt = renderCustomInboundContent(c, profile);
      if (!txt) return "";
      const prefix = c.flagPrefix ? c.flagPrefix + " " : "";
      return "trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#" + encodeURIComponent(prefix + txt);
    }).filter(Boolean);
  } catch (e) { return []; }
}

/* ==================== CONFIG BUILDERS ==================== */
async function buildUriProfile(hostName, targetSub, allowInsecure) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const reqPath = encodeURI("/" + sysConfig.apiRoute);
  const fragValue = getActiveFragmentValue();
  const fragParam = fragValue ? "&fragment=" + encodeURIComponent(fragValue) : "";
  const lines = [];
  const profiles = getAllProfiles(targetSub);
  const allHostNames = Array.from(new Set(profiles.reduce(function (acc, p) { return acc.concat(getProfileHostNames(hostName, p)); }, [])));
  try { await preloadIpFlags(profiles, allHostNames); } catch (e) {}

  // Fake configs
  getFakeConfigNames(targetSub).forEach(function (name) {
    lines.push("trojan://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?security=none#" + encodeURIComponent(name));
  });

  let _targetId = activeDeviceId;
  if (targetSub) {
    const tu = sysConfig.users.find(function (u) { return u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub; });
    if (tu) _targetId = tu.id;
  }
  const _targetProfile = profiles.find(function (p) { return p.id === _targetId; }) || null;

  // ⚡ Custom inbound cards - START position
  buildCustomInboundURIs(_targetProfile, "start").forEach(function (u) { lines.push(u); });

  // Static extra entries
  const extraEntries = getExtraInboundEntries(_targetId);
  extraEntries.filter(function (e) { return e.position !== "end"; }).forEach(function (e) {
    const u = buildStaticInboundURI(e);
    if (u) lines.push(u);
  });

  // Main configs
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, fragValue);
      const pips = getEffectivePips(p);
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayRegion = getRelayRegionInfo(p);
      const relayServerIps = getRelayRegionServerIps(p);

      let configIndex = 0;
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, pips.length);
        const ipEntryMap = {};
        entries.forEach(function (e) { ipEntryMap[e.ip] = e; });
        ePorts.forEach(function (port) {
          const sec = getTransportParams(port);
          const ispFrag = ispTemplate.fragment ? "&fragment=" + encodeURIComponent(ispTemplate.fragment) : fragParam;
          let extBase = "encryption=none&security=" + sec + "&sni=" + hName + "&fp=" + (ispTemplate.agent || sysConfig.agent || "chrome") + "&type=ws&host=" + hName + "&path=" + reqPath;
          if (sysConfig.enableOpt2) extBase += "&pbk=enabled";
          extBase += buildAdvancedExtras(ispFrag);
          extBase += "&allowInsecure=" + (allowInsecure ? "1" : "0");
          ips.forEach(function (ip) {
            const _pips = pips.length > 0 ? pips : [null];
            _pips.forEach(function (sel) {
              const ipEntry = ipEntryMap[ip] || {};
              const regionInfo = relayRegion || (ipEntry.regionId ? { id: ipEntry.regionId, name: ipEntry.regionName, flag: ipEntry.regionFlag } : null);
              if (mode === "alpha" || mode === "both") {
                const cfgUuid = generateConfigUuid(p.id, configIndex);
                registerConfigEntry(cfgUuid, p.id, sel || "");
                const name = buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false);
                lines.push(getAlpha() + "://" + cfgUuid + "@" + ip + ":" + port + "?" + extBase + "#" + encodeURIComponent(name));
              }
              if (mode === "beta" || mode === "both") {
                const junk = Array.from({ length: 11 }, function () { return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]; }).join("");
                const payload = { junk: junk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex };
                const pathStr = "/" + btoa(JSON.stringify(payload));
                let tb = "security=" + sec + "&sni=" + hName + "&fp=" + (ispTemplate.agent || sysConfig.agent || "chrome") + "&type=ws&host=" + hName + "&path=" + encodeURIComponent(pathStr);
                if (sysConfig.enableOpt2) tb += "&pbk=enabled";
                tb += buildAdvancedExtras(ispFrag);
                tb += "&allowInsecure=" + (allowInsecure ? "1" : "0");
                const name = buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false);
                lines.push(getBeta() + "://" + p.id + "@" + ip + ":" + port + "?" + tb + "#" + encodeURIComponent(name));
              }
              configIndex++;
            });
          });
        });
      });
    } catch (e) {}
  });

  // Upstream
  const up = parseVlessUri(sysConfig.upstreamUri);
  if (up) lines.unshift(up.raw);

  // End-position: extra entries + custom inbounds
  extraEntries.filter(function (e) { return e.position === "end"; }).forEach(function (e) {
    const u = buildStaticInboundURI(e);
    if (u) lines.push(u);
  });
  buildCustomInboundURIs(_targetProfile, "end").forEach(function (u) { lines.push(u); });

  return lines.join("\n");
}

async function buildYamlProfile(hostName, targetSub, allowInsecure, env) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const profiles = getAllProfiles(targetSub);
  const allHostNames = Array.from(new Set(profiles.reduce(function (acc, p) { return acc.concat(getProfileHostNames(hostName, p)); }, [])));
  try { await preloadIpFlags(profiles, allHostNames); } catch (e) {}
  const proxies = [], proxyNames = [], proxyGeoInfo = new Map();
  const nameCounts = {};
  getFakeConfigNames(targetSub).forEach(function (name) {
    proxies.push("- name: \"" + name + "\"\n  type: " + getBeta() + "\n  server: 127.0.0.1\n  port: 80\n  password: \"" + activeDeviceId + "\"\n  udp: true\n  tls: false");
  });
  const uniqueName = function (base) {
    if (!nameCounts[base]) { nameCounts[base] = 1; return base; }
    let c = nameCounts[base];
    let n = base + "-" + c;
    while (nameCounts[n]) { c++; n = base + "-" + c; }
    nameCounts[base] = c + 1;
    nameCounts[n] = 1;
    return n;
  };
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const pips = getEffectivePips(p);
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayRegion = getRelayRegionInfo(p);
      const relayServerIps = getRelayRegionServerIps(p);
      let configIndex = 0;
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, pips.length);
        const ipEntryMap = {};
        entries.forEach(function (e) { ipEntryMap[e.ip] = e; });
        ePorts.forEach(function (port) {
          const sec = getTransportParams(port) === "tls" ? "true" : "false";
          ips.forEach(function (ip) {
            const _pips = pips.length > 0 ? pips : [null];
            _pips.forEach(function (sel) {
              const ipEntry = ipEntryMap[ip] || {};
              const regionInfo = relayRegion || (ipEntry.regionId ? { id: ipEntry.regionId, name: ipEntry.regionName, flag: ipEntry.regionFlag } : null);
              if (mode === "alpha" || mode === "both") {
                const vName = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false));
                proxyNames.push("\"" + vName + "\"");
                proxyGeoInfo.set(vName, regionInfo ? { country: regionInfo.name, flag: regionInfo.flag } : getGeoInfo(sel || ip));
                const junk = Array.from({ length: 11 }, function () { return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]; }).join("");
                const pathStr = "/" + btoa(JSON.stringify({ junk: junk, protocol: "vl", mode: "proxyip", panelIPs: [] }));
                const cfgUuid = generateConfigUuid(p.id, configIndex);
                registerConfigEntry(cfgUuid, p.id, sel || "");
                proxies.push("- name: \"" + vName.replace(/"/g, '""') + "\"\n  type: " + getAlpha() + "\n  server: " + ip + "\n  port: " + port + "\n  uuid: " + cfgUuid + "\n  udp: true\n  tls: " + sec + "\n  servername: " + hName + "\n  client-fingerprint: " + (ispTemplate.agent || sysConfig.agent || "random") + "\n  network: ws\n  ws-opts:\n    path: \"" + pathStr + "\"\n    headers:\n      Host: " + hName + "\n  skip-cert-verify: " + allowInsecure);
              }
              if (mode === "beta" || mode === "both") {
                const tName = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false));
                proxyNames.push("\"" + tName + "\"");
                proxyGeoInfo.set(tName, regionInfo ? { country: regionInfo.name, flag: regionInfo.flag } : getGeoInfo(sel || ip));
                const junk = Array.from({ length: 11 }, function () { return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[Math.floor(Math.random() * 62)]; }).join("");
                const pathStr = "/" + btoa(JSON.stringify({ junk: junk, protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex }));
                proxies.push("- name: \"" + tName.replace(/"/g, '""') + "\"\n  type: " + getBeta() + "\n  server: " + ip + "\n  port: " + port + "\n  password: \"" + p.id + "\"\n  udp: true\n  tls: " + sec + "\n  sni: " + hName + "\n  client-fingerprint: " + (ispTemplate.agent || sysConfig.agent || "random") + "\n  network: ws\n  ws-opts:\n    path: \"" + pathStr + "\"\n    headers:\n      Host: " + hName + "\n  skip-cert-verify: " + allowInsecure);
              }
              configIndex++;
            });
          });
        });
      });
    } catch (e) {}
  });
  const countryGroups = new Map();
  proxyGeoInfo.forEach(function (geo, name) {
    const k = geo.country || "Unknown";
    if (!countryGroups.has(k)) countryGroups.set(k, { flag: geo.flag || "🌐", proxies: [] });
    countryGroups.get(k).proxies.push(name);
  });
  const sorted = Array.from(countryGroups.entries()).sort(function (a, b) { return a[0].localeCompare(b[0]); });
  let groups = 'proxy-groups:\n  - name: "✅ Selector"\n    type: select\n    proxies:\n      - "⚡ Fastest"\n      - "🖐 Manual"\n';
  sorted.forEach(function (entry) { groups += '      - "' + entry[1].flag + " " + entry[0] + '"\n'; });
  groups += '\n  - name: "⚡ Fastest"\n    type: url-test\n    url: "https://www.gstatic.com/generate_204"\n    interval: 30\n    tolerance: 50\n    proxies:\n';
  proxyNames.forEach(function (n) { groups += "      - " + n + "\n"; });
  return "mixed-port: 7890\nipv6: true\nallow-lan: false\nlog-level: warning\nmode: rule\ntcp-concurrent: true\ndns:\n  enable: true\n  listen: 127.0.0.1:1053\n  nameserver: [\"https://8.8.8.8/dns-query#✅ Selector\"]\n  enhanced-mode: redir-host\ntun:\n  enable: true\n  stack: mixed\n  auto-route: true\n  dns-hijack: [\"any:53\"]\n  mtu: 9000\n\nproxies:\n" + proxies.join("\n") + "\n\n" + groups + "\n\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,✅ Selector\n";
}

async function buildClashJsonProfile(hostName, targetSub, allowInsecure, env) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const profiles = getAllProfiles(targetSub);
  const allHostNames = Array.from(new Set(profiles.reduce(function (acc, p) { return acc.concat(getProfileHostNames(hostName, p)); }, [])));
  try { await preloadIpFlags(profiles, allHostNames); } catch (e) {}
  const proxiesArr = [], dynamicTags = [];
  const uniqueName = function (base) { let c = 0, n = base; while (proxiesArr.some(function (p) { return p.name === n; })) { c++; n = base + "-" + c; } return n; };
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const pips = getEffectivePips(p);
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayRegion = getRelayRegionInfo(p);
      const relayServerIps = getRelayRegionServerIps(p);
      let configIndex = 0;
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, pips.length);
        ePorts.forEach(function (port) {
          const sec = getTransportParams(port) === "tls";
          ips.forEach(function (ip) {
            const _pips = pips.length > 0 ? pips : [null];
            _pips.forEach(function (sel) {
              const regionInfo = relayRegion || null;
              if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, regionInfo, false)); dynamicTags.push(tag); const pathStr = "/" + btoa(JSON.stringify({ junk: "j", protocol: "vl", mode: "proxyip", panelIPs: [] })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); proxiesArr.push({ name: tag, type: "vless", server: ip, port: parseInt(port), udp: true, uuid: cfgUuid, tls: sec, servername: hName, "client-fingerprint": ispTemplate.agent || "random", "skip-cert-verify": allowInsecure, network: "ws", "ws-opts": { path: pathStr, headers: { Host: hName } } }); }
              if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, regionInfo, false)); dynamicTags.push(tag); const pathStr = "/" + btoa(JSON.stringify({ junk: "j", protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex })); proxiesArr.push({ name: tag, type: "trojan", server: ip, port: parseInt(port), udp: true, password: p.id, tls: sec, sni: hName, "client-fingerprint": ispTemplate.agent || "random", "skip-cert-verify": allowInsecure, network: "ws", "ws-opts": { path: pathStr, headers: { Host: hName } } }); }
              configIndex++;
            });
          });
        });
      });
    } catch (e) {}
  });
  if (dynamicTags.length === 0) dynamicTags.push("direct");
  return { "mixed-port": 7890, ipv6: true, "allow-lan": false, "log-level": "warning", mode: "rule", "tcp-concurrent": true, proxies: proxiesArr, "proxy-groups": [{ name: "✅ Selector", type: "select", proxies: ["⚡ Fastest"].concat(dynamicTags) }, { name: "⚡ Fastest", type: "url-test", url: "https://www.gstatic.com/generate_204", interval: 30, proxies: dynamicTags }], rules: ["GEOIP,IR,DIRECT", "MATCH,✅ Selector"] };
}

async function buildVJsonProfile(hostName, targetSub, allowInsecure, env) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const profiles = getAllProfiles(targetSub);
  const allHostNames = Array.from(new Set(profiles.reduce(function (acc, p) { return acc.concat(getProfileHostNames(hostName, p)); }, [])));
  try { await preloadIpFlags(profiles, allHostNames); } catch (e) {}
  const outbounds = [];
  const uniqueName = function (base) { let c = 0, n = base; while (outbounds.some(function (o) { return o.tag === n; })) { c++; n = base + "-" + c; } return n; };
  let configIndex = 0;
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const pips = getEffectivePips(p);
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayRegion = getRelayRegionInfo(p);
      const relayServerIps = getRelayRegionServerIps(p);
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, pips.length);
        ePorts.forEach(function (port) {
          const sec = getTransportParams(port) === "tls" ? "tls" : "none";
          ips.forEach(function (ip) {
            const _pips = pips.length > 0 ? pips : [null];
            _pips.forEach(function (sel) {
              if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, relayRegion, false)); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); const path = "/" + btoa(JSON.stringify({ junk: "j", protocol: "vl", mode: "proxyip", panelIPs: [], relayIdx: configIndex })); outbounds.push({ tag: tag, protocol: "vless", settings: { vnext: [{ address: ip, port: parseInt(port), users: [{ id: cfgUuid, encryption: "none" }] }] }, streamSettings: { network: "ws", security: sec, tlsSettings: sec === "tls" ? { serverName: hName, allowInsecure: allowInsecure } : undefined, wsSettings: { path: path, headers: { Host: hName } } } }); }
              if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, relayRegion, false)); const path = "/" + btoa(JSON.stringify({ junk: "j", protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex })); outbounds.push({ tag: tag, protocol: "trojan", settings: { servers: [{ address: ip, port: parseInt(port), password: p.id }] }, streamSettings: { network: "ws", security: sec, tlsSettings: sec === "tls" ? { serverName: hName, allowInsecure: allowInsecure } : undefined, wsSettings: { path: path, headers: { Host: hName } } } }); }
              configIndex++;
            });
          });
        });
      });
    } catch (e) {}
  });
  return { outbounds: outbounds };
}

async function buildSingBoxJsonProfile(hostName, targetSub, allowInsecure, env) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const profiles = getAllProfiles(targetSub);
  const allHostNames = Array.from(new Set(profiles.reduce(function (acc, p) { return acc.concat(getProfileHostNames(hostName, p)); }, [])));
  try { await preloadIpFlags(profiles, allHostNames); } catch (e) {}
  const outbounds = [];
  const uniqueName = function (base) { let c = 0, n = base; while (outbounds.some(function (o) { return o.tag === n; })) { c++; n = base + "-" + c; } return n; };
  let configIndex = 0;
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const pips = getEffectivePips(p);
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayRegion = getRelayRegionInfo(p);
      const relayServerIps = getRelayRegionServerIps(p);
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, pips.length);
        ePorts.forEach(function (port) {
          const sec = getTransportParams(port) === "tls";
          ips.forEach(function (ip) {
            const _pips = pips.length > 0 ? pips : [null];
            _pips.forEach(function (sel) {
              if (mode === "alpha" || mode === "both") { const tag = uniqueName(buildInboundName("alpha", p, ip, port, configIndex, hName, relayRegion, false)); const path = "/" + btoa(JSON.stringify({ junk: "j", protocol: "vl", mode: "proxyip", panelIPs: [] })); const cfgUuid = generateConfigUuid(p.id, configIndex); registerConfigEntry(cfgUuid, p.id, sel || ""); outbounds.push({ type: "vless", tag: tag, server: ip, server_port: parseInt(port), uuid: cfgUuid, network: "tcp", tls: { enabled: sec, server_name: hName, insecure: allowInsecure, utls: { enabled: true, fingerprint: "randomized" } }, transport: { type: "ws", path: path, headers: { Host: hName } } }); }
              if (mode === "beta" || mode === "both") { const tag = uniqueName(buildInboundName("beta", p, ip, port, configIndex, hName, relayRegion, false)); const path = "/" + btoa(JSON.stringify({ junk: "j", protocol: "tr", mode: "proxyip", panelIPs: [], relayIdx: configIndex })); outbounds.push({ type: "trojan", tag: tag, server: ip, server_port: parseInt(port), password: p.id, network: "tcp", tls: { enabled: sec, server_name: hName, insecure: allowInsecure, utls: { enabled: true, fingerprint: "randomized" } }, transport: { type: "ws", path: path, headers: { Host: hName } } }); }
              configIndex++;
            });
          });
        });
      });
    } catch (e) {}
  });
  return { log: { disabled: false, level: "warn", timestamp: true }, dns: { servers: [{ tag: "cf", address: "https://1.1.1.1/dns-query", detour: "direct" }], rules: [] }, inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 2080 }], outbounds: [{ type: "direct", tag: "direct" }].concat(outbounds), route: { rules: [], final: "direct" } };
}

async function buildSurgeProfile(hostName, targetSub, allowInsecure) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const lines = ["[Proxy]"];
  const profiles = getAllProfiles(targetSub);
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayServerIps = getRelayRegionServerIps(p);
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, 1);
        ips.forEach(function (ip) { ePorts.forEach(function (port) {
          if (mode === "alpha" || mode === "both") { const cfgUuid = generateConfigUuid(p.id, 0); registerConfigEntry(cfgUuid, p.id, ""); lines.push(p.name + "-V-" + ip + "-" + port + " = vless, " + ip + ", " + port + ", username=" + cfgUuid + ", tls=true, ws=true, ws-path=/" + sysConfig.apiRoute + ", ws-headers=Host:" + hName + ", sni=" + hName); }
          if (mode === "beta" || mode === "both") { lines.push(p.name + "-T-" + ip + "-" + port + " = trojan, " + ip + ", " + port + ", password=" + p.id + ", tls=true, ws=true, ws-path=/" + sysConfig.apiRoute + ", ws-headers=Host:" + hName + ", sni=" + hName); }
        }); });
      });
    } catch (e) {}
  });
  lines.push("", "[Proxy Group]", "Proxy = select, " + profiles.map(function (p) { return p.name; }).join(", "));
  lines.push("", "[Rule]", "GEOIP,IR,DIRECT", "FINAL,Proxy");
  return lines.join("\n");
}

async function buildLoonProfile(hostName, targetSub, allowInsecure) {
  if (targetSub === undefined) targetSub = null;
  if (allowInsecure === undefined) allowInsecure = false;
  const lines = ["[Proxy]"];
  const profiles = getAllProfiles(targetSub);
  profiles.forEach(function (p) {
    try {
      const ispTemplate = applyIspTemplate(p, "");
      const mode = p.userMode || sysConfig.mode;
      const ePorts = getEffectivePorts(p, ispTemplate);
      const relayServerIps = getRelayRegionServerIps(p);
      getProfileHostNames(hostName, p).forEach(function (hName) {
        const entries = getCleanIpsWithNames(hName, p.cleanIp);
        let sourceIps;
        if (relayServerIps && relayServerIps.length > 0) sourceIps = relayServerIps.slice();
        else sourceIps = entries.map(function (e) { return e.ip; });
        const ips = calcEffectiveIps(sourceIps, p.maxConfigs || null, mode, ePorts, 1);
        ips.forEach(function (ip) { ePorts.forEach(function (port) {
          if (mode === "alpha" || mode === "both") { const cfgUuid = generateConfigUuid(p.id, 0); registerConfigEntry(cfgUuid, p.id, ""); lines.push(p.name + "-V-" + ip + "-" + port + " = vless," + ip + "," + port + ",\"" + cfgUuid + "\",over-tls=true,tls-name=" + hName + ",transport=ws,path=/" + sysConfig.apiRoute + ",host=" + hName); }
          if (mode === "beta" || mode === "both") { lines.push(p.name + "-T-" + ip + "-" + port + " = trojan," + ip + "," + port + ",\"" + p.id + "\",over-tls=true,tls-name=" + hName + ",transport=ws,path=/" + sysConfig.apiRoute + ",host=" + hName); }
        }); });
      });
    } catch (e) {}
  });
  lines.push("", "[Proxy Group]", "Proxy = select, " + profiles.map(function (p) { return p.name; }).join(", "));
  lines.push("", "[Rule]", "GEOIP,CN,DIRECT", "FINAL,Proxy");
  return lines.join("\n");
}

/* ==================== SUBSCRIPTION ==================== */
async function handleSubscription(request, url, env, ctx) {
  try {
    const ua = (request.headers.get("User-Agent") || "").toLowerCase();
    const isCustomUaAllowed = sysConfig.subUserAgent && sysConfig.subUserAgent.trim().length > 0 && ua.indexOf(sysConfig.subUserAgent.trim().toLowerCase()) !== -1;
    const clientHost = request.headers.get("Host") || url.hostname;
    const targetSub = url.searchParams.get("sub");
    const hasMultiUser = sysConfig.users && sysConfig.users.length > 0;
    let targetUser = null, isValidUser = false;
    if (hasMultiUser) {
      if (targetSub) { targetUser = sysConfig.users.find(function (u) { return u.name.toLowerCase() === targetSub.toLowerCase() || u.id === targetSub; }); if (targetUser) isValidUser = true; }
    } else { isValidUser = true; targetUser = { id: activeDeviceId, name: "Default" }; }

    const acceptHeader = (request.headers.get("Accept") || "").toLowerCase();
    const secFetchDest = (request.headers.get("Sec-Fetch-Dest") || "").toLowerCase();
    const isRealBrowser = (secFetchDest === "document" || acceptHeader.indexOf("text/html") !== -1)
      && (ua.indexOf("mozilla") !== -1 || ua.indexOf("chrome") !== -1 || ua.indexOf("safari") !== -1 || ua.indexOf("applewebkit") !== -1 || ua.indexOf("gecko") !== -1)
      && ua.indexOf("cla" + "sh") === -1 && ua.indexOf("si" + "ng-box") === -1
      && ua.indexOf("v" + "2r" + "ay") === -1 && ua.indexOf("shadow" + "rocket") === -1;

    if (isRealBrowser && !isCustomUaAllowed) {
      if (isValidUser) {
        try {
          let html = SUBSCRIPTION_HTML;
          const idClean = targetUser.id.replace(/-/g, "").toLowerCase();
          const sysU = (sysUsageCache && sysUsageCache.users ? sysUsageCache.users[idClean] : null) || { reqs: 0, dReqs: 0, lastDay: "" };
          const totalReqs = sysU.reqs || 0;
          const today = todayStr();
          const dailyReqs = sysU.lastDay === today ? (sysU.dReqs || 0) : 0;
          const limitTotal = targetUser.limitTotalReq || 0;
          const limitDaily = targetUser.limitDailyReq || 0;
          const totalGb = (totalReqs / 6000).toFixed(2);
          const limitTotalGb = limitTotal ? (limitTotal / 6000).toFixed(2) : "∞";
          const dailyGb = (dailyReqs / 6000).toFixed(2);
          const limitDailyGb = limitDaily ? (limitDaily / 6000).toFixed(2) : "∞";
          const totalPercent = limitTotal ? Math.min(100, (totalReqs / limitTotal) * 100).toFixed(1) : "0";
          const dailyPercent = limitDaily ? Math.min(100, (dailyReqs / limitDaily) * 100).toFixed(1) : "0";
          let expiryDateTxt = "—", daysLeft = "∞", isExpired = false;
          if (targetUser.expiryMs) {
            expiryDateTxt = new Date(targetUser.expiryMs).toISOString().split("T")[0];
            const rem = Math.ceil((targetUser.expiryMs - Date.now()) / 86400000);
            daysLeft = rem >= 0 ? rem : 0;
            if (Date.now() > targetUser.expiryMs) isExpired = true;
          }
          let statusCode = "active";
          if (targetUser.isPaused) statusCode = "paused";
          else if (isExpired) statusCode = "expired";
          else if (limitTotal && totalReqs >= limitTotal) statusCode = "limit";
          else if (limitDaily && dailyReqs >= limitDaily) statusCode = "dailyLimit";

          const cleanUrl = new URL(url.href);
          let panelUrlToUse = sysConfig.customPanelUrl;
          if (targetUser.userPanelUrl && targetUser.userPanelUrl.trim()) panelUrlToUse = targetUser.userPanelUrl.trim();
          if (panelUrlToUse) {
            let c = panelUrlToUse;
            if (c.indexOf("http") !== 0) c = "https://" + c;
            try { const cu = new URL(c); cleanUrl.protocol = cu.protocol; cleanUrl.host = cu.host; } catch (e) {}
          }
          cleanUrl.searchParams.delete("flag");
          cleanUrl.searchParams.delete("format");
          cleanUrl.searchParams.delete("type");
          cleanUrl.searchParams.delete("output");
          cleanUrl.searchParams.delete("raw");
          const syncNormal = cleanUrl.href;
          const syncRaw = cleanUrl.href + (cleanUrl.href.indexOf("?") !== -1 ? "&flag=a" : "?flag=a");

          const frag = getActiveFragmentValue();
          const fragHtml = frag ? '<div class="mchip"><span class="cl">Fragment</span><code>' + frag + '</code></div>' : "";
          const logoHtml = sysConfig.customLogo ? '<img src="' + sysConfig.customLogo + '" class="brand-logo" alt="logo">' : "";
          const tags = (targetUser.tags || []).length > 0 ? '<div class="mchip"><span class="cl">Tags</span><span>' + targetUser.tags.join(" · ") + '</span></div>' : "";
          const relayRegion = getRelayRegionInfo(targetUser);
          const relayHtml = relayRegion ? '<div class="mchip relay"><span class="cl">Relay</span><span>' + relayRegion.flag + " " + relayRegion.name + '</span></div>' : "";
          const portsUsed = getEffectivePorts(targetUser, applyIspTemplate(targetUser, "")).slice(0, 8);
          const portsHtml = '<div class="mchip"><span class="cl">Ports</span><code>' + portsUsed.join(" · ") + '</code></div>';

          const rpl = function (s, re, v) { return s.replace(re, function () { return String(v == null ? "" : v); }); };
          html = rpl(html, /__USER_NAME__/g, targetUser.name);
          html = rpl(html, /__USER_ID__/g, targetUser.id);
          html = rpl(html, /__STATUS_CODE__/g, statusCode);
          html = rpl(html, /__TOTAL_GB__/g, totalGb);
          html = rpl(html, /__LIMIT_TOTAL_GB__/g, limitTotalGb);
          html = rpl(html, /__TOTAL_PERCENT__/g, totalPercent + "%");
          html = rpl(html, /__DAILY_GB__/g, dailyGb);
          html = rpl(html, /__LIMIT_DAILY_GB__/g, limitDailyGb);
          html = rpl(html, /__DAILY_PERCENT__/g, dailyPercent + "%");
          html = rpl(html, /__EXPIRY_DATE__/g, expiryDateTxt);
          html = rpl(html, /__DAYS_LEFT__/g, daysLeft);
          html = rpl(html, /__SYNC_NORMAL__/g, syncNormal);
          html = rpl(html, /__SYNC_RAW__/g, syncRaw);
          html = rpl(html, /__PANEL_NAME__/g, sysConfig.name || PANEL_BRAND);
          html = rpl(html, /__META_CHIPS__/g, fragHtml + relayHtml + tags + portsHtml);
          html = rpl(html, /__CUSTOM_LOGO_BLOCK__/g, logoHtml);
          html = rpl(html, /__CURRENT_VERSION__/g, CURRENT_VERSION);
          html = rpl(html, /__OTTER_SVG__/g, OTTER_SVG);
          return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        } catch (e) { return new Response("Failed", { status: 502 }); }
      } else return serveMaintenancePage(request, url);
    }

    if (hasMultiUser && !isValidUser) return new Response("Error", { status: 403 });
    const allowInsecure = url.searchParams.get("insecure") === "true" || url.searchParams.get("allowInsecure") === "true";
    const resHeaders = new Headers();
    resHeaders.set("Cache-Control", "no-store");
    resHeaders.set("Access-Control-Allow-Origin", "*");

    if (isValidUser && targetUser) {
      const idClean = targetUser.id.replace(/-/g, "").toLowerCase();
      const sysU = (sysUsageCache && sysUsageCache.users ? sysUsageCache.users[idClean] : null) || { reqs: 0 };
      const totalReqs = sysU.reqs || 0;
      let limitTotal = 0, expiryMs = 0;
      if (hasMultiUser) { limitTotal = targetUser.limitTotalReq || 0; expiryMs = targetUser.expiryMs || 0; }
      else { limitTotal = sysConfig.limitTotalReq || 0; expiryMs = sysConfig.expiryMs || 0; }
      const usedBytes = Math.floor(totalReqs * (1073741824 / 6000));
      const limitBytes = Math.floor(limitTotal * (1073741824 / 6000));
      const expireSec = expiryMs ? Math.floor(expiryMs / 1000) : 0;
      resHeaders.set("Subscription-UserInfo", "upload=0; download=" + usedBytes + "; total=" + limitBytes + "; expire=" + expireSec);
      const cleanName = encodeURIComponent(targetUser.name);
      resHeaders.set("Content-Disposition", "attachment; filename=\"" + cleanName + "\"; filename*=UTF-8''" + cleanName);
    }

    let isClashYaml = false, isSingboxJson = false, isClashJson = false, isVJson = false, isSurge = false, isLoon = false;
    let flag = (url.searchParams.get("flag") || url.searchParams.get("format") || url.searchParams.get("type") || "").toLowerCase();
    if (flag === "clash" || flag === "yaml" || flag === "meta" || flag === "stash" || flag === "y") isClashYaml = true;
    else if (flag === "b") isClashJson = true;
    else if (flag === "sing" || flag === "singbox" || flag === "sing-box" || flag === "sb" || flag === "s" || flag === "c" || flag === "g") isSingboxJson = true;
    else if (flag === "vjson" || flag === "v") isVJson = true;
    else if (flag === "surge") isSurge = true;
    else if (flag === "loon") isLoon = true;
    else if (flag === "a" || flag === "raw" || flag === "") {
      if (ua.indexOf(getGamma()) !== -1 || ua.indexOf("meta") !== -1 || ua.indexOf("mihomo") !== -1 || ua.indexOf("clash") !== -1) isClashYaml = true;
      else if (ua.indexOf("sing-box") !== -1 || ua.indexOf("singbox") !== -1 || ua.indexOf("karing") !== -1) isSingboxJson = true;
      else if (ua.indexOf("surge") !== -1) isSurge = true;
      else if (ua.indexOf("loon") !== -1) isLoon = true;
    }
    if (isClashYaml) { resHeaders.set("Content-Type", "text/yaml; charset=utf-8"); return new Response(await buildYamlProfile(clientHost, targetSub, allowInsecure, env), { headers: resHeaders }); }
    if (isSingboxJson) { resHeaders.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(await buildSingBoxJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders }); }
    if (isClashJson) { resHeaders.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(await buildClashJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders }); }
    if (isVJson) { resHeaders.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(await buildVJsonProfile(clientHost, targetSub, allowInsecure, env), null, 2), { headers: resHeaders }); }
    if (isSurge) { resHeaders.set("Content-Type", "text/plain; charset=utf-8"); return new Response(await buildSurgeProfile(clientHost, targetSub, allowInsecure), { headers: resHeaders }); }
    if (isLoon) { resHeaders.set("Content-Type", "text/plain; charset=utf-8"); return new Response(await buildLoonProfile(clientHost, targetSub, allowInsecure), { headers: resHeaders }); }
    resHeaders.set("Content-Type", "text/plain; charset=utf-8");
    const raw = await buildUriProfile(clientHost, targetSub, allowInsecure);
    return new Response(safeBtoa(raw), { headers: resHeaders });
  } catch (e) { return new Response("Error", { status: 500 }); }
}

/* ==================== TELEMETRY ==================== */
async function processTelemetryStream(env, ctx, wsRelayIdx, paused) {
  let client, webSocket;
  try {
    const pair = new WebSocketPair();
    const keys = Object.keys(pair);
    client = pair[keys[0]];
    webSocket = pair[keys[1]];
    webSocket.accept();
    webSocket.binaryType = "arraybuffer";
  } catch (e) { return new Response("WebSocket unavailable", { status: 500 }); }
  try {
    if (!paused) startDataPipeSafe(webSocket, env, ctx, wsRelayIdx);
    else { try { webSocket.close(1013, "Paused"); } catch (e) {} }
  } catch (e) { try { webSocket.close(1011, "init"); } catch (ee) {} }
  return new Response(null, { status: 101, webSocket: client });
}
function startDataPipeSafe(webSocket, env, ctx, wsRelayIdx) {
  try { startDataPipe(webSocket, env, ctx, wsRelayIdx).catch(function () { try { webSocket.close(1011, "pipe-error"); } catch (ee) {} }); }
  catch (e) { try { webSocket.close(1011, "sync-error"); } catch (ee) {} }
}
function safeWsSend(ws, data) { try { ws.send(data); return true; } catch (e) { return false; } }
function safeWsClose(ws, code, reason) { try { ws.close(code || 1000, reason || ""); } catch (e) {} }

async function startDataPipe(webSocket, env, ctx, wsRelayIdx) {
  activeConnections++;
  let activeClientHash = null;
  let closed = false;
  webSocket.addEventListener("close", function () {
    closed = true;
    activeConnections--;
    if (activeClientHash) {
      const c = activeConns.get(activeClientHash) || 0;
      if (c > 0) activeConns.set(activeClientHash, c - 1);
    }
  });
  webSocket.addEventListener("error", function () { closed = true; });
  let remoteSocket, dataWriter, isInit = true, queue = Promise.resolve();
  webSocket.addEventListener("message", function (event) {
    queue = queue.then(async function () {
      try {
        if (closed) return;
        if (isInit) {
          isInit = false;
          const a = await parseSensorData(event.data, wsRelayIdx);
          if (a && !closed) safeWsSend(webSocket, new Uint8Array([0, 0]));
        } else if (dataWriter) {
          try { await dataWriter.write(event.data); } catch (e) { safeWsClose(webSocket, 1011, "write-error"); }
        }
      } catch (err) { safeWsClose(webSocket, 1011, "msg-error"); }
    }).catch(function () {});
  });

  async function parseSensorData(bufferData, wsRelayIdx) {
    try {
      const view = new Uint8Array(bufferData);
      let targetAddr = "", targetPort = 0, offset = 0, isModeAlpha = false, activeProfile = null;
      if (view[0] === 0x00) {
        isModeAlpha = true;
        const clientHash = Array.from(view.slice(1, 17)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
        let entry = lookupConfigEntry(clientHash);
        if (entry) {
          activeClientHash = entry.userId.replace(/-/g, "").toLowerCase();
          activeProfile = getAllProfiles().find(function (p) { return p.id.replace(/-/g, "").toLowerCase() === activeClientHash; });
          if (!activeProfile) return false;
          if (entry.relayIp) activeProfile = Object.assign({}, activeProfile, { proxyIp: entry.relayIp });
        } else {
          const decoded = decodeConfigUuid(clientHash);
          if (decoded) activeProfile = getAllProfiles().find(function (p) { return getUserFingerprint(p.id) === decoded.userFingerprint; });
          if (!activeProfile) activeProfile = getAllProfiles().find(function (p) { return p.id.replace(/-/g, "").toLowerCase() === clientHash; });
          if (!activeProfile) return false;
          activeClientHash = activeProfile.id.replace(/-/g, "").toLowerCase();
        }
        try { trackUsage(activeClientHash, 0, env, ctx); } catch (e) {}
        const cur = activeConns.get(activeClientHash) || 0;
        if (activeProfile.connLimit && cur >= activeProfile.connLimit) { safeWsClose(webSocket, 1000, "limit"); return isModeAlpha; }
        activeConns.set(activeClientHash, cur + 1);
        const optLen = view[17], pPos = 18 + optLen + 1;
        targetPort = new DataView(bufferData.slice(pPos, pPos + 2)).getUint16(0);
        const aType = view[pPos + 2];
        let vPos = pPos + 3, aLen = 0;
        if (aType === 1) { aLen = 4; targetAddr = view.slice(vPos, vPos + aLen).join("."); }
        else if (aType === 2) { aLen = view[vPos]; vPos++; targetAddr = new TextDecoder().decode(view.slice(vPos, vPos + aLen)); }
        else if (aType === 3) { aLen = 16; const dv = new DataView(bufferData.slice(vPos, vPos + aLen)); targetAddr = Array.from({ length: 8 }, function (_, i) { return dv.getUint16(i * 2).toString(16); }).join(":"); }
        offset = vPos + aLen;
      } else {
        let ePos = bufferData.byteLength;
        for (let i = 0; i < bufferData.byteLength; i++) if (view[i] === 0x0d && view[i + 1] === 0x0a) { ePos = i; break; }
        const clientHashHex = new TextDecoder().decode(view.slice(0, ePos));
        let entry = lookupConfigEntry(clientHashHex);
        if (entry) {
          activeClientHash = entry.userId.replace(/-/g, "").toLowerCase();
          activeProfile = getAllProfiles().find(function (p) { return p.id.replace(/-/g, "").toLowerCase() === activeClientHash; });
          if (!activeProfile) return false;
          if (entry.relayIp) activeProfile = Object.assign({}, activeProfile, { proxyIp: entry.relayIp });
        } else {
          activeProfile = getAllProfiles().find(function (p) { return getTrojanHash(p.id) === clientHashHex; });
          if (!activeProfile) return false;
          activeClientHash = activeProfile.id.replace(/-/g, "").toLowerCase();
        }
        try { trackUsage(activeClientHash, 0, env, ctx); } catch (e) {}
        const cur = activeConns.get(activeClientHash) || 0;
        if (activeProfile.connLimit && cur >= activeProfile.connLimit) { safeWsClose(webSocket, 1000, "limit"); return isModeAlpha; }
        activeConns.set(activeClientHash, cur + 1);
        let hPos = ePos + 2; hPos++;
        const aType = view[hPos]; hPos++;
        let aLen = 0;
        if (aType === 1) { aLen = 4; targetAddr = view.slice(hPos, hPos + aLen).join("."); }
        else if (aType === 3) { aLen = view[hPos]; hPos++; targetAddr = new TextDecoder().decode(view.slice(hPos, hPos + aLen)); }
        else if (aType === 4) { aLen = 16; const dv = new DataView(bufferData.slice(hPos, hPos + aLen)); targetAddr = Array.from({ length: 8 }, function (_, i) { return dv.getUint16(i * 2).toString(16); }).join(":"); }
        hPos += aLen;
        targetPort = new DataView(bufferData.slice(hPos, hPos + 2)).getUint16(0);
        offset = hPos + 4;
      }

      const isDomain = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(targetAddr) || /^[a-zA-Z0-9-]+$/.test(targetAddr);
      let connectAddr = targetAddr;
      let resolvedIp = null;
      if (isDomain) {
        const dnsUrl = pickDnsFromPool();
        try {
          const dohUrl = new URL(dnsUrl);
          dohUrl.searchParams.set("name", targetAddr);
          dohUrl.searchParams.set("type", "A");
          const r = await fetch(dohUrl.toString(), { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(3000) });
          const j = await r.json();
          if (j.Answer && j.Answer.length > 0) { connectAddr = j.Answer[0].data; resolvedIp = connectAddr; }
        } catch (e) {}
      }

      const isCFIp = function (ip) {
        if (!ip) return false;
        return /^104\.(1[6-9]|2[0-7])\./.test(ip) || /^172\.6[4-7]\./.test(ip) || /^188\.114\./.test(ip)
          || /^197\.234\.24[0-3]\./.test(ip) || /^103\.2[12]\./.test(ip) || /^103\.31\.4\./.test(ip)
          || /^162\.159\./.test(ip) || /^131\.0\.72\./.test(ip) || /^141\.101\./.test(ip)
          || /^108\.162\./.test(ip) || /^190\.93\./.test(ip) || /^198\.41\./.test(ip);
      };
      const isCFProtected = resolvedIp && isCFIp(resolvedIp);

      const pool = buildRelayPool(activeProfile || {});
      const relayDomains = rankRelays(pool.relay);

      let connected = false;
      let usedRelayHost = null;
      const maxRelayTries = Math.min(relayDomains.length, 4);
      for (let a = 0; a < maxRelayTries; a++) {
        const relayHost = relayDomains[a].split(":")[0];
        const relayPort = relayDomains[a].split(":")[1] ? Number(relayDomains[a].split(":")[1]) : 443;
        if (!relayHost || relayHost.length < 4) continue;
        const t0 = Date.now();
        try {
          remoteSocket = connect({ hostname: relayHost, port: relayPort });
          await remoteSocket.opened;
          connected = true;
          usedRelayHost = relayDomains[a];
          recordRelayAttempt(relayDomains[a], true, Date.now() - t0);
          break;
        } catch (e) { recordRelayAttempt(relayDomains[a], false, 0); }
      }

      if (!connected && !isCFProtected) {
        try { remoteSocket = connect({ hostname: connectAddr, port: targetPort }); await remoteSocket.opened; connected = true; } catch (e) {}
      }
      if (!connected) {
        try { remoteSocket = connect({ hostname: connectAddr, port: targetPort }); await remoteSocket.opened; connected = true; } catch (e) {}
      }
      if (!connected) { safeWsClose(webSocket, 1011, "no-connect"); return isModeAlpha; }

      dataWriter = remoteSocket.writable.getWriter();
      if (usedRelayHost) {
        try { await dataWriter.write(bufferData); } catch (e) {}
      } else {
        if (offset < bufferData.byteLength) { try { await dataWriter.write(bufferData.slice(offset)); } catch (e) {} }
      }

      try {
        remoteSocket.readable.pipeTo(new WritableStream({
          write: function (chunk) { if (!closed) safeWsSend(webSocket, chunk); },
          close: function () { safeWsClose(webSocket, 1000, "done"); },
          abort: function () { safeWsClose(webSocket, 1011, "abort"); }
        })).catch(function () { safeWsClose(webSocket, 1000, "pipe"); });
      } catch (e) { safeWsClose(webSocket, 1011, "pipe-setup"); }
      return isModeAlpha;
    } catch (e) { safeWsClose(webSocket, 1011, "parse"); return false; }
  }
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
        if (didChange && ctx && ctx.waitUntil) ctx.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(function () {}));
      }
      if (!sysConfig._migratedV107) {
        try {
          const tmpl = sysConfig.ispTemplates || {};
          for (const k of Object.keys(tmpl)) if (tmpl[k] && tmpl[k].ports === "443") tmpl[k].ports = "";
          if (!Array.isArray(sysConfig.relayIpPresets) || sysConfig.relayIpPresets.length === 0) sysConfig.relayIpPresets = RELAY_IP_PRESETS;
          sysConfig._migratedV107 = true;
          if (ctx && ctx.waitUntil) ctx.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(function () {}));
        } catch (e) {}
      }
      if (!sysConfig._migratedV108) {
        try {
          if (!sysConfig.advanced) sysConfig.advanced = JSON.parse(JSON.stringify(SYSTEM_DEFAULTS.advanced));
          if (sysConfig.inboundConfigs && !sysConfig.inboundConfigs.customInbounds) sysConfig.inboundConfigs.customInbounds = [];
          sysConfig._migratedV108 = true;
          if (ctx && ctx.waitUntil) ctx.waitUntil(cachedD1Put(env, "sys_config", JSON.stringify(sysConfig)).catch(function () {}));
        } catch (e) {}
      }

      let reqPath = url.pathname;
      if (reqPath.endsWith("/") && reqPath.length > 1) reqPath = reqPath.slice(0, -1);

      if (sysConfig.apiRoute === "sub") {
        const legacyPrefix = "/sync", currentPrefix = "/sub";
        if (reqPath === legacyPrefix || reqPath === legacyPrefix + "/") reqPath = currentPrefix;
        else if (reqPath.indexOf(legacyPrefix + "/") === 0) reqPath = currentPrefix + reqPath.slice(legacyPrefix.length);
        if (reqPath === currentPrefix + "/dash" && (request.method === "GET" || request.method === "HEAD")) return Response.redirect(url.origin + "/panel", 301);
      }

      const isPanelPath = reqPath === "/panel";
      const isTgPath = reqPath === "/" + encodeURI(sysConfig.apiRoute) + "/tg";
      if (clientIp && !isPanelPath && !isTgPath) {
        try { if (await isIpBanned(env, clientIp)) return new Response("403 Forbidden", { status: 403 }); } catch (e) {}
      }

      const R = sysConfig.apiRoute;
      const routes = {
        data: "/" + encodeURI(R), panel: "/panel",
        auth: "/" + encodeURI(R) + "/api/auth", logout: "/" + encodeURI(R) + "/api/logout", me: "/" + encodeURI(R) + "/api/me",
        captcha: "/" + encodeURI(R) + "/api/captcha",
        sessions: "/" + encodeURI(R) + "/api/sessions", sync: "/" + encodeURI(R) + "/api/sync",
        tg: "/" + encodeURI(R) + "/tg", syncPanel: "/" + encodeURI(R) + "/tg/sync_panel",
        logs: "/" + encodeURI(R) + "/api/logs", users: "/" + encodeURI(R) + "/api/users", bulkUsers: "/" + encodeURI(R) + "/api/users/bulk",
        stats: "/" + encodeURI(R) + "/api/stats", history: "/" + encodeURI(R) + "/api/history", compare: "/" + encodeURI(R) + "/api/stats/compare",
        anomalies: "/" + encodeURI(R) + "/api/anomalies", update: "/" + encodeURI(R) + "/api/update", apiKeys: "/" + encodeURI(R) + "/api/keys",
        managers: "/" + encodeURI(R) + "/api/managers", nodes: "/" + encodeURI(R) + "/api/nodes", nodeHealth: "/" + encodeURI(R) + "/api/nodes/health",
        groups: "/" + encodeURI(R) + "/api/groups", backup: "/" + encodeURI(R) + "/api/backup", regions: "/" + encodeURI(R) + "/api/regions",
        cleanIpTest: "/" + encodeURI(R) + "/api/cleanip/test", cleanIpResults: "/" + encodeURI(R) + "/api/cleanip/results",
        cronJobs: "/" + encodeURI(R) + "/api/cron", webhooks: "/" + encodeURI(R) + "/api/webhooks", webhookEvents: "/" + encodeURI(R) + "/api/webhooks/events",
        banned: "/" + encodeURI(R) + "/api/banned", crisis: "/" + encodeURI(R) + "/api/crisis", crisisPresets: "/" + encodeURI(R) + "/api/crisis/presets",
        logo: "/" + encodeURI(R) + "/api/logo", ispTemplates: "/" + encodeURI(R) + "/api/isp-templates",
        configExport: "/" + encodeURI(R) + "/api/config/export", configImport: "/" + encodeURI(R) + "/api/config/import",
        broadcast: "/" + encodeURI(R) + "/api/broadcast",
        workflows: "/" + encodeURI(R) + "/api/workflows", workflowActions: "/" + encodeURI(R) + "/api/workflows/actions",
        dnsPool: "/" + encodeURI(R) + "/api/dns-pool", dnsPoolActions: "/" + encodeURI(R) + "/api/dns-pool/actions",
        upstreams: "/" + encodeURI(R) + "/api/upstreams",
        latencyMap: "/" + encodeURI(R) + "/api/latency-map", dpi: "/" + encodeURI(R) + "/api/dpi",
        networkWeather: "/" + encodeURI(R) + "/api/network-weather", suggestions: "/" + encodeURI(R) + "/api/suggestions",
        predictive: "/" + encodeURI(R) + "/api/predictive",
        inbounds: "/" + encodeURI(R) + "/api/inbounds", inboundsActions: "/" + encodeURI(R) + "/api/inbounds/actions",
        advancedSettings: "/" + encodeURI(R) + "/api/advanced",
        relayHealth: "/" + encodeURI(R) + "/api/relay-health",
        relayTest: "/" + encodeURI(R) + "/api/relay-test",
        relayPresets: "/" + encodeURI(R) + "/api/relay-presets",
        portsPresets: "/" + encodeURI(R) + "/api/ports-presets",
        userBulkAction: "/" + encodeURI(R) + "/api/users/bulk-action"
      };

      const isAuthorizedRoute = reqPath === routes.data || reqPath === routes.panel || reqPath === routes.auth
        || reqPath === routes.sync || reqPath === routes.tg || reqPath === routes.syncPanel
        || reqPath === routes.logs || reqPath === routes.captcha
        || reqPath.indexOf("/" + encodeURI(R) + "/api/") === 0;

      if (!isTelemetryStream && !isAuthorizedRoute) return serveMaintenancePage(request, url);

      if (!isTelemetryStream) {
        if (reqPath === routes.panel) {
          const rpl = function (s, re, v) { return s.replace(re, function () { return String(v == null ? "" : v); }); };
          let html = DASHBOARD_HTML;
          html = rpl(html, /__CURRENT_VERSION__/g, CURRENT_VERSION);
          html = rpl(html, /__API_ROUTE__/g, sysConfig.apiRoute);
          html = rpl(html, /__PANEL_NAME__/g, sysConfig.name || PANEL_BRAND);
          html = rpl(html, /__CUSTOM_LOGO__/g, sysConfig.customLogo || "");
          html = rpl(html, /__TITLE_COLOR__/g, sysConfig.customTitleColor || "");
          html = rpl(html, /__OTTER_SVG__/g, OTTER_SVG);
          html = rpl(html, /__CAPTCHA_ENABLED__/g, sysConfig.captchaEnabled === false ? "0" : "1");
          return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": "no-store" } });
        }
        if (reqPath === routes.auth) { if (request.method !== "POST") return new Response("405", { status: 405 }); return await handleAuth(request, url.hostname, ctx, env); }
        if (reqPath === routes.captcha) return await handleCaptcha(request, env);
        if (reqPath === routes.logout) return await handleLogout(request, env);
        if (reqPath === routes.me) return await handleMe(request, env);
        if (reqPath === routes.sessions) return await handleSessions(request, env);
        if (reqPath === routes.sync) {
          if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" } });
          if (request.method !== "POST") return new Response("405", { status: 405 });
          const r = await handleConfigSync(request, env, ctx);
          r.headers.set("Access-Control-Allow-Origin", "*");
          return r;
        }
        if (reqPath === routes.logs) return await handleLogs(request, env);
        if (reqPath === routes.bulkUsers) return await handleBulkUsers(request, env, ctx);
        if (reqPath === routes.userBulkAction) return await handleUserBulkAction(request, env, ctx);
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
        if (reqPath === routes.webhookEvents) return new Response(JSON.stringify({ ok: true, success: true, events: WEBHOOK_EVENTS }), { headers: { "Content-Type": "application/json" } });
        if (reqPath === routes.banned) return await handleBannedApi(request, env, ctx);
        if (reqPath === routes.crisis) return await handleCrisisApi(request, env, ctx);
        if (reqPath === routes.crisisPresets) return new Response(JSON.stringify({ ok: true, success: true, presets: sysConfig.crisisPresets || [] }), { headers: { "Content-Type": "application/json" } });
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
        if (reqPath === routes.latencyMap) return await handleLatencyMap(request, env, ctx);
        if (reqPath === routes.dpi) return await handleDpiDetection(request, env);
        if (reqPath === routes.networkWeather) return await handleNetworkWeather(request, env);
        if (reqPath === routes.suggestions) return await handleSuggestions(request, env);
        if (reqPath === routes.predictive) return await handlePredictive(request, env);
        if (reqPath === routes.inbounds) return await handleInboundsApi(request, env, ctx);
        if (reqPath === routes.inboundsActions) return await handleInboundsActions(request, env, ctx);
        if (reqPath === routes.advancedSettings) return await handleAdvancedApi(request, env, ctx);
        if (reqPath === routes.relayHealth) return await handleRelayHealth(request, env);
        if (reqPath === routes.relayTest) return await handleRelayTest(request, env, ctx);
        if (reqPath === routes.relayPresets) return new Response(JSON.stringify({ ok: true, success: true, presets: sysConfig.relayIpPresets || RELAY_IP_PRESETS }), { headers: { "Content-Type": "application/json" } });
        if (reqPath === routes.portsPresets) return new Response(JSON.stringify({ ok: true, success: true, https: CF_HTTPS_PORTS, http: CF_HTTP_PORTS, all: CF_ALL_PORTS }), { headers: { "Content-Type": "application/json" } });
        if (reqPath === routes.syncPanel) { if (request.method !== "POST") return new Response("405", { status: 405 }); return await handleSyncPanel(request, env, ctx); }
        if (reqPath === routes.tg) { if (request.method !== "POST") return new Response("405", { status: 405 }); return await handleTelegramWebhook(request, env, url.hostname, ctx); }
        if (reqPath === routes.data) return await handleSubscription(request, url, env, ctx);
      }

      if (isTelemetryStream) {
        try {
          if (sysConfig.isPaused) return await processTelemetryStream(env, ctx, -1, true);
          let wsRelayIdx = -1;
          try { const rp = url.searchParams.get("ri"); if (rp !== null) wsRelayIdx = parseInt(rp, 10); } catch (e) {}
          if (wsRelayIdx < 0) { try { const ls = url.pathname.split("/").pop(); if (ls) { const n = parseInt(ls, 10); if (!isNaN(n) && n >= 0) wsRelayIdx = n; } } catch (e) {} }
          if (wsRelayIdx < 0) { try { const ls = url.pathname.split("/").pop(); if (ls) { const d = JSON.parse(atob(ls)); if (typeof d.relayIdx === "number") wsRelayIdx = d.relayIdx; } } catch (e) {} }
          return await processTelemetryStream(env, ctx, wsRelayIdx, false);
        } catch (wsErr) {
          try {
            const pair = new WebSocketPair();
            const keys = Object.keys(pair);
            const c = pair[keys[0]];
            const s = pair[keys[1]];
            s.accept();
            try { s.close(1011, "init-error"); } catch (e) {}
            return new Response(null, { status: 101, webSocket: c });
          } catch (e) { return new Response("WS Error", { status: 500 }); }
        }
      }
      return new Response(null, { status: 404 });
    } catch (err) {
      try { const url = new URL(request.url); return await serveMaintenancePage(request, url); }
      catch (e) { return new Response("Error", { status: 500 }); }
    }
  },
  async scheduled(event, env, ctx) {
    try {
      await loadSysConfig(env, ctx);
      await ensureRootManager();
      try { await cleanupExpiredSessions(env); } catch (e) {}
      try { await runDueCronJobs(env, ctx); } catch (e) {}
      if (sysConfig.autoCleanIpTest && Date.now() - lastCleanIpTest > 3600 * 1000) { try { await runCleanIpTest(env); } catch (e) {} }
      if (!sysConfig.autoResetCycles) sysConfig.autoResetCycles = {};
      for (const userId in sysConfig.autoResetCycles) {
        const cycle = sysConfig.autoResetCycles[userId];
        if (!cycle || !cycle.type || cycle.type === "none") continue;
        const elapsed = Date.now() - (cycle.lastReset || 0);
        let shouldReset = false;
        if (cycle.type === "daily" && elapsed > 86400000) shouldReset = true;
        else if (cycle.type === "weekly" && elapsed > 604800000) shouldReset = true;
        else if (cycle.type === "monthly" && elapsed > 2592000000) shouldReset = true;
        if (shouldReset) {
          const c = userId.replace(/-/g, "").toLowerCase();
          if (sysUsageCache.users && sysUsageCache.users[c]) { sysUsageCache.users[c].reqs = 0; sysUsageCache.users[c].dReqs = 0; }
          cycle.lastReset = Date.now();
        }
      }
      await cachedD1Put(env, "sys_usage", JSON.stringify(sysUsageCache));
      await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
      if (sysConfig.cfUsageAlert && sysConfig.cfUsageAlert.enabled && sysConfig.cfAccountId && sysConfig.cfApiToken) {
        try {
          const reqs = await fetchCloudflareUsage(sysConfig.cfAccountId, sysConfig.cfApiToken);
          if (reqs !== null) {
            const pct = (reqs / 100000) * 100;
            if (pct >= (sysConfig.cfUsageAlert.thresholdPct || 80) && Date.now() - (sysConfig.cfUsageAlert.lastAlert || 0) > 6 * 3600 * 1000) {
              sysConfig.cfUsageAlert.lastAlert = Date.now();
              if (sysConfig.tgToken && (sysConfig.tgAdminId || sysConfig.tgChatId)) {
                fetch("https://api.telegram.org/bot" + sysConfig.tgToken + "/sendMessage", {
                  method: "POST", headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ chat_id: sysConfig.tgAdminId || sysConfig.tgChatId, text: "⚠️ <b>CF Usage Alert</b>\n\nمصرف به " + pct.toFixed(1) + "% رسید.", parse_mode: "HTML" }),
                  signal: AbortSignal.timeout(8000)
                }).catch(function () {});
              }
            }
            await cachedD1Put(env, "sys_config", JSON.stringify(sysConfig));
          }
        } catch (e) {}
      }
      if ((Date.now() - (sysConfig.nodeFailoverState.lastCheck || 0)) > (sysConfig.autoFailover && sysConfig.autoFailover.healthCheckIntervalMin ? sysConfig.autoFailover.healthCheckIntervalMin : 15) * 60 * 1000) {
        sysConfig.nodeFailoverState.lastCheck = Date.now();
        try { await runNodeHealthCheck(env); } catch (e) {}
      }
    } catch (e) {}
  }
};
const DASHBOARD_HTML = String.raw`<!DOCTYPE html>
<html lang="fa" dir="rtl"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="format-detection" content="telephone=no">
<meta name="theme-color" content="#04040a">
<title>__PANEL_NAME__ · v__CURRENT_VERSION__</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%A6%A6%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
/* ══════════ TOKENS ══════════ */
:root{
  --ios-blue:#007AFF;--ios-indigo:#5856D6;--ios-purple:#AF52DE;--ios-pink:#FF2D55;
  --ios-red:#FF3B30;--ios-orange:#FF9500;--ios-yellow:#FFCC00;--ios-green:#34C759;
  --ios-teal:#5AC8FA;--ios-mint:#00C7BE;
  --g1:rgba(142,142,147,.2);--g2:rgba(142,142,147,.32);--g3:rgba(142,142,147,.46);
  --g4:rgba(142,142,147,.6);--g5:rgba(142,142,147,.75);--g6:rgba(142,142,147,.9);
  --mat-ultra:rgba(28,28,30,.42);--mat-thin:rgba(28,28,30,.56);
  --mat-reg:rgba(28,28,30,.72);--mat-thick:rgba(28,28,30,.86);--mat-chrome:rgba(28,28,30,.94);
  --blur-reg:blur(30px) saturate(180%);--blur-thick:blur(50px) saturate(180%);--blur-chrome:blur(80px) saturate(200%);
  --bglass:rgba(255,255,255,.14);--bglass-hi:rgba(255,255,255,.24);
  --bg:#04040a;--text:#fafaff;--text-2:#b8b8cc;--muted:#7d7d96;--muted-2:#4d4d66;
  --violet:#8b5cf6;--violet-2:#a78bfa;--cyan:#06b6d4;--pink:#ec4899;
  --ok:#10b981;--warn:#f59e0b;--danger:#f43f5e;--info:#38bdf8;
  --grad:linear-gradient(135deg,#8b5cf6 0%,#d946ef 48%,#06b6d4 100%);
  --spring-gentle:cubic-bezier(.25,1,.5,1);
  --spring-bouncy:cubic-bezier(.34,1.56,.64,1);
  --spring-snappy:cubic-bezier(.4,0,.2,1);
  --spring-smooth:cubic-bezier(.22,1,.36,1);
  --r-xs:6px;--r-sm:10px;--r-md:14px;--r-lg:18px;--r-xl:22px;--r-2xl:28px;--r-c:34px;
  --sh-1:0 1px 3px rgba(0,0,0,.3);--sh-2:0 4px 12px rgba(0,0,0,.4);
  --sh-3:0 12px 32px rgba(0,0,0,.5);--sh-4:0 24px 60px rgba(0,0,0,.6);
  --sh-glass:0 20px 60px -20px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.08);
  --safe-top:env(safe-area-inset-top,0px);--safe-bottom:env(safe-area-inset-bottom,0px);
  --safe-left:env(safe-area-inset-left,0px);--safe-right:env(safe-area-inset-right,0px);
}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;-webkit-touch-callout:none;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility;-webkit-text-size-adjust:100%;font-family:'Vazirmatn',-apple-system,'SF Pro Display',system-ui,sans-serif}
html,body{height:100%;overscroll-behavior:none;-webkit-overflow-scrolling:touch;overflow-x:hidden}
body{background:var(--bg);color:var(--text);min-height:100vh;line-height:1.55;letter-spacing:-.005em;padding-top:var(--safe-top);padding-bottom:var(--safe-bottom);padding-left:var(--safe-left);padding-right:var(--safe-right)}
.mono,code,.mc2{font-family:'JetBrains Mono',ui-monospace,monospace!important}
input,select,textarea{font-size:16px!important}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}

/* ══════════ BEAUTIFUL iOS SCROLLBAR ══════════ */
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:rgba(255,255,255,.03);border-radius:10px}
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,rgba(0,122,255,.65),rgba(88,86,214,.65));border-radius:10px;border:2px solid transparent;background-clip:content-box;transition:background .3s}
::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,rgba(0,122,255,.95),rgba(88,86,214,.95));background-clip:content-box}
::-webkit-scrollbar-thumb:active{background:linear-gradient(180deg,#007AFF,#5856D6);background-clip:content-box}
::-webkit-scrollbar-corner{background:transparent}
*{scrollbar-width:thin;scrollbar-color:rgba(0,122,255,.6) rgba(255,255,255,.03)}
::-webkit-scrollbar-button{display:none}
::selection{background:rgba(0,122,255,.4);color:#fff}

/* ══════════ BACKGROUND ══════════ */
.bgA{position:fixed;inset:0;z-index:-4;pointer-events:none;overflow:hidden;contain:strict}
.bgA span{position:absolute;border-radius:50%;filter:blur(120px);opacity:.5;will-change:transform}
.bgA .b1{width:820px;height:820px;top:-40%;right:-20%;background:radial-gradient(circle,rgba(88,86,214,.6),transparent 65%);animation:aur1 32s ease-in-out infinite}
.bgA .b2{width:700px;height:700px;bottom:-30%;left:-18%;background:radial-gradient(circle,rgba(90,200,250,.5),transparent 65%);animation:aur2 36s ease-in-out infinite}
.bgA .b3{width:520px;height:520px;top:38%;left:34%;background:radial-gradient(circle,rgba(255,45,85,.4),transparent 70%);animation:aur1 44s ease-in-out infinite}
@keyframes aur1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-80px,60px) scale(1.12)}}
@keyframes aur2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(70px,-50px) scale(1.15)}}
.bgG{position:fixed;inset:0;z-index:-3;pointer-events:none;background-image:linear-gradient(rgba(139,92,246,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(139,92,246,.03) 1px,transparent 1px);background-size:64px 64px;-webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,black,transparent 88%);mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,black,transparent 88%)}
@media(prefers-reduced-motion:reduce){.bgA span{animation:none!important}}

/* ══════════ ICONS ══════════ */
.icn{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;line-height:0;vertical-align:middle}
.icn svg{display:block;width:1em;height:1em;stroke-width:1.85;stroke:currentColor;fill:none;stroke-linecap:round;stroke-linejoin:round}

/* ══════════ LOGIN v3.0 ══════════ */
.lp{position:fixed;inset:0;display:flex;z-index:100;background:#000;transition:opacity .5s var(--spring-smooth);overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;-webkit-overflow-scrolling:touch}
.lp.hide{opacity:0;pointer-events:none;overflow:hidden}
.lp::before{content:"";position:absolute;inset:-50%;background:radial-gradient(circle at 20% 30%,rgba(88,86,214,.5),transparent 40%),radial-gradient(circle at 80% 20%,rgba(175,82,222,.4),transparent 40%),radial-gradient(circle at 50% 80%,rgba(90,200,250,.35),transparent 40%),radial-gradient(circle at 90% 70%,rgba(255,45,85,.3),transparent 40%);filter:blur(80px);animation:aurShift 24s ease-in-out infinite;z-index:0;pointer-events:none}
@keyframes aurShift{0%,100%{transform:translate(0,0) rotate(0deg) scale(1)}33%{transform:translate(5%,-3%) rotate(120deg) scale(1.05)}66%{transform:translate(-3%,5%) rotate(240deg) scale(.98)}}
.lp::after{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");opacity:.035;pointer-events:none;z-index:1}
.lp-l{flex:1.15;position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;padding:60px 50px;z-index:2;min-height:100vh}
.lp-lc{position:relative;z-index:2;max-width:520px;animation:slideR .9s var(--spring-smooth) both}
@keyframes slideR{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
.lp-badge{display:inline-flex;align-items:center;gap:8px;padding:7px 15px;border-radius:999px;background:rgba(0,122,255,.15);border:1px solid rgba(0,122,255,.35);font-size:11px;font-weight:800;color:#a5d8ff;letter-spacing:.9px;margin-bottom:24px;text-transform:uppercase}
.lp-badge .dot{width:7px;height:7px;border-radius:50%;background:#34C759;box-shadow:0 0 10px #34C759;animation:pdot 2s infinite}
@keyframes pdot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(.85)}}
.lp-t1{font-size:50px;font-weight:900;letter-spacing:-.03em;line-height:1.05;margin-bottom:16px}
.tg{background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.lp-sub{font-size:14.5px;color:var(--text-2);margin-bottom:28px;line-height:1.7;font-weight:500}
.lp-feats{display:grid;grid-template-columns:1fr 1fr;gap:11px;margin-top:28px}
.lp-feat{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);transition:all .25s var(--spring-snappy);font-size:12px;font-weight:700}
.lp-feat:hover{background:rgba(0,122,255,.1);border-color:rgba(0,122,255,.4);transform:translateY(-2px)}
.lp-feat .em{font-size:17px}
.lp-r{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 24px;z-index:2;min-height:100vh}
.lp-card{width:100%;max-width:440px;padding:44px 36px 34px;border-radius:var(--r-c);background:linear-gradient(160deg,var(--mat-thin),rgba(10,10,22,.85));backdrop-filter:var(--blur-thick);-webkit-backdrop-filter:var(--blur-thick);border:1px solid var(--bglass);box-shadow:var(--sh-glass);position:relative;overflow:hidden;animation:cardIn .7s var(--spring-bouncy) both;margin:auto}
@keyframes cardIn{from{opacity:0;transform:translateY(40px) scale(.94)}to{opacity:1;transform:translateY(0) scale(1)}}
.lp-card::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(135deg,rgba(255,255,255,.25) 0%,rgba(255,255,255,.05) 50%,rgba(255,255,255,.2) 100%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.lp-logo{width:100px;height:100px;margin:0 auto 20px;position:relative;display:flex;align-items:center;justify-content:center;animation:floatOtter 5s ease-in-out infinite}
@keyframes floatOtter{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-8px) rotate(2deg)}}
.lp-logo::before{content:"";position:absolute;inset:-8px;border-radius:50%;background:conic-gradient(from 0deg,rgba(88,86,214,.8),rgba(175,82,222,.8),rgba(90,200,250,.8),rgba(255,45,85,.8),rgba(88,86,214,.8));animation:spinB 8s linear infinite;filter:blur(20px);opacity:.7}
.lp-logo::after{content:"";position:absolute;inset:10px;border-radius:50%;background:radial-gradient(circle at 30% 30%,rgba(88,86,214,.3),#0a0a16)}
@keyframes spinB{to{transform:rotate(360deg)}}
.lp-logo svg,.lp-logo img{position:relative;z-index:2;width:78px;height:78px;border-radius:24px;object-fit:cover;filter:drop-shadow(0 0 28px rgba(88,86,214,.85))}
.lp-name{text-align:center;font-size:24px;font-weight:900;letter-spacing:-.5px;margin-bottom:3px}
.lp-tag{text-align:center;font-size:10.5px;color:var(--muted);font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:22px}
.lp-wel{text-align:center;margin-bottom:20px}
.lp-wel h2{font-size:18px;font-weight:800;margin-bottom:5px}
.lp-wel p{font-size:12px;color:var(--text-2)}
.lp-err{display:none;padding:11px 13px;border-radius:13px;background:rgba(255,59,48,.1);border:1px solid rgba(255,59,48,.32);color:#fda4af;font-size:12.5px;margin-bottom:14px;text-align:center;font-weight:600}
.lp-err.on{display:block;animation:shk .4s}
@keyframes shk{0%,100%{transform:translateX(0)}25%{transform:translateX(-8px)}75%{transform:translateX(8px)}}
.lp-float{position:relative;margin-bottom:14px}
.lp-float input{width:100%;padding:22px 16px 10px 16px;border-radius:var(--r-md);background:rgba(8,8,20,.6);border:1.5px solid var(--bglass);color:var(--text);font-size:16px;font-weight:500;outline:none;transition:all .25s var(--spring-snappy)}
.lp-float input:focus{border-color:rgba(0,122,255,.75);background:rgba(8,8,20,.85);box-shadow:0 0 0 4px rgba(0,122,255,.15)}
.lp-float label{position:absolute;right:16px;top:50%;transform:translateY(-50%);font-size:15px;color:var(--g4);font-weight:500;pointer-events:none;transition:all .22s var(--spring-snappy)}
.lp-float input:focus+label,.lp-float input:not(:placeholder-shown)+label{top:14px;font-size:11px;color:var(--ios-blue);font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.lp-cap{padding:13px 15px;border-radius:var(--r-md);background:rgba(0,122,255,.08);border:1.5px solid rgba(0,122,255,.3);margin-bottom:14px;display:none}
.lp-cap.on{display:block}
.lp-cap-h{display:flex;align-items:center;justify-content:space-between;margin-bottom:9px;gap:10px}
.lp-cap-q{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:800;color:#a5d8ff;letter-spacing:.5px;direction:ltr;text-align:left;flex:1;min-width:0;padding:4px 0}
.lp-cap-r{width:32px;height:32px;border-radius:9px;background:rgba(0,122,255,.18);border:1px solid rgba(0,122,255,.4);color:#a5d8ff;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .2s;flex-shrink:0;font-family:inherit}
.lp-cap-r:active{transform:scale(.94)}
.lp-cap-i{width:100%;padding:11px 14px;border-radius:11px;background:rgba(4,4,12,.65);border:1.5px solid var(--bglass);color:var(--text);font-size:16px;font-weight:600;outline:none;text-align:center;font-family:'JetBrains Mono',monospace;direction:ltr;letter-spacing:3px;transition:border-color .2s}
.lp-cap-i:focus{border-color:rgba(0,122,255,.7);background:rgba(4,4,12,.9)}
.lp-bio{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;margin:12px 0;font-size:12px;color:var(--g5);font-weight:500}
.lp-bio svg{width:20px;height:20px;stroke:var(--ios-blue);fill:none;stroke-width:1.75}
.lp-btn{width:100%;padding:16px;border-radius:var(--r-md);font-weight:700;font-size:17px;cursor:pointer;border:none;background:var(--ios-blue);color:#fff;box-shadow:0 8px 24px -8px rgba(0,122,255,.6);letter-spacing:-.2px;transition:all .15s var(--spring-snappy);position:relative;overflow:hidden;font-family:inherit}
.lp-btn:active{transform:scale(.97);background:#0066DD}
.lp-btn:disabled{opacity:.5;cursor:not-allowed}
.lp-foot{margin-top:20px;padding-top:15px;border-top:1px solid rgba(255,255,255,.07);text-align:center;font-size:10.5px;color:var(--muted-2);letter-spacing:.5px;line-height:1.9}
.lp-foot strong{color:var(--violet-2)}
@media(max-width:960px){
  .lp{align-items:flex-end}
  .lp-l{display:none}
  .lp-r{flex:1;width:100%;padding:0;align-items:flex-end;min-height:100vh}
  .lp-card{max-width:100%;width:100%;border-radius:34px 34px 0 0;padding:32px 24px calc(24px + var(--safe-bottom));padding-top:44px;animation:sheetUp .5s var(--spring-snappy) both;margin:auto auto 0}
  @keyframes sheetUp{from{transform:translateY(100%)}to{transform:translateY(0)}}
  .lp-card::after{content:"";position:absolute;top:12px;left:50%;transform:translateX(-50%);width:40px;height:5px;border-radius:3px;background:var(--g3)}
}

/* ══════════ SHELL / SIDEBAR — FIXED CLIPPING ══════════ */
.sh{display:none;min-height:100vh}
.sh.on{display:block}
.sb{
  position:fixed;top:12px;right:12px;bottom:12px;width:280px;
  background:linear-gradient(180deg,var(--mat-thick),var(--mat-chrome));
  backdrop-filter:var(--blur-thick);-webkit-backdrop-filter:var(--blur-thick);
  border:1px solid var(--bglass-hi);border-radius:var(--r-2xl);
  padding:0;z-index:50;
  transition:transform .45s var(--spring-smooth);
  box-shadow:var(--sh-4);
  display:flex;flex-direction:column;
  overflow:hidden;
}
/* ⚡ FIX: brand ثابت در بالا، nav مستقل اسکرول می‌شود */
.sb-brand-wrapper{
  flex-shrink:0;
  padding:14px 11px 0 11px;
}
.sb-nav-scroll{
  flex:1 1 auto;
  min-height:0;
  overflow-y:auto;
  overflow-x:hidden;
  padding:0 11px;
  -webkit-overflow-scrolling:touch;
  overscroll-behavior:contain;
}
.sb-nav-scroll::-webkit-scrollbar{width:5px}
.sb-nav-scroll::-webkit-scrollbar-track{background:transparent}
.sb-nav-scroll::-webkit-scrollbar-thumb{background:linear-gradient(180deg,rgba(0,122,255,.5),rgba(88,86,214,.5));border-radius:5px}
.sb-bottom-wrapper{
  flex-shrink:0;
  padding:0 11px 14px 11px;
}
.brand{
  padding:16px 12px 14px;margin-bottom:8px;
  background:linear-gradient(150deg,rgba(0,122,255,.16),rgba(90,200,250,.09));
  border-radius:18px;border:1px solid rgba(0,122,255,.25);
  position:relative;overflow:hidden;text-align:center;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-height:130px;
  flex-shrink:0;
}
.brand::before{content:"";position:absolute;top:-60px;right:-60px;width:180px;height:180px;background:radial-gradient(circle,rgba(0,122,255,.5),transparent 70%);pointer-events:none;z-index:0}
.brand #brandLogo{
  position:relative;z-index:1;
  width:52px;height:52px;
  margin:0 auto 10px;
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;
}
.brand #brandLogo svg,.brand #brandLogo img{
  width:52px!important;height:52px!important;
  display:block;border-radius:15px;object-fit:cover;
  filter:drop-shadow(0 4px 12px rgba(0,122,255,.5));
}
.brand .nm{font-size:14px;font-weight:900;letter-spacing:-.3px;position:relative;z-index:1;line-height:1.3;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 4px;width:100%}
.brand .tg2{font-size:9px;color:var(--text-2);margin-top:5px;letter-spacing:1.5px;text-transform:uppercase;font-weight:800;position:relative;z-index:1;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;width:100%;padding:0 4px}
.ng{font-size:9.5px;color:var(--muted-2);font-weight:800;letter-spacing:1.6px;text-transform:uppercase;padding:12px 10px 5px;opacity:.85}
.nv{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:13px;color:var(--text-2);font-weight:600;font-size:12.5px;cursor:pointer;transition:all .18s var(--spring-snappy);border:1px solid transparent;text-decoration:none;position:relative;margin-bottom:2px;user-select:none;touch-action:manipulation}
.nv .icn{font-size:16px}
.nv:hover{color:var(--text);background:rgba(255,255,255,.05)}
.nv:active{transform:scale(.98)}
.nv.on{color:#fff;background:linear-gradient(90deg,rgba(0,122,255,.24),rgba(90,200,250,.06));border-color:rgba(0,122,255,.35)}
.nv.on .icn{color:#a5d8ff}
.nv.on::before{content:"";position:absolute;right:0;top:9px;bottom:9px;width:3px;background:var(--ios-blue);border-radius:3px}
.dvd{height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.09),transparent);margin:11px 0}
.stp{display:flex;align-items:center;gap:9px;padding:10px 12px;border-radius:13px;background:var(--mat-thin);border:1px solid var(--bglass);font-size:11.5px;font-weight:600}
.pd{width:8px;height:8px;border-radius:50%;background:var(--ios-green);box-shadow:0 0 12px var(--ios-green);animation:pdot 2s infinite;flex-shrink:0}
.lgb{width:100%;margin-top:9px;padding:11px 15px;border-radius:13px;background:linear-gradient(135deg,rgba(255,59,48,.1),rgba(255,45,85,.07));border:1px solid rgba(255,59,48,.26);color:#fda4af;font-size:12.5px;font-weight:800;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:9px;font-family:inherit}
.lgb:active{transform:scale(.97)}
.mn{margin-right:300px;padding:24px 24px 44px;min-height:100vh;transition:margin .4s var(--spring-smooth);max-width:1620px;position:relative;z-index:1}
@media(max-width:1100px){.mn{margin-right:0;padding:74px 14px 30px}.sb{transform:translateX(calc(100% + 24px));width:296px}.sb.on{transform:translateX(0)}}
.mmb{display:none;position:fixed;top:calc(16px + var(--safe-top));right:16px;z-index:60;width:46px;height:46px;border-radius:13px;background:var(--mat-thick);backdrop-filter:var(--blur-reg);-webkit-backdrop-filter:var(--blur-reg);border:1px solid var(--bglass-hi);align-items:center;justify-content:center;cursor:pointer;color:var(--text);box-shadow:var(--sh-3);transition:transform .15s var(--spring-snappy)}
.mmb:active{transform:scale(.94)}
.mmb svg{width:22px;height:22px;stroke-width:2.2;stroke:currentColor;fill:none;stroke-linecap:round;stroke-linejoin:round;pointer-events:none}
@media(max-width:1100px){.mmb{display:flex}}
.ov{position:fixed;inset:0;background:rgba(4,4,10,.7);backdrop-filter:blur(4px);z-index:40;opacity:0;pointer-events:none;transition:opacity .28s}
.ov.on{opacity:1;pointer-events:auto}

/* ══════════ HEADER / BUTTONS ══════════ */
.ph{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.ph-t{flex:1;min-width:200px}
.pt{font-size:23px;font-weight:900;letter-spacing:-.5px;display:flex;align-items:center;gap:10px;line-height:1.2}
.pt .icn{font-size:19px;color:var(--violet-2)}
.ps{color:var(--text-2);font-size:12px;margin-top:5px;font-weight:500}
.ph-a{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.blive{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:10px;background:rgba(52,199,89,.11);color:#6ee7b7;font-size:9.5px;font-weight:800;border:1px solid rgba(52,199,89,.3);letter-spacing:.5px}
.blive::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--ios-green);box-shadow:0 0 8px var(--ios-green);animation:pdot 2s infinite}
.btn{padding:9px 14px;border-radius:12px;font-weight:700;font-size:12px;cursor:pointer;border:none;transition:all .15s var(--spring-snappy);display:inline-flex;align-items:center;justify-content:center;gap:6px;white-space:nowrap;user-select:none;font-family:inherit;touch-action:manipulation}
.btn .icn{font-size:13px}
.btn:active{transform:scale(.96)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.bp{background:var(--ios-blue);color:#fff;box-shadow:0 8px 20px -8px rgba(0,122,255,.6)}
.bp:hover{box-shadow:0 12px 28px -8px rgba(0,122,255,.8)}
.bg2{background:var(--mat-thin);color:var(--text);border:1px solid var(--bglass)}
.bg2:hover{background:var(--mat-reg);border-color:var(--bglass-hi)}
.bd{background:rgba(255,59,48,.1);color:#fda4af;border:1px solid rgba(255,59,48,.28)}
.bd:hover{background:rgba(255,59,48,.2);color:#fff}
.bok{background:rgba(52,199,89,.12);color:#6ee7b7;border:1px solid rgba(52,199,89,.3)}
.bs{padding:7px 11px;font-size:11px;border-radius:10px}
.bs .icn{font-size:12px}
.ibtn{padding:6px!important;min-width:30px;width:30px;height:30px;aspect-ratio:1}

/* ══════════ BENTO ══════════ */
.bento{display:grid;grid-template-columns:repeat(12,1fr);gap:12px;margin-bottom:20px}
.bcard{position:relative;padding:20px;border-radius:var(--r-xl);background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.02));backdrop-filter:var(--blur-reg);-webkit-backdrop-filter:var(--blur-reg);border:1px solid var(--bglass);box-shadow:var(--sh-2);overflow:hidden;transition:transform .3s var(--spring-bouncy),border-color .3s}
.bcard:hover{transform:translateY(-3px);border-color:var(--bglass-hi)}
.bcard:active{transform:scale(.98)}
.bcard.s3{grid-column:span 3}
.bcard.s4{grid-column:span 4}
.bcard.s6{grid-column:span 6}
.bcard.s8{grid-column:span 8}
.bcard.s12{grid-column:span 12}
.bhero{padding:22px 20px;background:linear-gradient(135deg,rgba(0,122,255,.15) 0%,rgba(88,86,214,.1) 50%,rgba(175,82,222,.08) 100%);border-color:rgba(0,122,255,.3)}
.blabel{font-size:11px;font-weight:700;color:var(--g5);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.bvalue{font-size:32px;font-weight:800;letter-spacing:-1.2px;line-height:1;font-variant-numeric:tabular-nums;color:#fff}
.bvalue small{font-size:14px;color:var(--g5);font-weight:500;letter-spacing:0}
.bpulse{width:8px;height:8px;border-radius:50%;background:var(--ios-green);box-shadow:0 0 12px var(--ios-green);animation:pdot 2s infinite;display:inline-block;margin-right:4px}
@media(max-width:700px){
  .bento{grid-template-columns:repeat(2,1fr)}
  .bcard.s3,.bcard.s4{grid-column:span 1}
  .bcard.s6,.bcard.s8{grid-column:span 2}
  .bcard.s12{grid-column:span 2}
  .bvalue{font-size:26px}
  .bcard{padding:16px}
}

/* ══════════ CARDS / CHART ══════════ */
.gl{background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.012));backdrop-filter:var(--blur-reg);-webkit-backdrop-filter:var(--blur-reg);border:1px solid var(--bglass);border-radius:var(--r-xl);position:relative;overflow:hidden}
.cc{padding:20px;border-radius:var(--r-xl);background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.012));backdrop-filter:var(--blur-reg);-webkit-backdrop-filter:var(--blur-reg);border:1px solid var(--bglass)}
.ct{font-size:14px;font-weight:800;margin-bottom:15px;display:flex;align-items:center;gap:10px}
.ct .icn{font-size:16px;color:var(--violet-2)}
.cw{position:relative;height:260px;padding:5px}
.card2{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:11px}
.nc{padding:15px;border-radius:var(--r-lg);background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.012));border:1px solid var(--bglass);transition:all .22s var(--spring-snappy)}
.nc:hover{border-color:var(--bglass-hi);transform:translateY(-2px)}

/* ══════════ TABLE ══════════ */
.tw{overflow-x:auto;border-radius:var(--r-lg);background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.01));border:1px solid var(--bglass);padding:5px;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:right;padding:13px 11px;color:var(--text-2);font-weight:800;font-size:10px;text-transform:uppercase;letter-spacing:.9px;border-bottom:1px solid var(--bglass);white-space:nowrap}
td{padding:13px 11px;border-bottom:1px solid var(--bglass);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,122,255,.045)}

/* ══════════ BADGES / PROGRESS ══════════ */
.bdg{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.15px;white-space:nowrap}
.bdg .icn{font-size:10px}
.bok-b{background:rgba(52,199,89,.13);color:#6ee7b7;border:1px solid rgba(52,199,89,.3)}
.bw-b{background:rgba(255,149,0,.13);color:#fcd34d;border:1px solid rgba(255,149,0,.3)}
.bd-b{background:rgba(255,59,48,.13);color:#fda4af;border:1px solid rgba(255,59,48,.3)}
.bi-b{background:rgba(90,200,250,.13);color:#7dd3fc;border:1px solid rgba(90,200,250,.3)}
.bm-b{background:rgba(142,142,147,.1);color:#cbd5e1;border:1px solid var(--bglass-hi)}
.prg{height:6px;border-radius:999px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:7px}
.prg>div{height:100%;background:var(--grad);border-radius:999px;transition:width .7s var(--spring-smooth)}
.prg.w>div{background:linear-gradient(90deg,#FF9500,#f97316)}
.prg.d>div{background:linear-gradient(90deg,#FF3B30,#dc2626)}
.tm{display:inline-block;padding:2.5px 8px;border-radius:7px;background:rgba(0,122,255,.16);color:#a5d8ff;font-size:9px;font-weight:800;margin-left:4px}

/* ══════════ FORMS ══════════ */
.fg{display:grid;gap:13px}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:13px}
@media(max-width:600px){.fr{grid-template-columns:1fr}}
.fd{display:flex;flex-direction:column;gap:6px}
.fd label{font-size:11.5px;font-weight:700;color:var(--text-2);display:flex;align-items:center;gap:6px}
.fd label .icn{font-size:12px;color:var(--violet-2)}
.fd input,.fd select,.fd textarea{width:100%;padding:11px 13px;border-radius:13px;background:rgba(8,8,20,.55);border:1.5px solid var(--bglass);color:var(--text);font-size:13px;font-weight:500;outline:none;transition:all .22s var(--spring-snappy);font-family:inherit}
.fd input:focus,.fd select:focus,.fd textarea:focus{border-color:rgba(0,122,255,.7);background:rgba(8,8,20,.85);box-shadow:0 0 0 4px rgba(0,122,255,.12)}
.fd input::placeholder,.fd textarea::placeholder{color:var(--muted-2)}
.fd textarea{resize:vertical;min-height:76px;font-family:'JetBrains Mono',monospace}
.stt{font-size:15px;font-weight:800;margin-bottom:13px;display:flex;align-items:center;gap:10px;padding-bottom:11px;border-bottom:1px solid var(--bglass)}
.stt .icn{font-size:16px;color:var(--violet-2)}
.si{width:100%;max-width:330px;padding:11px 14px;border-radius:13px;background:rgba(8,8,20,.6);border:1.5px solid var(--bglass);color:var(--text);font-size:12.5px;outline:none;font-family:inherit}
.si:focus{border-color:rgba(0,122,255,.7)}
.switch{position:relative;display:inline-block;width:42px;height:24px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.switch .sl2{position:absolute;inset:0;background:rgba(255,255,255,.15);border-radius:24px;cursor:pointer;transition:background .24s var(--spring-snappy)}
.switch .sl2::before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:transform .24s var(--spring-bouncy);box-shadow:0 2px 6px rgba(0,0,0,.35)}
.switch input:checked+.sl2{background:var(--ios-green)}
.switch input:checked+.sl2::before{transform:translateX(18px)}

/* ══════════ ADVANCED / RELAY / LIST ══════════ */
.adv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:11px}
.adv-item{display:flex;align-items:center;justify-content:space-between;gap:11px;padding:12px 14px;border-radius:13px;background:var(--mat-thin);border:1px solid var(--bglass);transition:all .2s}
.adv-item:hover{border-color:rgba(0,122,255,.35);background:rgba(0,122,255,.05)}
.adv-item .ai-l{flex:1}
.adv-item .ai-t{font-weight:800;font-size:12.5px;display:flex;align-items:center;gap:8px}
.adv-item .ai-t .icn{font-size:14px;color:var(--violet-2)}
.adv-item .ai-d{font-size:10.5px;color:var(--text-2);margin-top:3px;line-height:1.5}
.adv-row{display:flex;flex-direction:column;gap:7px;padding:12px 14px;border-radius:13px;background:var(--mat-thin);border:1px solid var(--bglass)}
.adv-row label{font-size:12px;font-weight:800;display:flex;align-items:center;gap:8px}
.adv-row label .icn{font-size:13px;color:var(--violet-2)}
.adv-row .ai-d{font-size:10px;color:var(--text-2);line-height:1.5}
.adv-row input{width:100%;padding:9px 11px;border-radius:10px;background:rgba(4,4,12,.6);border:1.5px solid var(--bglass);color:var(--text);font-size:12.5px;font-family:'JetBrains Mono',monospace;outline:none}
.adv-row input:focus{border-color:rgba(0,122,255,.7)}
.adv-pv{padding:13px 17px;border-radius:13px;background:rgba(0,122,255,.07);border:1px dashed rgba(0,122,255,.4);font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#a5d8ff;word-break:break-all;line-height:1.75;direction:ltr;text-align:left}
.relay-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:9px;max-height:290px;overflow-y:auto;padding:5px}
.relay-grid::-webkit-scrollbar{width:5px}
.relay-grid::-webkit-scrollbar-thumb{background:linear-gradient(180deg,rgba(0,122,255,.5),rgba(88,86,214,.5));border-radius:5px}
.rc{padding:11px 7px;border-radius:12px;background:var(--mat-thin);border:1.5px solid var(--bglass);cursor:pointer;transition:all .2s var(--spring-bouncy);text-align:center;font-size:11.5px;user-select:none;position:relative}
.rc:hover{border-color:rgba(0,122,255,.5);background:rgba(0,122,255,.08);transform:translateY(-2px)}
.rc.on{border-color:rgba(90,200,250,.7);background:linear-gradient(135deg,rgba(90,200,250,.16),rgba(0,122,255,.1));box-shadow:0 8px 24px -8px rgba(0,122,255,.8)}
.rc.on::after{content:"";position:absolute;top:5px;left:5px;width:7px;height:7px;border-radius:50%;background:var(--ios-teal);box-shadow:0 0 8px var(--ios-teal)}
.rc .flag{font-size:24px;display:block;margin-bottom:5px}
.rc .name{font-weight:800;font-size:11px}
.rc .count{font-size:9px;color:var(--text-2);margin-top:2px}
.list-box{display:flex;flex-wrap:wrap;gap:7px;padding:11px;border-radius:13px;background:var(--mat-thin);border:1.5px solid var(--bglass);min-height:52px}
.list-box:empty::before{content:"— خالی —";color:var(--muted-2);font-size:11.5px;margin:auto}
.li{display:inline-flex;align-items:center;gap:6px;padding:5px 9px 5px 11px;border-radius:9px;background:rgba(0,122,255,.14);border:1px solid rgba(0,122,255,.3);color:#a5d8ff;font-size:11.5px;font-weight:700;font-family:'JetBrains Mono',monospace}
.li .x{cursor:pointer;width:15px;height:15px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,.1);font-size:10px;color:#fda4af;user-select:none}
.li .x:hover{background:rgba(255,59,48,.5);color:#fff}
.li.port{background:rgba(90,200,250,.14);border-color:rgba(90,200,250,.32);color:#67e8f9}
.list-add{display:flex;gap:7px;margin-top:9px;flex-wrap:wrap}
.list-add input{flex:1;min-width:130px}

/* ══════════ BOTTOM SHEET ══════════ */
.mb{position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);display:none;align-items:flex-end;justify-content:center;z-index:999;padding:0;animation:fi .3s var(--spring-smooth);overflow-y:auto}
.mb.on{display:flex}
@keyframes fi{from{opacity:0}to{opacity:1}}
.md{width:100%;max-width:640px;max-height:92vh;padding:44px 24px calc(24px + var(--safe-bottom));border-radius:34px 34px 0 0;background:linear-gradient(180deg,var(--mat-chrome),rgba(10,10,22,.98));backdrop-filter:var(--blur-chrome);-webkit-backdrop-filter:var(--blur-chrome);border:1px solid var(--bglass-hi);border-bottom:none;overflow-y:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;animation:sheetUp .4s var(--spring-snappy) both;position:relative;box-shadow:0 -20px 60px rgba(0,0,0,.7);margin:auto auto 0}
.md::before{content:"";position:absolute;top:12px;left:50%;transform:translateX(-50%);width:40px;height:5px;border-radius:3px;background:var(--g3)}
@media(min-width:960px){
  .mb{align-items:center;padding:20px}
  .md{border-radius:var(--r-c);border-bottom:1px solid var(--bglass-hi);max-height:85vh;padding:26px 28px;animation:modalIn .35s var(--spring-bouncy) both;margin:auto}
  .md::before{display:none}
  @keyframes modalIn{from{opacity:0;transform:scale(.94) translateY(20px)}to{opacity:1;transform:scale(1) translateY(0)}}
}
.mh{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.mh h3{font-size:18px;font-weight:900}

/* ══════════ TOAST / MISC ══════════ */
.tst{position:fixed;bottom:calc(20px + var(--safe-bottom));left:50%;transform:translateX(-50%);padding:13px 19px;border-radius:13px;background:var(--mat-chrome);backdrop-filter:var(--blur-thick);-webkit-backdrop-filter:var(--blur-thick);border:1px solid var(--bglass-hi);color:var(--text);font-size:12.5px;font-weight:700;box-shadow:var(--sh-3);display:flex;align-items:center;gap:9px;z-index:1000;animation:ti .3s var(--spring-bouncy);max-width:92vw}
.tst .icn{font-size:15px}
@keyframes ti{from{opacity:0;transform:translate(-50%,26px) scale(.94)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
.tp{display:none;animation:ftb .28s var(--spring-smooth)}
.tp.on{display:block}
@keyframes ftb{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.empty{padding:40px 22px;text-align:center;color:var(--text-2);font-size:12.5px;font-weight:500}
.empty .icn{font-size:34px;display:block;margin:0 auto 11px;color:var(--muted-2);opacity:.6}
.pill{padding:7px 13px;border-radius:10px;background:var(--mat-thin);border:1px solid var(--bglass);color:var(--text-2);font-size:11.5px;font-weight:700;cursor:pointer;transition:all .18s var(--spring-snappy);user-select:none}
.pill.on{background:var(--ios-blue);color:#fff;border-color:transparent}
.chip{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:10px;background:rgba(0,122,255,.1);border:1px solid rgba(0,122,255,.3);color:#a5d8ff;font-size:11.5px;font-weight:700;cursor:pointer;transition:all .18s}
.chip:hover{background:rgba(0,122,255,.22);transform:translateY(-1px)}
.perm{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:10px;background:var(--mat-thin);border:1px solid var(--bglass);color:var(--text-2);font-size:11px;font-weight:700;cursor:pointer;transition:all .18s;user-select:none}
.perm.on{background:rgba(90,200,250,.16);border-color:rgba(90,200,250,.55);color:#67e8f9}
.sugg{padding:13px;border-radius:13px;background:var(--mat-thin);border:1px solid var(--bglass);display:flex;gap:11px;align-items:flex-start;transition:all .2s;margin-bottom:7px}
.sugg:hover{border-color:rgba(0,122,255,.45);transform:translateX(-3px)}
.sugg .icn{font-size:22px;color:var(--violet-2);flex-shrink:0}
.wbox{display:flex;align-items:center;gap:18px;padding:22px;border-radius:var(--r-xl);background:linear-gradient(135deg,rgba(90,200,250,.09),rgba(255,45,85,.05));border:1px solid rgba(0,122,255,.22)}
.wbox .em{font-size:52px;color:var(--violet-2);filter:drop-shadow(0 0 20px rgba(0,122,255,.5))}
.erow{display:flex;gap:9px;align-items:center;padding:11px;border-radius:13px;background:var(--mat-thin);border:1px solid var(--bglass);margin-bottom:7px}
.erow .txt{flex:1;font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--text-2)}
.pvbox{padding:15px;border-radius:13px;background:rgba(0,122,255,.07);border:1px dashed rgba(0,122,255,.38);font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#a5d8ff;text-align:center;word-break:break-word;font-weight:600}
.bulkbar{padding:9px 13px;margin-bottom:9px;border-radius:11px;background:rgba(0,122,255,.11);border:1px solid rgba(0,122,255,.32);display:none;gap:8px;align-items:center;flex-wrap:wrap;font-size:11.5px;font-weight:700}
.bulkbar.on{display:flex}
</style></head><body>

<div class="bgA"><span class="b1"></span><span class="b2"></span><span class="b3"></span></div>
<div class="bgG"></div>

<!-- ══════════ LOGIN ══════════ -->
<div id="login" class="lp">
  <div class="lp-l"><div class="lp-lc">
    <div class="lp-badge"><span class="dot"></span>SECURE ACCESS · v2.1</div>
    <h1 class="lp-t1">مدیریت <span class="tg">حرفه‌ای</span><br>پنل تلگرام</h1>
    <p class="lp-sub">پلتفرم کامل مدیریت کاربران، ترافیک، رله و کانفیگ‌های V2Ray / Clash / Sing-Box.</p>
    <div class="lp-feats">
      <div class="lp-feat"><span class="em">⚡</span> اتصال فوق سریع</div>
      <div class="lp-feat"><span class="em">🛡️</span> امنیت پیشرفته</div>
      <div class="lp-feat"><span class="em">🌍</span> چند منطقه رله</div>
      <div class="lp-feat"><span class="em">📊</span> آمار لحظه‌ای</div>
      <div class="lp-feat"><span class="em">🤖</span> اتوماسیون کامل</div>
      <div class="lp-feat"><span class="em">🎯</span> مدیریت آسان</div>
    </div>
  </div></div>
  <div class="lp-r"><div class="lp-card">
    <div class="lp-logo" id="loginOtter">__OTTER_SVG__</div>
    <h2 class="lp-name tg">__PANEL_NAME__</h2>
    <div class="lp-tag">Aurora · v__CURRENT_VERSION__</div>
    <div class="lp-wel"><h2>خوش آمدید 👋</h2><p>برای ورود اطلاعات خود را وارد کنید</p></div>
    <div id="le" class="lp-err"></div>
    <div class="lp-float"><input id="lu" placeholder=" " autocomplete="username" inputmode="text" spellcheck="false" value="admin"><label>نام کاربری</label></div>
    <div class="lp-float"><input id="lp" type="password" placeholder=" " autocomplete="current-password"><label>رمز عبور</label></div>
    <div id="captchaBox" class="lp-cap">
      <div class="lp-cap-h">
        <div class="lp-cap-q" id="capQ">— + — = ?</div>
        <button type="button" class="lp-cap-r" id="capR" title="تغییر">↻</button>
      </div>
      <input id="capA" class="lp-cap-i" placeholder="پاسخ" inputmode="numeric" autocomplete="off">
    </div>
    <div class="lp-bio">
      <svg viewBox="0 0 24 24"><path d="M12 11v2M7 11a5 5 0 0 1 10 0v2M12 19a5 5 0 0 0 5-5M12 19a5 5 0 0 1-5-5"/></svg>
      <span>Face ID / Touch ID فعال است</span>
    </div>
    <button id="loginBtn" class="lp-btn">ورود به پنل</button>
    <div class="lp-foot"><div>© 2025 <strong>__PANEL_NAME__</strong></div><div style="margin-top:3px;opacity:.75">v__CURRENT_VERSION__ · Made with 🦦</div></div>
  </div></div>
</div>

<!-- ══════════ SHELL ══════════ -->
<div id="shell" class="sh">
  <div class="ov" id="ov"></div>
  <button class="mmb" id="menuBtn" aria-label="Menu"><svg viewBox="0 0 24 24"><path d="M3 6h18M3 12h18M3 18h18"/></svg></button>
  <aside class="sb" id="sb">
    <div class="sb-brand-wrapper">
      <div class="brand">
        <div id="brandLogo">__OTTER_SVG__</div>
        <div class="nm tg">__PANEL_NAME__</div>
        <div class="tg2" id="whoami">Loading...</div>
      </div>
    </div>
    <div class="sb-nav-scroll">
      <nav id="nav" style="display:flex;flex-direction:column;gap:2px"></nav>
    </div>
    <div class="sb-bottom-wrapper">
      <div class="dvd"></div>
      <div class="stp"><span class="pd"></span><span style="color:var(--text-2)">وضعیت:</span><span id="sst" style="font-weight:800;color:var(--ios-green)">فعال</span></div>
      <button class="lgb" id="logoutBtn"><span class="icn" id="logoutIcon"></span><span>خروج از حساب</span></button>
      <div style="text-align:center;padding:11px 4px 4px;font-size:9.5px;color:var(--muted-2)">© 2025 <strong style="color:var(--violet-2)">__PANEL_NAME__</strong><br>v__CURRENT_VERSION__</div>
    </div>
  </aside>
  <main class="mn">

  <!-- OVERVIEW -->
  <div id="tab-overview" class="tp on">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="h-ov"></span> داشبورد</h1><p class="ps">نمای کلی سیستم</p></div><div class="ph-a"><span class="blive">LIVE</span><button class="btn bg2 bs" id="refBtn">بروزرسانی</button></div></div>
    <div class="bento">
      <div class="bcard bhero s3"><div class="blabel"><span class="bpulse"></span>کل کاربران</div><div class="bvalue" id="st1">0</div></div>
      <div class="bcard s3"><div class="blabel">فعال</div><div class="bvalue" id="st2" style="color:var(--ios-green)">0</div></div>
      <div class="bcard s3"><div class="blabel">متوقف</div><div class="bvalue" id="st3" style="color:var(--ios-orange)">0</div></div>
      <div class="bcard s3"><div class="blabel">منقضی</div><div class="bvalue" id="st4" style="color:var(--ios-red)">0</div></div>
      <div class="bcard s6"><div class="blabel">ترافیک کل</div><div class="bvalue" id="st5">0 <small>GB</small></div></div>
      <div class="bcard s6"><div class="blabel">امروز</div><div class="bvalue" id="st6" style="color:var(--ios-teal)">0 <small>GB</small></div></div>
      <div class="bcard s6"><div class="blabel">اتصالات فعال</div><div class="bvalue" id="st7">0</div></div>
      <div class="bcard s6"><div class="blabel">آپتایم</div><div class="bvalue" id="st8" style="font-size:22px">0h</div></div>
      <div class="bcard s8"><div class="blabel">📊 ترافیک ۷ روز</div><div style="height:240px;margin-top:6px"><canvas id="ch1"></canvas></div></div>
      <div class="bcard s4"><div class="blabel">🥧 توزیع امروز</div><div style="height:240px;margin-top:6px"><canvas id="ch2"></canvas></div></div>
      <div class="bcard s12"><div class="blabel">🏆 پرمصرف‌ترین‌ها</div><div id="topUsers" style="margin-top:10px"></div></div>
    </div>
  </div>

  <!-- USERS -->
  <div id="tab-users" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hu"></span> کاربران</h1><p class="ps">مدیریت مشترکین</p></div><div class="ph-a"><button class="btn bg2 bs" id="expBtn">CSV</button><button class="btn bg2 bs" id="impBtn">Import</button><button class="btn bp bs" id="addUserBtn">کاربر جدید</button></div></div>
    <div style="margin-bottom:11px;display:flex;gap:9px;flex-wrap:wrap;align-items:center"><input id="userSearch" class="si" placeholder="جستجو..."><select id="groupFilter" class="si" style="max-width:150px"><option value="">همه گروه‌ها</option></select></div>
    <div id="bulkBar" class="bulkbar"><span id="bulkCount">0</span> انتخاب شده<button class="btn bp bs" onclick="if(window.bulkAction)bulkAction('pause')">توقف</button><button class="btn bok bs" onclick="if(window.bulkAction)bulkAction('resume')">فعال</button><button class="btn bg2 bs" onclick="if(window.bulkReset)bulkReset()">ریست مصرف</button><button class="btn bd bs" onclick="if(window.bulkClear)bulkClear()">لغو</button></div>
    <div class="tw"><table><thead><tr><th style="width:30px"><input type="checkbox" id="selAll"></th><th>نام</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="ub"><tr><td colspan="6" class="empty">بارگذاری...</td></tr></tbody></table></div>
  </div>

  <!-- GROUPS -->
  <div id="tab-groups" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hg"></span> گروه‌ها</h1></div><div class="ph-a"><button class="btn bp bs" id="addGroupBtn">گروه جدید</button></div></div>
    <div id="groupsGrid" class="card2"></div>
  </div>

  <!-- TRAFFIC -->
  <div id="tab-traffic" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="ht"></span> ترافیک</h1></div></div>
    <div style="display:flex;gap:7px;margin-bottom:14px;flex-wrap:wrap"><div class="pill on" data-days="7">۷ روز</div><div class="pill" data-days="14">۱۴ روز</div><div class="pill" data-days="30">۳۰ روز</div></div>
    <div class="cc" style="margin-bottom:13px"><div class="ct"><span class="icn" id="ic3"></span> مصرف کل (GB)</div><div class="cw" style="height:280px"><canvas id="ch3"></canvas></div></div>
    <div class="cc"><div class="ct"><span class="icn" id="ic4"></span> مقایسه کاربران</div><div class="cw" style="height:300px"><canvas id="ch4"></canvas></div></div>
  </div>

  <!-- ANOMALIES -->
  <div id="tab-anomalies" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="ha"></span> هشدارها</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.lanom)lanom()">بررسی</button></div></div>
    <div id="anomList" class="gl" style="padding:14px"><div class="empty">در حال بررسی...</div></div>
  </div>

  <!-- PREDICTIVE -->
  <div id="tab-predictive" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hp"></span> پیش‌بینی</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.lpredictive)lpredictive()">بروزرسانی</button></div></div>
    <div id="predictiveBox" class="gl" style="padding:16px;margin-bottom:13px"><div class="empty">در حال محاسبه...</div></div>
    <div class="cc"><div class="ct"><span class="icn" id="icp"></span> نمودار پیش‌بینی</div><div class="cw"><canvas id="chPred"></canvas></div></div>
  </div>

  <!-- SUGGESTIONS -->
  <div id="tab-suggestions" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hs"></span> پیشنهادات</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.lsug)lsug()">بروزرسانی</button></div></div>
    <div id="sugList" class="fg"></div>
  </div>

  <!-- WEATHER -->
  <div id="tab-weather" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hw"></span> وضعیت شبکه</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.lweather)lweather()">بروزرسانی</button></div></div>
    <div id="weatherBox" class="gl" style="padding:20px"><div class="empty">در حال بارگذاری...</div></div>
  </div>

  <!-- ADVANCED -->
  <div id="tab-advanced" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hadv"></span> تنظیمات پیشرفته</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.testRelays)testRelays()">تست Relay</button><button class="btn bd bs" onclick="if(window.resetAdvanced)resetAdvanced()">بازنشانی</button><button class="btn bp bs" onclick="if(window.saveAdvanced)saveAdvanced()">ذخیره</button></div></div>
    <div class="gl" style="padding:20px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="ia1"></span> پارامترهای VLESS / Trojan</div>
      <div class="adv-grid" id="advGrid"></div>
    </div>
    <div class="gl" style="padding:20px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="ia1b"></span> بهینه‌سازی ایران</div>
      <div class="fg">
        <div class="fr"><div class="fd"><label>اپراتور پیش‌فرض</label><select id="a9"><option value="">هیچ</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="mokhaberat">مخابرات</option><option value="shatel">شاتل</option></select></div><div class="fd"><label>Fragment Preset</label><select id="a10"></select></div></div>
        <div class="fd"><label style="display:flex;align-items:center;gap:8px;font-weight:600"><input type="checkbox" id="a11" style="width:auto"> مسیردهی دامنه‌های ایرانی</label></div>
      </div>
    </div>
    <div class="gl" style="padding:20px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="ia2"></span> وضعیت سلامت Relay</div>
      <div id="relayHealthBox" style="padding:10px;border-radius:12px;background:rgba(0,122,255,.06);border:1px dashed rgba(0,122,255,.3)">
        <div style="font-size:11px;color:var(--muted);text-align:center">در حال بارگذاری...</div>
      </div>
    </div>
    <div class="gl" style="padding:20px">
      <div class="stt"><span class="icn" id="ia3"></span> پیش‌نمایش پارامترها</div>
      <div class="adv-pv" id="advPreview">...پارامترها بعد از تغییر نمایش داده می‌شوند</div>
    </div>
  </div>

  <!-- INBOUNDS -->
  <div id="tab-inbounds" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hin"></span> اینباند کانفیگ‌ها</h1></div><div class="ph-a"><button class="btn bp bs" id="addCustomInbBtn">+ کارت جدید</button><button class="btn bp bs" onclick="if(window.saveInboundGlobal)saveInboundGlobal()">ذخیره سراسری</button></div></div>

    <div class="gl" style="padding:19px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="ii1"></span> تنظیمات سراسری نام</div>
      <div class="fg">
        <div class="fr"><div class="fd"><label>الگوی نام</label><input id="inb-template" placeholder="{FLAG} {PREFIX}-{INDEX}"></div><div class="fd"><label>پیشوند</label><input id="inb-prefix" placeholder="Hamed"></div></div>
        <div class="fr"><div class="fd"><label>حداکثر طول</label><input id="inb-maxlen" type="number" value="60"></div><div class="fd"><label>فقط ASCII</label><div style="padding-top:6px"><label class="switch"><input id="inb-ascii" type="checkbox"><span class="sl2"></span></label></div></div></div>
        <div class="fd"><label>پیش‌نمایش</label><div class="pvbox" id="inb-preview">🇩🇪 Hamed-1</div></div>
        <div class="fd"><label>تگ‌ها (کلیک = درج)</label><div id="inb-tags" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:5px"></div></div>
      </div>
    </div>

    <div class="gl" style="padding:19px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="ii2"></span> کارت‌های اینباند سفارشی</div>
      <div style="font-size:11.5px;color:var(--muted);margin-bottom:11px;line-height:1.7">
        💡 هر کارت = یک لینک استاتیک در پنل ساب. Placeholders: <code>{USER}</code> <code>{DATE}</code> <code>{PREFIX}</code> <code>{PANEL}</code> <code>{VERSION}</code>
      </div>
      <div id="customInboundsList" class="fg" style="gap:9px"></div>
    </div>
  </div>

  <!-- MANAGERS -->
  <div id="tab-managers" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hm"></span> مدیران</h1></div><div class="ph-a"><button class="btn bp bs" id="addMgrBtn">مدیر جدید</button></div></div>
    <div class="tw"><table><thead><tr><th>کاربر</th><th>دسترسی</th><th>وضعیت</th><th>آخرین ورود</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="mb"></tbody></table></div>
  </div>

  <!-- SESSIONS -->
  <div id="tab-sessions" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hs2"></span> نشست‌ها</h1></div><div class="ph-a"><button class="btn bd bs" onclick="if(window.revokeAll)revokeAll()">قطع همه</button></div></div>
    <div class="tw"><table><thead><tr><th>کاربر</th><th>IP</th><th>شروع</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="sessBody"></tbody></table></div>
  </div>

  <!-- NODES -->
  <div id="tab-nodes" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hn"></span> نودها</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.healthAll)healthAll()">تست سلامت</button><button class="btn bp bs" id="addNodeBtn">نود جدید</button></div></div>
    <div id="nodesGrid" class="card2"></div>
  </div>

  <!-- BANNED -->
  <div id="tab-banned" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hb"></span> IPهای بسته</h1></div><div class="ph-a"><button class="btn bd bs" onclick="if(window.clearBanned)clearBanned()">پاک همه</button><button class="btn bp bs" id="addBanBtn">Ban</button></div></div>
    <div class="tw"><table><thead><tr><th>IP</th><th>دلیل</th><th>زمان</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="banBody"></tbody></table></div>
  </div>

  <!-- WORKFLOWS -->
  <div id="tab-workflows" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hwf"></span> Workflows</h1></div><div class="ph-a"><button class="btn bp bs" id="addWfBtn">Workflow جدید</button></div></div>
    <div id="wfGrid" class="card2"></div>
  </div>

  <!-- CRON -->
  <div id="tab-cron" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hc"></span> Cron Jobs</h1></div><div class="ph-a"><button class="btn bp bs" id="addCronBtn">Cron جدید</button></div></div>
    <div id="cronGrid" class="card2"></div>
  </div>

  <!-- WEBHOOKS -->
  <div id="tab-webhooks" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hwh"></span> Webhooks</h1></div><div class="ph-a"><button class="btn bp bs" id="addWhBtn">Webhook جدید</button></div></div>
    <div id="whGrid" class="card2"></div>
  </div>

  <!-- CRISIS -->
  <div id="tab-crisis" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hcr"></span> اعلان بحران</h1></div></div>
    <div class="gl" style="padding:19px;margin-bottom:13px">
      <div class="stt"><span class="icn" id="icr1"></span> پیام فوری</div>
      <div class="fg"><div class="fd"><label>پیام</label><textarea id="crisisMsg" rows="3"></textarea></div><button class="btn bp" style="justify-self:flex-start" onclick="if(window.sendCrisis)sendCrisis()">ارسال به همه</button></div>
    </div>
    <div class="gl" style="padding:19px;margin-bottom:13px"><div class="stt"><span class="icn" id="icr2"></span> پریست‌ها</div><div id="crisisPresets" class="card2"></div></div>
    <div class="gl" style="padding:19px"><div class="stt"><span class="icn" id="icr3"></span> تاریخچه</div><div id="crisisHistory"></div></div>
  </div>

  <!-- REGIONS -->
  <div id="tab-regions" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hr"></span> مناطق IP</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.runCleanIp)runCleanIp()">تست IP</button><button class="btn bp bs" id="addRegBtn">منطقه جدید</button></div></div>
    <div class="gl" style="padding:13px 17px;margin-bottom:13px;display:flex;align-items:center;gap:11px;flex-wrap:wrap"><label style="display:flex;align-items:center;gap:9px;font-size:12px;font-weight:600"><input type="checkbox" id="autoClean"> تست خودکار</label><span id="cleanInfo" style="font-size:11px;color:var(--text-2)"></span></div>
    <div id="regionsGrid" class="card2" style="margin-bottom:13px"></div>
    <div class="gl" style="padding:17px"><div class="stt"><span class="icn" id="icl"></span> نتایج تست</div><div class="tw" style="border:none;padding:0"><table><thead><tr><th>IP</th><th>Ping</th></tr></thead><tbody id="cleanBody"><tr><td colspan="2" class="empty">تست نشده</td></tr></tbody></table></div></div>
  </div>

  <!-- ISP -->
  <div id="tab-isp" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hisp"></span> قالب اپراتور</h1></div><div class="ph-a"><button class="btn bp bs" onclick="if(window.saveIsp)saveIsp()">ذخیره</button></div></div>
    <div id="ispGrid" class="fg"></div>
  </div>

  <!-- SETTINGS -->
  <div id="tab-settings" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hset"></span> تنظیمات</h1></div></div>
    <div class="gl" style="padding:20px">
      <div class="stt"><span class="icn" id="is1"></span> پیکربندی اصلی</div>
      <div class="fg">
        <div class="fr"><div class="fd"><label>نام پنل</label><input id="c1"></div><div class="fd"><label>مسیر API</label><input id="c2" disabled></div></div>
        <div class="fr"><div class="fd"><label>کلید اصلی (Master Key)</label><input id="c3" type="password" placeholder="••••••"><div style="font-size:10px;color:var(--text-2);margin-top:4px;line-height:1.5">⚠️ تغییر = تغییر رمز admin</div></div><div class="fd"><label>پروتکل</label><select id="c4"><option value="alpha">Alpha (VLESS)</option><option value="beta">Beta (Trojan)</option><option value="both">Both</option></select></div></div>
        <div class="fd"><label><span class="icn" id="iports"></span> پورت‌های کانفیگ</label>
          <div class="list-box" id="portsListBox"></div>
          <div class="list-add"><input id="newPortInput" class="si" placeholder="پورت جدید" style="max-width:none" inputmode="numeric"><button class="btn bp bs" onclick="if(window.addPort)addPort()">افزودن</button><button class="btn bg2 bs" onclick="if(window.loadPresetPorts)loadPresetPorts()">HTTPS</button><button class="btn bg2 bs" onclick="if(window.loadAllPorts)loadAllPorts()">همه</button></div>
        </div>
        <div class="fd"><label>DNS</label><input id="c6"></div>
        <div class="fd"><label>سایت استتار</label><input id="c7"></div>
        <div class="fd"><label>آی‌پی تمیز دستی</label><textarea id="c8" rows="3"></textarea></div>
        <div class="fd"><label>کپچای امنیتی ورود</label><div style="padding-top:6px"><label class="switch"><input id="c11" type="checkbox" checked><span class="sl2"></span></label></div></div>
        <div class="stt" style="margin-top:16px"><span class="icn" id="ilogo"></span> لوگو</div>
        <div class="fd"><label>Base64 یا URL</label><input id="c9"></div>
        <div class="fd"><label>رنگ عنوان</label><input id="c10" placeholder="#8b5cf6"></div>
      </div>
      <div style="display:flex;gap:9px;margin-top:18px;flex-wrap:wrap"><button class="btn bp" onclick="if(window.sc)sc()">ذخیره</button><button class="btn bg2" onclick="if(window.fc)fc()">بازنشانی</button><button class="btn bd" onclick="if(window.clearLogo)clearLogo()">حذف لوگو</button></div>
    </div>
  </div>

  <!-- CF -->
  <div id="tab-cf" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hcf"></span> Cloudflare & Telegram</h1></div></div>
    <div class="gl" style="padding:20px;margin-bottom:13px"><div class="stt"><span class="icn" id="icf1"></span> Cloudflare</div><div class="fg"><div class="fr"><div class="fd"><label>Account ID</label><input id="a1"></div><div class="fd"><label>API Token</label><input id="a2" type="password"></div></div><div class="fd"><label>Worker Name</label><input id="a3"></div></div></div>
    <div class="gl" style="padding:20px;margin-bottom:13px"><div class="stt"><span class="icn" id="icf2"></span> Telegram</div><div class="fg"><div class="fr"><div class="fd"><label>Bot Token</label><input id="a4" type="password"></div><div class="fd"><label>Chat ID</label><input id="a5"></div></div><div class="fd"><label>Admin ID</label><input id="a6"></div></div></div>
    <div class="gl" style="padding:20px"><div class="stt"><span class="icn" id="icf3"></span> رله پیش‌فرض</div><div class="fg"><div class="fd"><label>آی‌پی/دامنه رله</label><textarea id="a7" rows="3"></textarea></div><div class="fd"><label>NAT64 Prefix</label><input id="a8" placeholder="2a00:1a00:1::/96"></div></div></div>
    <div style="display:flex;gap:9px;margin-top:14px"><button class="btn bp" onclick="if(window.sc)sc()">ذخیره</button></div>
  </div>

  <!-- APIKEYS -->
  <div id="tab-apikeys" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hk"></span> API Keys</h1></div><div class="ph-a"><button class="btn bp bs" onclick="if(window.ck)ck()">کلید جدید</button></div></div>
    <div class="tw"><table><thead><tr><th>نام</th><th>کلید</th><th>تاریخ</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="kb"></tbody></table></div>
  </div>

  <!-- BACKUP -->
  <div id="tab-backup" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hbk"></span> پشتیبان</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.exportConfig)exportConfig()">JSON</button><button class="btn bg2 bs" onclick="if(window.openImportConfig)openImportConfig()">Import</button><button class="btn bp bs" onclick="if(window.makeBackup)makeBackup()">بکاپ جدید</button></div></div>
    <div class="tw"><table><thead><tr><th>فایل</th><th>اندازه</th><th>تاریخ</th><th style="text-align:left">عملیات</th></tr></thead><tbody id="backupBody"><tr><td colspan="4" class="empty">بارگذاری...</td></tr></tbody></table></div>
  </div>

  <!-- LOGS -->
  <div id="tab-logs" class="tp">
    <div class="ph"><div class="ph-t"><h1 class="pt"><span class="icn" id="hlog"></span> لاگ‌ها</h1></div><div class="ph-a"><button class="btn bg2 bs" onclick="if(window.ll)ll()">بروزرسانی</button></div></div>
    <div class="gl" style="padding:17px"><div id="lc" style="display:flex;flex-direction:column;gap:7px"></div></div>
  </div>

  </main>
</div>

<!-- MODALS -->
<div id="um" class="mb"><div class="md">
  <div class="mh"><h3 id="umt" class="tg">کاربر جدید</h3><button class="btn bg2 bs" onclick="if(window.cu)cu()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام</label><input id="u1"></div>
    <div class="fr"><div class="fd"><label>گروه</label><select id="u6"></select></div><div class="fd"><label>اپراتور</label><select id="u9"><option value="">هیچ</option><option value="mci">همراه اول</option><option value="irancell">ایرانسل</option><option value="rightel">رایتل</option><option value="mokhaberat">مخابرات</option><option value="shatel">شاتل</option></select></div></div>
    <div class="fr"><div class="fd"><label>ترافیک (GB)</label><input id="u2" type="number" placeholder="0 = ∞"></div><div class="fd"><label>روزانه (GB)</label><input id="u3" type="number" placeholder="0 = ∞"></div></div>
    <div class="fr"><div class="fd"><label>اعتبار (روز)</label><input id="u4" type="number" placeholder="0 = ∞"></div><div class="fd"><label>محدودیت کانفیگ</label><input id="u7" type="number" placeholder="0 = ∞"></div></div>
    <div class="fr"><div class="fd"><label>پهنای باند (Kbps)</label><input id="u10" type="number" placeholder="0 = ∞"></div><div class="fd"><label>بازنشانی</label><select id="u8"><option value="none">غیرفعال</option><option value="daily">روزانه</option><option value="weekly">هفتگی</option><option value="monthly">ماهانه</option></select></div></div>
    <div class="fd"><label>برچسب‌ها (با کاما)</label><input id="u11" placeholder="VIP,Premium"></div>
    <div class="fd"><label>یادداشت</label><input id="u5"></div>
    <div class="stt" style="margin-top:12px"><span class="icn" id="ir1"></span> Relay IP — نمایش لوکیشن</div>
    <div style="font-size:11px;color:var(--text-2);margin-bottom:9px;line-height:1.7">🎯 منطقه رله انتخاب کن — پرچم و نام کشور در V2rayNG / Hiddify / Clash نمایش داده می‌شود.</div>
    <div class="relay-grid" id="relayPresetGrid"></div>
    <div class="fd" style="margin-top:11px"><label>آی‌پی رله سفارشی (خط‌به‌خط)</label><textarea id="uRelayIps" rows="2" placeholder="ProxyIP.CMLiussss.net&#10;188.114.96.1"></textarea></div>
    <div style="display:flex;gap:9px;margin-top:11px"><button class="btn bp" style="flex:1" onclick="if(window.su2)su2()">ذخیره</button><button class="btn bg2" onclick="if(window.cu)cu()">انصراف</button></div>
  </div>
</div></div>

<div id="gml" class="mb"><div class="md">
  <div class="mh"><h3 id="gmt" class="tg">گروه</h3><button class="btn bg2 bs" onclick="if(window.cg)cg()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام</label><input id="g1"></div>
    <div class="fr"><div class="fd"><label>ترافیک (GB)</label><input id="g2" type="number"></div><div class="fd"><label>روزانه (GB)</label><input id="g3" type="number"></div></div>
    <div class="fr"><div class="fd"><label>اعتبار (روز)</label><input id="g4" type="number"></div><div class="fd"><label>حداکثر کانفیگ</label><input id="g5" type="number"></div></div>
    <div class="fd"><label>محدودیت اتصال</label><input id="g6" type="number"></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.sg2)sg2()">ذخیره</button><button class="btn bg2" onclick="if(window.cg)cg()">انصراف</button></div>
  </div>
</div></div>

<div id="mm2" class="mb"><div class="md">
  <div class="mh"><h3 id="mmt" class="tg">مدیر</h3><button class="btn bg2 bs" onclick="if(window.cm)cm()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام کاربری</label><input id="m1"></div>
    <div class="fd"><label>رمز <span style="color:var(--muted);font-weight:500;font-size:10.5px">(خالی = بدون تغییر)</span></label><input id="m2" type="password"></div>
    <div class="fd"><label>دسترسی‌ها</label><div id="mp" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:5px"></div></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.sm)sm()">ذخیره</button><button class="btn bg2" onclick="if(window.cm)cm()">انصراف</button></div>
  </div>
</div></div>

<div id="nm" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">نود جدید</h3><button class="btn bg2 bs" onclick="if(window.cn)cn()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام</label><input id="n1"></div>
    <div class="fd"><label>آدرس</label><input id="n2" placeholder="https://..."></div>
    <div class="fd"><label>API Key</label><input id="n3" type="password"></div>
    <div class="fd"><label>گروه</label><input id="n4" placeholder="default"></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.sn)sn()">ذخیره</button><button class="btn bg2" onclick="if(window.cn)cn()">انصراف</button></div>
  </div>
</div></div>

<div id="rm" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">منطقه جدید</h3><button class="btn bg2 bs" onclick="if(window.cr)cr()">✕</button></div>
  <div class="fg">
    <div class="fr"><div class="fd"><label>نام</label><input id="r1"></div><div class="fd"><label>پرچم</label><input id="r2" placeholder="🇩🇪"></div></div>
    <div class="fd"><label>آی‌پی‌ها (خط‌به‌خط)</label><textarea id="r3" rows="5"></textarea></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.sr2)sr2()">ذخیره</button><button class="btn bg2" onclick="if(window.cr)cr()">انصراف</button></div>
  </div>
</div></div>

<div id="com" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Cron Job</h3><button class="btn bg2 bs" onclick="if(window.ccj)ccj()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام</label><input id="cj1"></div>
    <div class="fd"><label>عملیات</label><select id="cj2"></select></div>
    <div class="fd"><label>پارامترها (JSON)</label><textarea id="cj3" rows="3">{"userId":""}</textarea></div>
    <div class="fr"><div class="fd"><label>فاصله (دقیقه)</label><input id="cj4" type="number" value="60"></div><div class="fd"><label>فعال</label><div style="padding-top:6px"><label class="switch"><input id="cj5" type="checkbox" checked><span class="sl2"></span></label></div></div></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.scj)scj()">ذخیره</button><button class="btn bg2" onclick="if(window.ccj)ccj()">انصراف</button></div>
  </div>
</div></div>

<div id="whm" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Webhook جدید</h3><button class="btn bg2 bs" onclick="if(window.cwh)cwh()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>URL</label><input id="wh1" placeholder="https://hooks.slack.com/..."></div>
    <div class="fd"><label>رویدادها</label><div id="whEvents" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:5px"></div></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.swh)swh()">ذخیره</button><button class="btn bg2" onclick="if(window.cwh)cwh()">انصراف</button></div>
  </div>
</div></div>

<div id="bam" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Ban IP</h3><button class="btn bg2 bs" onclick="if(window.cban)cban()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>IP</label><input id="b1"></div>
    <div class="fd"><label>دلیل</label><input id="b2"></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bd" style="flex:1" onclick="if(window.doban)doban()">Ban</button><button class="btn bg2" onclick="if(window.cban)cban()">انصراف</button></div>
  </div>
</div></div>

<div id="wfm" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Workflow</h3><button class="btn bg2 bs" onclick="if(window.cwf)cwf()">✕</button></div>
  <div class="fg">
    <div class="fd"><label>نام</label><input id="wf1"></div>
    <div class="fd"><label>Trigger</label><select id="wf2"></select></div>
    <div class="fd"><label>Actions (JSON)</label><textarea id="wf3" rows="5">[{"type":"send.telegram","params":{"message":"سلام {name}"}}]</textarea></div>
    <div style="display:flex;gap:9px;margin-top:7px"><button class="btn bp" style="flex:1" onclick="if(window.swf)swf()">ذخیره</button><button class="btn bg2" onclick="if(window.cwf)cwf()">انصراف</button></div>
  </div>
</div></div>

<div id="im" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Import CSV</h3><button class="btn bg2 bs" onclick="if(window.ci)ci()">✕</button></div>
  <div class="fd"><label>محتوای CSV</label><textarea id="csvData" rows="10"></textarea></div>
  <div style="display:flex;gap:9px;margin-top:11px"><button class="btn bp" style="flex:1" onclick="if(window.doImport)doImport()">آپلود</button><button class="btn bg2" onclick="if(window.ci)ci()">انصراف</button></div>
</div></div>

<div id="imc" class="mb"><div class="md">
  <div class="mh"><h3 class="tg">Import JSON</h3><button class="btn bg2 bs" onclick="if(window.cic)cic()">✕</button></div>
  <div class="fd"><label>محتوای JSON</label><textarea id="jsonData" rows="10"></textarea></div>
  <div style="display:flex;gap:9px;margin-top:11px"><button class="btn bp" style="flex:1" onclick="if(window.doImportConfig)doImportConfig()">آپلود</button><button class="btn bg2" onclick="if(window.cic)cic()">انصراف</button></div>
</div></div>

<div id="tb"></div>

<script>
'use strict';
/* ══════════ ICONS ══════════ */
var ICO={home:'<svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',users:'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',group:'<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>',chart:'<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 4-6"/></svg>',alert:'<svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',predict:'<svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"/></svg>',bulb:'<svg viewBox="0 0 24 24"><path d="M9 18h6M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.2 1 2.3h6c0-1.1.4-1.8 1-2.3A7 7 0 0 0 12 2z"/></svg>',crown:'<svg viewBox="0 0 24 24"><path d="M3 6l4.5 5L12 4l4.5 7L21 6v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',activity:'<svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',server:'<svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',ban:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',workflow:'<svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',clock:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',webhook:'<svg viewBox="0 0 24 24"><path d="M18 16.98h-5.99c-1.1 0-2.12.5-2.83 1.34A4.95 4.95 0 0 1 5 20a5 5 0 1 1 5-5"/><path d="M6 8h15a3 3 0 0 1 3 3v6"/></svg>',crisis:'<svg viewBox="0 0 24 24"><path d="M12 2L2 22h20L12 2zM12 9v5M12 18v.01"/></svg>',globe:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',wifi:'<svg viewBox="0 0 24 24"><path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/></svg>',layers:'<svg viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',link:'<svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',zap:'<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',radar:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',shield:'<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',settings:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33"/></svg>',sliders:'<svg viewBox="0 0 24 24"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',key:'<svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>',save:'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',log:'<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',tag:'<svg viewBox="0 0 24 24"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',refresh:'<svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',plus:'<svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',edit:'<svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',trash:'<svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',pause:'<svg viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>',play:'<svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>',trophy:'<svg viewBox="0 0 24 24"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16M10 14.66V17c0 .55.47.98.97 1.21C9.5 19.5 9 20.5 9 21M14 14.66V17c0 .55-.47.98-.97 1.21C14.5 19.5 15 20.5 15 21"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2z"/></svg>',cloud:'<svg viewBox="0 0 24 24"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>',sun:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',rain:'<svg viewBox="0 0 24 24"><path d="M16 13v8M8 13v8M12 15v8M20 16.58A5 5 0 0 0 18 7h-1.26A8 8 0 1 0 4 15.25"/></svg>',storm:'<svg viewBox="0 0 24 24"><path d="M19 16.9A5 5 0 0 0 18 7h-1.26a8 8 0 1 0-11.62 9"/><polyline points="13 11 9 17 15 17 11 23"/></svg>',info:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',check:'<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',x:'<svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',download:'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',upload:'<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',scan:'<svg viewBox="0 0 24 24"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/></svg>',ports:'<svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="6" rx="2"/><rect x="2" y="14" width="20" height="6" rx="2"/></svg>',logout:'<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',bolt:'<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',web:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'};
function icn(n,c){var s=ICO[n]||ICO.info;return '<span class="icn '+(c||'')+'">'+s+'</span>'}
function setIco(id,n){var el=document.getElementById(id);if(el)el.innerHTML=ICO[n]||ICO.info}

/* ══════════ STATE ══════════ */
var AR="__API_ROUTE__",PN="__PANEL_NAME__";
var CAPTCHA_ENABLED="__CAPTCHA_ENABLED__"==="1";
var CF_HTTPS=["443","8443","2053","2083","2087","2096"];
var CF_ALL=["80","8080","8880","2052","2082","2086","2095","443","8443","2053","2083","2087","2096"];
var ADV_META=[{k:"http3",t:"HTTP/3",d:"اتصال روی HTTP/3",i:"zap",type:"bool"},{k:"tcpFastOpen",t:"TCP Fast Open",d:"کاهش تأخیر اولیه",i:"bolt",type:"bool"},{k:"mux",t:"Multiplexing",d:"ادغام چند اتصال",i:"layers",type:"bool"},{k:"muxConcurrency",t:"Mux Concurrency",d:"تعداد استریم",i:"activity",type:"num"},{k:"xtls",t:"XTLS Direct",d:"عبور مستقیم",i:"zap",type:"bool"},{k:"earlyData",t:"Early Data (0-RTT)",d:"شروع سریع",i:"bolt",type:"bool"},{k:"earlyDataHeader",t:"Early Data Header",d:"هدر انتقال",i:"tag",type:"str"},{k:"padding",t:"Padding",d:"پدینگ",i:"shield",type:"bool"},{k:"keepAlive",t:"KeepAlive (ثانیه)",d:"زنده نگه‌داشتن",i:"clock",type:"num"},{k:"udpRelay",t:"UDP Relay",d:"پشتیبانی UDP",i:"activity",type:"bool"},{k:"tlsFragment",t:"TLS Fragment",d:"شکست TLS",i:"shield",type:"bool"},{k:"alpn",t:"ALPN",d:"مقادیر با کاما",i:"tag",type:"str"},{k:"ech",t:"ECH",d:"Encrypted CH",i:"shield",type:"bool"}];
var S={token:null,me:null,config:null,users:[],managers:[],groups:[],sessions:[],nodes:[],regions:[],activeRegions:[],cronJobs:[],cronActions:[],webhooks:[],webhookEvents:[],banned:[],crisisPresets:[],crisisHistory:[],ispTemplates:{},workflows:[],workflowTriggers:[],workflowActions:[],upstreams:[],dnsPool:[],dnsStrategy:"weighted",relayPresets:[],advanced:null,inbound:null,inboundUsers:[],editU:null,editG:null,editM:null,editCron:null,editWh:null,editRegion:null,editWf:null,editUserInbound:null,days:7,pollTimer:null,charts:{},ports:[],selectedRelayPreset:"auto",selectedUsers:{},captcha:null};
function $(id){return document.getElementById(id)}
function $$(s){return document.querySelectorAll(s)}
function ts(m,t){t=t||"info";var c={info:"#38bdf8",ok:"#34C759",warn:"#FF9500",error:"#FF3B30"}[t],i={info:"info",ok:"check",warn:"alert",error:"x"}[t];var e=document.createElement("div");e.className="tst";e.style.borderLeft="3px solid "+c;e.innerHTML=icn(i)+'<span style="color:'+c+'">'+m+'</span>';var tb=$("tb");if(tb){tb.appendChild(e);setTimeout(function(){e.style.opacity="0";e.style.transition=".3s";setTimeout(function(){if(e.parentNode)e.parentNode.removeChild(e)},300)},2600)}}
window.ts=ts;
var Haptic={light:function(){try{if(navigator.vibrate)navigator.vibrate(8)}catch(e){}},medium:function(){try{if(navigator.vibrate)navigator.vibrate(15)}catch(e){}},success:function(){try{if(navigator.vibrate)navigator.vibrate([10,40,10])}catch(e){}}};
window.Haptic=Haptic;

/* ══════════ API ══════════ */
async function ap(p,o){o=o||{};var h=Object.assign({"Content-Type":"application/json"},o.headers||{});if(S.token)h.Authorization="Bearer "+S.token;var r=await fetch("/"+AR+p,Object.assign({},o,{headers:h}));var d;try{d=await r.json()}catch(e){d={}}return{ok:r.ok,status:r.status,data:d}}
window.ap=ap;

/* ══════════ SAFE BIND ══════════ */
function safeBind(id,fn){
  try{
    var el=$(id);
    if(!el){console.warn("Element not found:",id);return}
    el.addEventListener("click",function(e){
      try{ e.preventDefault(); fn(e); }
      catch(err){ console.error("Click handler error ["+id+"]:",err); ts("خطا: "+(err.message||"unknown"),"error"); }
    });
  }catch(e){console.error("safeBind failed:",id,e)}
}
window.safeBind=safeBind;

/* ══════════ CAPTCHA ══════════ */
async function loadCaptcha(){if(!CAPTCHA_ENABLED){$("captchaBox").classList.remove("on");return}$("captchaBox").classList.add("on");try{var r=await fetch("/"+AR+"/api/captcha",{headers:{"Cache-Control":"no-store"}});var d=await r.json();if(d.ok||d.success){S.captcha=d.data;$("capQ").textContent=d.data.question;$("capA").value=""}else $("capQ").textContent="خطا"}catch(e){$("capQ").textContent="خطا اتصال"}}
window.loadCaptcha=loadCaptcha;

/* ══════════ LOGIN ══════════ */
function showLoginError(m){var e=$("le");e.classList.add("on");e.textContent=m;Haptic.medium()}
window.showLoginError=showLoginError;
async function doLogin(){
  var u=$("lu").value.trim(),p=$("lp").value;
  if(!u||!p){showLoginError("نام و رمز الزامی");return}
  var capId=S.captcha?S.captcha.id:"",capAns=$("capA").value.trim();
  if(CAPTCHA_ENABLED&&(!capId||!capAns)){showLoginError("پاسخ کپچا را وارد کنید");$("capA").focus();return}
  var b=$("loginBtn");b.disabled=true;b.textContent="در حال ورود...";$("le").classList.remove("on");
  try{
    var r=await fetch("/"+AR+"/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p,captchaId:capId,captchaAnswer:capAns})});
    var d;try{d=await r.json()}catch(pe){showLoginError("پاسخ نامعتبر ("+r.status+")");b.disabled=false;b.textContent="ورود به پنل";return}
    if(d.ok||d.success){
      var sess=(d.data&&d.data.session)||d.session,cfg=(d.data&&d.data.config)||d.config;
      if(!sess||!sess.token){showLoginError("توکن دریافت نشد");b.disabled=false;b.textContent="ورود به پنل";return}
      S.token=sess.token;S.me=sess;S.config=cfg||{};
      try{sessionStorage.setItem("hp_token",S.token)}catch(e){}
      Haptic.success();show();
    } else {
      showLoginError(d.error||"خطا");b.disabled=false;b.textContent="ورود به پنل";
      if(d.needCaptcha)loadCaptcha();
    }
  }catch(e){showLoginError("خطا: "+(e.message||"network"));b.disabled=false;b.textContent="ورود به پنل"}
}
window.doLogin=doLogin;
function lo(){try{sessionStorage.removeItem("hp_token")}catch(e){}location.reload()}
window.lo=lo;
function tg(){$("sb").classList.toggle("on");$("ov").classList.toggle("on");Haptic.light()}
window.tg=tg;

/* ══════════ NAV ══════════ */
function renderNav(){
  var has=function(p){return S.me.isRoot||S.me.permissions.indexOf("all")!==-1||S.me.permissions.indexOf(p)!==-1};
  var items=[{g:"عمومی"},{t:"overview",i:"home",l:"داشبورد"},{t:"users",i:"users",l:"کاربران",p:"users"},{t:"groups",i:"group",l:"گروه‌ها",p:"groups"},{t:"traffic",i:"chart",l:"ترافیک",p:"stats"},{t:"anomalies",i:"alert",l:"هشدارها",p:"stats"},{t:"predictive",i:"predict",l:"پیش‌بینی",p:"stats"},{t:"suggestions",i:"bulb",l:"پیشنهادات",p:"stats"},{t:"weather",i:"sun",l:"وضعیت شبکه"},{g:"مدیریت"},{t:"managers",i:"crown",l:"مدیران",p:"managers"},{t:"sessions",i:"activity",l:"نشست‌ها",p:"managers"},{t:"nodes",i:"server",l:"نودها",p:"nodes"},{t:"banned",i:"ban",l:"IPهای بسته",p:"advanced"},{g:"اتوماسیون"},{t:"workflows",i:"workflow",l:"Workflows",p:"advanced"},{t:"cron",i:"clock",l:"Cron Jobs",p:"cron"},{t:"webhooks",i:"webhook",l:"Webhooks",p:"webhooks"},{t:"crisis",i:"crisis",l:"اعلان بحران",p:"users"},{g:"شبکه"},{t:"inbounds",i:"tag",l:"اینباند",p:"inbounds"},{t:"regions",i:"globe",l:"مناطق IP",p:"advanced"},{t:"isp",i:"wifi",l:"قالب اپراتور",p:"advanced"},{g:"تنظیمات"},{t:"settings",i:"settings",l:"تنظیمات",p:"settings"},{t:"advanced",i:"sliders",l:"پیشرفته",p:"advanced"},{t:"cf",i:"cloud",l:"Cloudflare",p:"settings"},{t:"apikeys",i:"key",l:"API Keys",p:"apikeys"},{t:"backup",i:"save",l:"پشتیبان",p:"backup"},{t:"logs",i:"log",l:"لاگ‌ها",p:"logs"}];
  var h="";
  items.forEach(function(x){
    if(x.g){h+='<div class="ng">'+x.g+'</div>';return}
    if(x.p&&!has(x.p))return;
    h+='<a class="nv'+(x.t==="overview"?" on":"")+'" data-tab="'+x.t+'">'+icn(x.i)+'<span>'+x.l+'</span></a>';
  });
  $("nav").innerHTML=h;
  var nvs=$$(".nv");
  for(var i=0;i<nvs.length;i++){nvs[i].addEventListener("click",function(){tab(this.getAttribute("data-tab"))})}
}
function renderStaticIcons(){
  setIco("logoutIcon","logout");setIco("h-ov","home");setIco("hu","users");setIco("hg","group");setIco("ht","chart");
  setIco("ha","alert");setIco("hp","predict");setIco("hs","bulb");setIco("hw","sun");setIco("hadv","sliders");
  setIco("hin","tag");setIco("hm","crown");setIco("hs2","activity");setIco("hn","server");setIco("hb","ban");
  setIco("hwf","workflow");setIco("hc","clock");setIco("hwh","webhook");setIco("hcr","crisis");setIco("hr","globe");
  setIco("hisp","wifi");setIco("hset","settings");setIco("hcf","cloud");setIco("hk","key");setIco("hbk","save");setIco("hlog","log");
  setIco("ic1","chart");setIco("ic2","chart");setIco("ic3","chart");setIco("ic4","chart");setIco("icp","predict");
  setIco("ia1","sliders");setIco("ia1b","globe");setIco("ia2","zap");setIco("ia3","info");
  setIco("ii1","settings");setIco("ii2","link");setIco("icr1","crisis");setIco("icr2","link");setIco("icr3","log");setIco("icl","zap");
  setIco("is1","settings");setIco("ilogo","save");setIco("iports","ports");
  setIco("icf1","cloud");setIco("icf2","webhook");setIco("icf3","link");setIco("ir1","globe");
}
function show(){
  var lp=$("login");lp.classList.add("hide");setTimeout(function(){lp.style.display="none"},500);
  $("shell").classList.add("on");$("whoami").textContent=(S.me.isRoot?"root · ":"")+S.me.username;
  renderNav();renderStaticIcons();renderLogo();fc();refreshAll();startPolling();
}
window.show=show;
function renderLogo(){
  try{
    var l=S.config&&S.config.customLogo,c=$("brandLogo"),lo=$("loginOtter");
    if(!c)return;
    if(l){
      c.innerHTML='<img src="'+l+'" alt="logo" style="width:52px;height:52px;border-radius:15px;object-fit:cover;display:block">';
      if(lo)lo.innerHTML='<img src="'+l+'" style="width:78px;height:78px;border-radius:24px;object-fit:cover" alt="logo">';
    }
  }catch(e){console.error("renderLogo:",e)}
}
window.renderLogo=renderLogo;
function tab(t){
  var tps=$$(".tp");for(var i=0;i<tps.length;i++)tps[i].classList.remove("on");
  var el=$("tab-"+t);if(el)el.classList.add("on");
  var nvs=$$(".nv");for(var j=0;j<nvs.length;j++)nvs[j].classList.remove("on");
  var nv=document.querySelector('.nv[data-tab="'+t+'"]');if(nv)nv.classList.add("on");
  if(window.innerWidth<=1100){$("sb").classList.remove("on");$("ov").classList.remove("on")}
  Haptic.light();
  if(t==="apikeys")lk();if(t==="traffic"){lhist();lcompare()}
  if(t==="managers")lm();if(t==="sessions")lsess();if(t==="nodes")lnodes();
  if(t==="regions")lregions();if(t==="backup")lbackup();if(t==="groups")lgroups();
  if(t==="anomalies")lanom();if(t==="cron")lcron();if(t==="webhooks")lwh();
  if(t==="banned")lbanned();if(t==="crisis")lcrisis();if(t==="isp")lisp();
  if(t==="weather")lweather();if(t==="predictive")lpredictive();if(t==="suggestions")lsug();
  if(t==="workflows")lwf();if(t==="inbounds")linbounds();if(t==="advanced"){loadAdvanced();renderRelayHealthBox()}
}
window.tab=tab;
function startPolling(){if(S.pollTimer)clearInterval(S.pollTimer);S.pollTimer=setInterval(function(){if(document.hidden)return;var t=document.querySelector(".tp.on");if(!t)return;if(t.id==="tab-overview")ls()},15000)}
function refreshAll(){try{ls()}catch(e){}try{lu2()}catch(e){}try{ll()}catch(e){}try{lgroups()}catch(e){}}

/* ══════════ PORTS ══════════ */
function renderPorts(){var c=$("portsListBox");if(!c)return;if(!S.ports||S.ports.length===0){c.innerHTML="";return}c.innerHTML=S.ports.map(function(p){return '<span class="li port">'+p+'<span class="x" onclick="if(window.removePort)removePort(\''+p+'\')">✕</span></span>'}).join("")}
function addPort(){var inp=$("newPortInput"),v=(inp.value||"").trim();if(!v)return;if(!/^\d{1,5}$/.test(v)||parseInt(v)<1||parseInt(v)>65535){ts("پورت نامعتبر","warn");return}if(S.ports.indexOf(v)!==-1){ts("قبلاً اضافه شده","warn");inp.value="";return}S.ports.push(v);inp.value="";inp.focus();renderPorts()}
window.addPort=addPort;
function removePort(p){S.ports=S.ports.filter(function(x){return x!==p});renderPorts()}
window.removePort=removePort;
function loadPresetPorts(){S.ports=CF_HTTPS.slice();renderPorts();ts("HTTPS بارگذاری شد","ok")}
window.loadPresetPorts=loadPresetPorts;
function loadAllPorts(){S.ports=CF_ALL.slice();renderPorts();ts("همه پورت‌ها بارگذاری شد","ok")}
window.loadAllPorts=loadAllPorts;

/* ══════════ SETTINGS ══════════ */
function fc(){
  var c=S.config||{};
  S.ports=((c.socketPorts||"443").toString().split(/[\r\n,;\s]+/).map(function(s){return s.trim()}).filter(Boolean));
  if(S.ports.length===0)S.ports=["443"];
  renderPorts();
  var map={c1:"name",c2:"apiRoute",c3:"masterKey",c4:"mode",c6:"customDns",c7:"maintenanceHost",c8:"cleanIps",c9:"customLogo",c10:"customTitleColor",a1:"cfAccountId",a2:"cfApiToken",a3:"cfWorkerName",a4:"tgToken",a5:"tgChatId",a6:"tgAdminId",a7:"backupRelay",a8:"nat64Prefix",a9:"activeCarrier",a10:"activeFragment",a11:"iranRouting",c11:"captchaEnabled"};
  Object.keys(map).forEach(function(k){var el=$(k);if(!el)return;var v=c[map[k]];if(el.type==="checkbox")el.checked=v!==false&&v!==undefined?!!v:(map[k]==="captchaEnabled"?true:false);else el.value=v||""});
  var fs=$("a10");
  if(fs){fs.innerHTML="";(c.fragmentPresets||[]).forEach(function(f){var o=document.createElement("option");o.value=f.id;o.textContent=f.name;if(f.id===c.activeFragment)o.selected=true;fs.appendChild(o)})}
  var st=$("sst");if(st){st.textContent=c.isPaused?"متوقف":"فعال";st.style.color=c.isPaused?"var(--danger)":"var(--ios-green)"}
  CAPTCHA_ENABLED=c.captchaEnabled!==false;
}
window.fc=fc;
async function sc(){
  var p={name:$("c1").value,masterKey:$("c3").value,mode:$("c4").value,socketPorts:S.ports.join(","),customDns:$("c6").value,maintenanceHost:$("c7").value,cleanIps:$("c8").value,customLogo:$("c9").value,customTitleColor:$("c10").value,cfAccountId:$("a1").value,cfApiToken:$("a2").value,cfWorkerName:$("a3").value,tgToken:$("a4").value,tgChatId:$("a5").value,tgAdminId:$("a6").value,backupRelay:$("a7").value,nat64Prefix:$("a8").value,activeCarrier:$("a9").value,activeFragment:$("a10").value,iranRouting:$("a11").checked,captchaEnabled:$("c11").checked};
  if(p.masterKey&&p.masterKey!==(S.config.masterKey||"admin")){if(!confirm("⚠️ با تغییر Master Key، رمز admin هم تغییر می‌کند. ادامه؟"))return}
  var r=await ap("/api/sync",{method:"POST",body:JSON.stringify({config:p})});
  if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.config=Object.assign({},S.config,p);fc();renderLogo();Haptic.success();if(p.masterKey&&p.masterKey!==(S.config.masterKey||"admin")){setTimeout(function(){alert("کلید تغییر کرد. با رمز جدید وارد شوید.");lo()},900)}}
  else ts("خطا","error");
}
window.sc=sc;
async function clearLogo(){if(!confirm("حذف؟"))return;var r=await ap("/api/logo",{method:"POST",body:JSON.stringify({action:"clear"})});if(r.data.ok||r.data.success){ts("حذف شد","ok");S.config.customLogo="";renderLogo()}}
window.clearLogo=clearLogo;

/* ══════════ ADVANCED ══════════ */
function renderAdvGrid(){
  var c=$("advGrid");if(!c)return;if(!S.advanced)S.advanced={};
  c.innerHTML=ADV_META.map(function(m){
    if(m.type==="bool")return '<div class="adv-item"><div class="ai-l"><div class="ai-t">'+icn(m.i)+m.t+'</div><div class="ai-d">'+m.d+'</div></div><label class="switch"><input type="checkbox" id="adv_'+m.k+'"'+(S.advanced[m.k]?' checked':'')+' onchange="if(window.onAdvChange)onAdvChange()"><span class="sl2"></span></label></div>';
    if(m.type==="num")return '<div class="adv-row"><label>'+icn(m.i)+m.t+'</label><div class="ai-d">'+m.d+'</div><input type="number" id="adv_'+m.k+'" value="'+(S.advanced[m.k]||0)+'" oninput="if(window.onAdvChange)onAdvChange()"></div>';
    return '<div class="adv-row"><label>'+icn(m.i)+m.t+'</label><div class="ai-d">'+m.d+'</div><input type="text" id="adv_'+m.k+'" value="'+(S.advanced[m.k]||'')+'" oninput="if(window.onAdvChange)onAdvChange()" spellcheck="false"></div>';
  }).join("");
}
function onAdvChange(){var n={};ADV_META.forEach(function(m){var el=$("adv_"+m.k);if(!el)return;if(m.type==="bool")n[m.k]=el.checked;else if(m.type==="num")n[m.k]=parseInt(el.value)||0;else n[m.k]=el.value||""});updateAdvPreview(n)}
window.onAdvChange=onAdvChange;
function updateAdvPreview(a){var p=[];if(a.http3)p.push("h3=1");if(a.tcpFastOpen)p.push("tfo=1");if(a.mux)p.push("mux=1&muxConcurrency="+(a.muxConcurrency||8));if(a.xtls)p.push("xtls=1");if(a.earlyData)p.push("ed=2048");if(a.padding)p.push("padding=1");if(a.keepAlive)p.push("keepAlive="+a.keepAlive);if(a.udpRelay===false)p.push("udp=0");if(a.tlsFragment===false)p.push("fragment=off");if(a.alpn)p.push("alpn="+a.alpn);if(a.ech)p.push("ech=1");var el=$("advPreview");if(el)el.textContent=p.length?p.join(" & "):"هیچ پارامتر پیشرفته‌ای فعال نیست"}
async function loadAdvanced(){var r=await ap("/api/advanced");if(!(r.data.ok||r.data.success)){ts("دسترسی ندارید","warn");return}S.advanced=r.data.data||{};renderAdvGrid();updateAdvPreview(S.advanced)}
window.loadAdvanced=loadAdvanced;
async function saveAdvanced(){var p={};ADV_META.forEach(function(m){var el=$("adv_"+m.k);if(!el)return;if(m.type==="bool")p[m.k]=el.checked;else if(m.type==="num")p[m.k]=parseInt(el.value)||0;else p[m.k]=el.value||""});var r=await ap("/api/advanced",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.advanced=r.data.data||p;updateAdvPreview(S.advanced);Haptic.success()}else ts(r.data.error||"خطا","error")}
window.saveAdvanced=saveAdvanced;
async function resetAdvanced(){if(!confirm("بازنشانی؟"))return;var r=await ap("/api/advanced",{method:"POST",body:JSON.stringify({action:"reset"})});if(r.data.ok||r.data.success){ts("بازنشانی","ok");S.advanced=r.data.data||{};renderAdvGrid();updateAdvPreview(S.advanced)}}
window.resetAdvanced=resetAdvanced;

/* ══════════ RELAY ══════════ */
async function loadRelayPresets(){try{var r=await fetch("/"+AR+"/api/relay-presets",{headers:{"Authorization":"Bearer "+S.token}});var d=await r.json();S.relayPresets=d.presets||[]}catch(e){S.relayPresets=[]}}
window.loadRelayPresets=loadRelayPresets;
function renderRelayGrid(sel){
  var c=$("relayPresetGrid");if(!c)return;
  if(!S.relayPresets.length){c.innerHTML='<div class="empty" style="padding:18px;font-size:11.5px">درحال بارگذاری...</div>';return}
  c.innerHTML=S.relayPresets.map(function(p){return '<div class="rc'+(p.id===sel?' on':'')+'" onclick="if(window.selectRelay)selectRelay(\''+p.id+'\')"><span class="flag">'+p.flag+'</span><div class="name">'+p.name+'</div><div class="count">'+(p.ips?p.ips.length:0)+' IP</div></div>'}).join("");
}
function selectRelay(id){S.selectedRelayPreset=id;renderRelayGrid(id);Haptic.light()}
window.selectRelay=selectRelay;
async function renderRelayHealthBox(){
  var box=$("relayHealthBox");if(!box)return;
  box.innerHTML='<div style="font-size:11px;color:var(--muted);padding:10px;text-align:center">در حال بارگذاری...</div>';
  try{
    var r=await ap("/api/relay-health");
    if(!(r.data.ok||r.data.success)){box.innerHTML='<div style="font-size:11px;color:var(--muted);padding:10px;text-align:center">—</div>';return}
    var relays=r.data.relays||[];
    if(!relays.length){box.innerHTML='<div style="font-size:11px;color:var(--muted);padding:10px;text-align:center">هنوز تست نشده — از دکمه «تست Relay» استفاده کن</div>';return}
    var h='<div style="font-size:11px;font-weight:800;color:var(--text-2);margin-bottom:8px">وضعیت سلامت Relay ها</div>';
    relays.slice(0,8).forEach(function(x){
      var rate=parseFloat(x.rate)||0;
      var color=rate>=70?"var(--ios-green)":rate>=40?"var(--warn)":"var(--danger)";
      h+='<div style="display:flex;justify-content:space-between;padding:7px 10px;border-radius:8px;background:rgba(8,8,20,.5);margin-bottom:5px;font-size:11px"><span style="font-family:JetBrains Mono,monospace">'+x.host+'</span><span style="color:'+color+';font-weight:800">'+x.rate+'</span></div>';
    });
    box.innerHTML=h;
  }catch(e){box.innerHTML='<div style="font-size:11px;color:var(--danger);padding:10px;text-align:center">خطا</div>'}
}
window.renderRelayHealthBox=renderRelayHealthBox;
async function testRelays(){
  ts("در حال تست Relay ها...","info");
  try{
    var r=await ap("/api/relay-test");
    if(r.data.ok||r.data.success){
      var online=(r.data.results||[]).filter(function(x){return x.status==="online"}).length;
      ts(online+" از "+(r.data.results||[]).length+" آنلاین","ok");
      Haptic.success();
      renderRelayHealthBox();
    } else ts("خطا","error");
  }catch(e){ts("خطا","error")}
}
window.testRelays=testRelays;

/* ══════════ STATS ══════════ */
async function ls(){
  var r=await ap("/api/stats");if(!(r.data.ok||r.data.success))return;
  var s=r.data.data||r.data.stats;S.stats=s;
  $("st1").textContent=s.users.total;$("st2").textContent=s.users.active;$("st3").textContent=s.users.paused;$("st4").textContent=s.users.expired;
  $("st5").innerHTML=s.traffic.totalGB+" <small>GB</small>";$("st6").innerHTML=s.traffic.dailyGB+" <small>GB</small>";
  $("st7").textContent=s.system.activeConnections;$("st8").textContent=Math.floor(s.system.uptimeSeconds/3600)+"h";
  var tp="";
  (s.system.topUsers||[]).forEach(function(u,i){
    var pct=u.gb>0?Math.min(100,(u.gb/Math.max(1,s.traffic.totalGB))*100):0;
    var medal=i===0?"trophy":i===1?"chart":"check";
    tp+='<div style="padding:11px;border-radius:12px;background:rgba(255,255,255,.04);margin-bottom:7px;display:flex;align-items:center;gap:11px"><span style="color:var(--violet-2)">'+icn(medal)+'</span><div style="flex:1"><div style="font-weight:700;font-size:12.5px">'+u.name+'</div><div class="prg"><div style="width:'+pct.toFixed(1)+'%"></div></div></div><div style="font-weight:800;color:var(--violet-2)">'+u.gb+' GB</div></div>';
  });
  $("topUsers").innerHTML=tp||'<div class="empty">'+icn("info")+'داده نیست</div>';
  setTimeout(function(){c1();c2()},80);
}
window.ls=ls;

/* ══════════ USERS ══════════ */
async function lu2(){var r=await ap("/api/users");if(!(r.data.ok||r.data.success))return;S.users=r.data.data||r.data.users||[];S.selectedUsers={};updateBulkBar();ru();refreshGroupFilter()}
window.lu2=lu2;
function refreshGroupFilter(){var s=$("groupFilter");if(!s)return;var cur=s.value;s.innerHTML='<option value="">همه گروه‌ها</option>';var seen={};(S.users||[]).forEach(function(u){var g=u.groupId||"default";if(!seen[g]){seen[g]=1;var grp=(S.config.userGroups||[]).find(function(x){return x.id===g});var o=document.createElement("option");o.value=g;o.textContent=grp?grp.name:g;s.appendChild(o)}});s.value=cur||""}
function bd(s){var m={active:["bok-b","check","فعال"],paused:["bw-b","pause","متوقف"],expired:["bd-b","x","منقضی"],"auto-disabled":["bd-b","ban","غیرفعال"]};var v=m[s]||["bm-b","info",s];return '<span class="bdg '+v[0]+'">'+icn(v[1])+v[2]+'</span>'}
function fb(b){if(!b)return"0 GB";var g=b/1073741824;if(g<1)return(b/1048576).toFixed(1)+" MB";return g.toFixed(2)+" GB"}
function relayBadge(u){var flag="",name="";if(u.relayPresetId&&S.relayPresets&&S.relayPresets.length){var preset=S.relayPresets.find(function(p){return p.id===u.relayPresetId});if(preset&&preset.id!=="auto"){flag=preset.flag;name=preset.name}}if(!flag&&u.proxyIpGeo&&u.proxyIpGeo.flag&&u.proxyIpGeo.flag!=="🌐"){flag=u.proxyIpGeo.flag;name=u.proxyIpGeo.country}if(!flag&&(u.relayIps||u.proxyIp)){flag="🎯";name="Relay"}if(!flag)return"";return '<span class="tm" style="background:rgba(90,200,250,.18);color:#67e8f9">'+flag+' '+(name||"Relay")+'</span>'}
function ru(){
  var q=(($("userSearch")&&$("userSearch").value)||"").toLowerCase();
  var gf=($("groupFilter")&&$("groupFilter").value)||"";
  var u=S.users;
  if(q)u=u.filter(function(x){return x.name.toLowerCase().indexOf(q)!==-1||x.id.toLowerCase().indexOf(q)!==-1});
  if(gf)u=u.filter(function(x){return(x.groupId||"default")===gf});
  if(!u.length){$("ub").innerHTML='<tr><td colspan="6" class="empty">'+icn("users")+'خالی</td></tr>';return}
  var h="";
  u.forEach(function(x){
    var us=x.usage?fb(x.usage.total):"0 GB",lm=x.limitTotalReq?fb(x.limitTotalReq*1073741824/6000):"∞",ex=x.expiryMs?new Date(x.expiryMs).toLocaleDateString("fa-IR"):"∞";
    var pct=0;if(x.limitTotalReq&&x.usage&&x.usage.total){var lb=x.limitTotalReq*1073741824/6000;pct=Math.min(100,(x.usage.total/lb)*100)}
    var pc=pct>90?"d":pct>70?"w":"";
    var grp=(S.config.userGroups||[]).find(function(g){return g.id===(x.groupId||"default")});
    var tagH=(x.tags||[]).map(function(t){return '<span class="tm">'+t+'</span>'}).join("");
    var rB=relayBadge(x);
    var ck=S.selectedUsers[x.id]?"checked":"";
    h+='<tr><td><input type="checkbox" '+ck+' onchange="if(window.toggleSelect)toggleSelect(\''+x.id+'\',this.checked)"></td><td><div style="font-weight:800">'+(x.name||"—")+'</div>'+(grp?'<span class="tm" style="background:'+grp.color+'22;color:'+grp.color+'">'+grp.name+'</span>':"")+tagH+rB+'</td><td>'+bd(x.status)+'</td><td><div style="font-weight:700;font-size:12px">'+us+'</div><div style="font-size:9.5px;color:var(--text-2)">/ '+lm+'</div><div class="prg '+pc+'"><div style="width:'+pct.toFixed(1)+'%"></div></div></td><td style="font-size:12px">'+ex+'</td><td style="text-align:left">'+iBtn("link","sun",x.id,"ساب")+iBtn("pause","tu",x.id,"توقف")+iBtn("edit","eu",x.id,"ویرایش")+iBtn("trash","du",x.id,"حذف","bd")+'</td></tr>';
  });
  $("ub").innerHTML=h;
}
window.ru=ru;
function iBtn(ic,handler,arg,title,cls){return '<button class="btn '+(cls||"bg2")+' bs ibtn" onclick="if(window.'+handler+')window.'+handler+'(\''+arg+'\')" title="'+title+'">'+icn(ic)+'</button>'}
function sun(id){var u=S.users.find(function(x){return x.id===id});if(!u)return;window.open(location.origin+"/"+AR+"?sub="+encodeURIComponent(u.name),"_blank")}
window.sun=sun;
function toggleSelect(id,ck){if(ck)S.selectedUsers[id]=1;else delete S.selectedUsers[id];updateBulkBar()}
window.toggleSelect=toggleSelect;
function updateBulkBar(){var n=Object.keys(S.selectedUsers).length;if(n>0){$("bulkBar").classList.add("on");$("bulkCount").textContent=n}else $("bulkBar").classList.remove("on");var sa=$("selAll");if(sa)sa.checked=false}
function bulkClear(){S.selectedUsers={};updateBulkBar();ru()}
window.bulkClear=bulkClear;
async function bulkAction(action){var ids=Object.keys(S.selectedUsers);if(ids.length===0)return;var r=await ap("/api/users/bulk-action",{method:"POST",body:JSON.stringify({ids:ids,action:action})});if(r.data.ok||r.data.success){ts("انجام شد ("+r.data.affected+")","ok");bulkClear();lu2();Haptic.success()}}
window.bulkAction=bulkAction;
async function bulkReset(){var ids=Object.keys(S.selectedUsers);if(ids.length===0)return;if(!confirm("ریست مصرف "+ids.length+" کاربر؟"))return;var r=await ap("/api/users/bulk-action",{method:"POST",body:JSON.stringify({ids:ids,action:"reset"})});if(r.data.ok||r.data.success){ts("انجام شد","ok");bulkClear();lu2()}}
window.bulkReset=bulkReset;

/* ⚡ FIX: ou بدون تاخیر — modal اول باز می‌شود */
function ou(){
  S.editU=null;
  $("umt").textContent="کاربر جدید";
  ["u1","u2","u3","u4","u5","u7","u10","u11","uRelayIps"].forEach(function(k){if($(k))$(k).value=""});
  if($("u8"))$("u8").value="none";
  if($("u9"))$("u9").value="";
  refreshGroupSelect();
  S.selectedRelayPreset="auto";
  $("um").classList.add("on");
  Haptic.light();
  // Async load relay presets AFTER opening modal
  var box=$("relayPresetGrid");
  if(!S.relayPresets.length){
    if(box)box.innerHTML='<div class="empty" style="padding:18px;font-size:11.5px">در حال بارگذاری...</div>';
    loadRelayPresets().then(function(){renderRelayGrid("auto")}).catch(function(){renderRelayGrid("auto")});
  } else {
    renderRelayGrid("auto");
  }
}
window.ou=ou;
function cu(){$("um").classList.remove("on")}
window.cu=cu;
function refreshGroupSelect(){var s=$("u6");if(!s)return;s.innerHTML="";(S.config.userGroups||[]).forEach(function(g){var o=document.createElement("option");o.value=g.id;o.textContent=g.name;s.appendChild(o)})}
function eu(id){
  var u=S.users.find(function(x){return x.id===id});if(!u)return;
  S.editU=u;
  $("umt").textContent="ویرایش: "+u.name;
  $("u1").value=u.name||"";
  $("u2").value=u.limitTotalReq?(u.limitTotalReq/6000).toFixed(2):"";
  $("u3").value=u.limitDailyReq?(u.limitDailyReq/6000).toFixed(2):"";
  $("u4").value=u.expiryMs?Math.max(0,Math.ceil((u.expiryMs-Date.now())/86400000)):"";
  $("u5").value=u.notes||"";
  $("u7").value=u.maxConfigs||"";
  $("u9").value=u.isp||"";
  $("u10").value=u.bandwidthKbps||"";
  $("u11").value=(u.tags||[]).join(",");
  $("uRelayIps").value=u.relayIps||"";
  var c=(S.config.autoResetCycles||{})[u.id];$("u8").value=c?c.type:"none";
  refreshGroupSelect();$("u6").value=u.groupId||"default";
  S.selectedRelayPreset=u.relayPresetId||"auto";
  $("um").classList.add("on");
  Haptic.light();
  var box=$("relayPresetGrid");
  if(!S.relayPresets.length){
    if(box)box.innerHTML='<div class="empty" style="padding:18px;font-size:11.5px">در حال بارگذاری...</div>';
    loadRelayPresets().then(function(){renderRelayGrid(S.selectedRelayPreset)}).catch(function(){renderRelayGrid(S.selectedRelayPreset)});
  } else {
    renderRelayGrid(S.selectedRelayPreset);
  }
}
window.eu=eu;
async function su2(){
  var n=$("u1").value.trim();if(!n){ts("نام الزامی","warn");return}
  var tagsArr=$("u11").value.split(",").map(function(t){return t.trim()}).filter(Boolean);
  var p={name:n,groupId:$("u6").value,isp:$("u9").value||null,tags:tagsArr,trafficLimit:$("u2").value||0,dailyLimit:$("u3").value||0,expiryDays:$("u4").value||0,notes:$("u5").value,maxConfigs:$("u7").value||0,bandwidthKbps:$("u10").value||0,relayIps:$("uRelayIps").value,relayMode:"single",relayPresetId:S.selectedRelayPreset||"",autoReset:{type:$("u8").value}};
  var r;if(S.editU)r=await ap("/api/users?id="+encodeURIComponent(S.editU.id),{method:"PUT",body:JSON.stringify(p)});else r=await ap("/api/users",{method:"POST",body:JSON.stringify(p)});
  if(r.data.ok||r.data.success){ts("ذخیره شد","ok");cu();lu2();ls();Haptic.success()}else ts(r.data.error||"خطا","error");
}
window.su2=su2;
async function tu(id){var r=await ap("/api/users?id="+encodeURIComponent(id)+"&action=toggle",{method:"POST"});if(r.data.ok||r.data.success){ts("✓","ok");lu2()}}
window.tu=tu;
async function du(id){if(!confirm("حذف؟"))return;var r=await ap("/api/users?id="+encodeURIComponent(id),{method:"DELETE"});if(r.data.ok||r.data.success){ts("حذف شد","ok");lu2();ls()}}
window.du=du;

/* ⚡ FIX: export CSV با fetch + blob (بدون 401) */
async function exportCsv(){
  try{
    ts("در حال ساخت فایل...","info");
    var r = await fetch("/"+AR+"/api/users/bulk", {
      headers: { "Authorization": "Bearer " + S.token }
    });
    if(!r.ok){
      ts("خطا در دانلود ("+r.status+")","error");
      return;
    }
    var blob = await r.blob();
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "hamed-users-" + new Date().toISOString().split("T")[0] + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function(){URL.revokeObjectURL(url)},100);
    ts("دانلود شد ✓","ok");
    Haptic.success();
  }catch(e){
    console.error("exportCsv:",e);
    ts("خطا در دانلود","error");
  }
}
window.exportCsv=exportCsv;
function openImport(){$("csvData").value="";$("im").classList.add("on")}
window.openImport=openImport;
function ci(){$("im").classList.remove("on")}
window.ci=ci;
async function doImport(){var c=$("csvData").value.trim();if(!c){ts("خالی","warn");return}var r=await ap("/api/users/bulk",{method:"POST",body:JSON.stringify({csv:c})});if(r.data.ok||r.data.success){ts((r.data.created||0)+" اضافه شد","ok");ci();lu2()}}
window.doImport=doImport;

/* ══════════ GROUPS ══════════ */
async function lgroups(){var r=await ap("/api/groups");if(!(r.data.ok||r.data.success))return;S.groups=r.data.data||r.data.groups||[];S.config.userGroups=S.groups;var g=S.groups;if(!g.length){$("groupsGrid").innerHTML='<div class="empty">'+icn("group")+'خالی</div>';return}var h="";g.forEach(function(x){h+='<div class="nc"><div style="font-size:14px;font-weight:900;margin-bottom:9px;display:flex;align-items:center;gap:10px"><span style="display:inline-block;width:11px;height:11px;border-radius:50%;background:'+x.color+';box-shadow:0 0 10px '+x.color+'"></span>'+x.name+'</div><div style="font-size:11.5px;color:var(--text-2);line-height:1.9">'+x.limitTotalGb+' GB · '+x.expiryDays+' روز</div><div style="display:flex;gap:6px;margin-top:11px">'+(x.id!=="default"?iBtn("edit","eg",x.id,"ویرایش")+iBtn("trash","dg",x.id,"حذف","bd"):"")+'</div></div>'});$("groupsGrid").innerHTML=h}
window.lgroups=lgroups;
function og(){S.editG=null;$("gmt").textContent="گروه جدید";["g1","g2","g3","g4","g5","g6"].forEach(function(k){$(k).value=""});$("gml").classList.add("on")}
window.og=og;
function cg(){$("gml").classList.remove("on")}
window.cg=cg;
function eg(id){var g=S.groups.find(function(x){return x.id===id});if(!g)return;S.editG=g;$("gmt").textContent="ویرایش گروه";$("g1").value=g.name;$("g2").value=g.limitTotalGb||"";$("g3").value=g.limitDailyGb||"";$("g4").value=g.expiryDays||"";$("g5").value=g.maxConfigs||"";$("g6").value=g.connLimit||"";$("gml").classList.add("on")}
window.eg=eg;
async function sg2(){var n=$("g1").value.trim();if(!n)return;var p={action:S.editG?"update":"create",id:S.editG?S.editG.id:null,name:n,limitTotalGb:$("g2").value||0,limitDailyGb:$("g3").value||0,expiryDays:$("g4").value||0,maxConfigs:$("g5").value||0,connLimit:$("g6").value||0,color:S.editG?S.editG.color:"#"+Math.floor(Math.random()*16777215).toString(16).padStart(6,"0")};var r=await ap("/api/groups",{method:"POST",body:JSON.stringify(p)});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");cg();lgroups()}}
window.sg2=sg2;
async function dg(id){if(!confirm("حذف؟"))return;var r=await ap("/api/groups",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lgroups()}}
window.dg=dg;

/* ══════════ MANAGERS ══════════ */
var ALLP=["users","settings","advanced","managers","apikeys","logs","stats","subscriptions","nodes","backup","groups","cron","webhooks","regions","inbounds"];
async function lm(){var r=await ap("/api/managers");if(!(r.data.ok||r.data.success)){$("mb").innerHTML='<tr><td colspan="5" class="empty">دسترسی نیست</td></tr>';return}S.managers=r.data.data||r.data.managers||[];var m=S.managers;if(!m.length){$("mb").innerHTML='<tr><td colspan="5" class="empty">خالی</td></tr>';return}var h="";m.forEach(function(x){var pm=x.isRoot?icn("crown")+" Root":(x.permissions||[]).length+" دسترسی";var st=x.isActive!==false?'<span class="bdg bok-b">'+icn("check")+'فعال</span>':'<span class="bdg bd-b">'+icn("x")+'غیرفعال</span>';var ll=x.lastLogin?new Date(x.lastLogin).toLocaleDateString("fa-IR"):"—";h+='<tr><td style="font-weight:800">'+x.username+'</td><td style="font-size:12px">'+pm+'</td><td>'+st+'</td><td style="font-size:12px">'+ll+'</td><td style="text-align:left">';if(!x.isRoot)h+=iBtn("edit","em",x.id,"ویرایش")+iBtn("trash","dm",x.id,"حذف","bd");else h+="—";h+='</td></tr>'});$("mb").innerHTML=h}
window.lm=lm;
function renderPerms(sel){var c=$("mp");c.innerHTML="";ALLP.forEach(function(p){var e=document.createElement("div");e.className="perm"+(sel.indexOf(p)!==-1?" on":"");e.textContent=p;e.setAttribute("data-perm",p);e.onclick=function(){this.classList.toggle("on");Haptic.light()};c.appendChild(e)})}
function om(){S.editM=null;$("mmt").textContent="مدیر جدید";$("m1").value="";$("m2").value="";$("m1").disabled=false;renderPerms(["users"]);$("mm2").classList.add("on")}
window.om=om;
function cm(){$("mm2").classList.remove("on")}
window.cm=cm;
function em(id){var m=S.managers.find(function(x){return x.id===id});if(!m||m.isRoot)return;S.editM=m;$("mmt").textContent="ویرایش مدیر";$("m1").value=m.username;$("m1").disabled=true;$("m2").value="";renderPerms(m.permissions||[]);$("mm2").classList.add("on")}
window.em=em;
async function sm(){var u=$("m1").value.trim(),p=$("m2").value;var perms=Array.prototype.map.call($$(".perm.on"),function(e){return e.getAttribute("data-perm")});if(!u){ts("نام الزامی","warn");return}var r;if(S.editM){if(!p)r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"update",id:S.editM.id,permissions:perms})});else{if(p.length<4){ts("رمز حداقل ۴ کاراکتر","warn");return}r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"update",id:S.editM.id,password:p,permissions:perms})})}}else{if(!p||p.length<4){ts("رمز حداقل ۴ کاراکتر","warn");return}r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"create",username:u,password:p,permissions:perms})})}if(r.data.ok||r.data.success){ts("ذخیره شد","ok");cm();lm();Haptic.success()}else ts(r.data.error||"خطا","error")}
window.sm=sm;
async function dm(id){if(!confirm("حذف؟"))return;var r=await ap("/api/managers",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lm()}}
window.dm=dm;

/* ══════════ SESSIONS ══════════ */
async function lsess(){var r=await ap("/api/sessions");var b=$("sessBody");if(!(r.data.ok||r.data.success)){b.innerHTML='<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>';return}var ss=r.data.data||r.data.sessions||[];if(!ss.length){b.innerHTML='<tr><td colspan="4" class="empty">خالی</td></tr>';return}var h="";ss.forEach(function(s){h+='<tr><td style="font-weight:700">'+s.username+(s.isRoot?icn("crown"):"")+(s.current?' <span class="bdg bok-b">'+icn("check")+'فعلی</span>':"")+'</td><td class="mc2">'+s.ip+'</td><td style="font-size:11px">'+new Date(s.createdAt).toLocaleString("fa-IR")+'</td><td style="text-align:left">'+(s.current?"—":iBtn("x","rs",s.fullToken,"قطع","bd"))+'</td></tr>'});b.innerHTML=h}
window.lsess=lsess;
async function rs(t){if(!confirm("قطع؟"))return;var r=await ap("/api/sessions",{method:"POST",body:JSON.stringify({action:"revoke",token:t})});if(r.data.ok||r.data.success){ts("قطع شد","ok");lsess()}}
window.rs=rs;
async function revokeAll(){if(!confirm("قطع همه؟"))return;var r=await ap("/api/sessions",{method:"POST",body:JSON.stringify({action:"revokeAll"})});if(r.data.ok||r.data.success){ts("قطع شد","ok");lsess()}}
window.revokeAll=revokeAll;

/* ══════════ NODES ══════════ */
async function lnodes(){var r=await ap("/api/nodes");if(!(r.data.ok||r.data.success))return;S.nodes=r.data.data||r.data||[];var n=S.nodes;if(!n.length){$("nodesGrid").innerHTML='<div class="empty">'+icn("server")+'نودی نیست</div>';return}var h="";n.forEach(function(x){var hh=x.lastHealth||{};var st=hh.status==="online"?icn("check")+" آنلاین":hh.status==="offline"?icn("x")+" آفلاین":hh.status?icn("alert")+" خطا":icn("info")+" تست‌نشده";h+='<div class="nc"><div style="font-weight:800;font-size:12.5px;margin-bottom:7px">'+(x.name||x.url)+'</div><div class="mc2" style="font-size:10px;margin-bottom:9px;word-break:break-all">'+x.url+'</div><div style="font-size:11.5px;display:flex;align-items:center;gap:7px">'+st+(hh.latency>=0?" · "+hh.latency+"ms":"")+'</div><div style="margin-top:11px">'+iBtn("trash","dnode",x.url,"حذف","bd")+'</div></div>'});$("nodesGrid").innerHTML=h}
window.lnodes=lnodes;
function onNode(){["n1","n2","n3","n4"].forEach(function(k){$(k).value=""});$("nm").classList.add("on")}
window.onNode=onNode;
function cn(){$("nm").classList.remove("on")}
window.cn=cn;
async function sn(){var url=$("n2").value.trim();if(!url){ts("آدرس الزامی","warn");return}var r=await ap("/api/nodes",{method:"POST",body:JSON.stringify({action:"add",url:url,apiKey:$("n3").value,name:$("n1").value,group:$("n4").value||"default"})});if(r.data.ok||r.data.success){ts("اضافه شد","ok");cn();lnodes()}}
window.sn=sn;
async function dnode(url){if(!confirm("حذف؟"))return;var r=await ap("/api/nodes",{method:"POST",body:JSON.stringify({action:"remove",url:url})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lnodes()}}
window.dnode=dnode;
async function healthAll(){ts("تست...","info");var r=await ap("/api/nodes/health");if(r.data.ok||r.data.success){ts("انجام شد","ok");lnodes()}}
window.healthAll=healthAll;

/* ══════════ REGIONS / CLEAN IP ══════════ */
async function lregions(){var r=await ap("/api/regions");if(!(r.data.ok||r.data.success))return;var d=r.data.data||r.data;S.regions=d.regions||[];S.activeRegions=d.active||[];var reg=S.regions;if(!reg.length){$("regionsGrid").innerHTML='<div class="empty">'+icn("globe")+'خالی</div>'}else{var h="";reg.forEach(function(x){var a=S.activeRegions.indexOf(x.id)!==-1;h+='<div class="nc" onclick="if(window.togRegion)togRegion(\''+x.id+'\')" style="cursor:pointer;border-color:'+(a?"rgba(90,200,250,.5)":"var(--bglass)")+'"><div style="display:flex;align-items:center;gap:11px;margin-bottom:9px"><span style="font-size:24px">'+x.flag+'</span><div style="flex:1"><div style="font-weight:800;font-size:13px">'+x.name+'</div><div style="font-size:10px;color:var(--text-2)">'+x.ips.length+' آی‌پی</div></div>'+(a?'<span class="bdg bok-b">'+icn("check")+'</span>':"")+'</div>'+(x.id!=="de"&&x.id!=="ae"&&x.id!=="us"?'<div onclick="event.stopPropagation()">'+iBtn("trash","dregion",x.id,"حذف","bd")+'</div>':"")+'</div>'});$("regionsGrid").innerHTML=h}lcleanResults()}
window.lregions=lregions;
async function togRegion(id){var r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"toggle",id:id})});if(r.data.ok||r.data.success){S.activeRegions=r.data.active;lregions();Haptic.light()}}
window.togRegion=togRegion;
function oregion(){$("r1").value="";$("r2").value="";$("r3").value="";$("rm").classList.add("on")}
window.oregion=oregion;
function cr(){$("rm").classList.remove("on")}
window.cr=cr;
async function sr2(){var n=$("r1").value.trim(),f=$("r2").value.trim()||"🌐",ips=$("r3").value.trim();if(!n||!ips)return;var r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"add",name:n,flag:f,ips:ips})});if(r.data.ok||r.data.success){ts("اضافه شد","ok");cr();lregions()}}
window.sr2=sr2;
async function dregion(id){if(!confirm("حذف؟"))return;var r=await ap("/api/regions",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lregions()}}
window.dregion=dregion;
async function lcleanResults(){var r=await ap("/api/cleanip/results");if(!(r.data.ok||r.data.success))return;var c=r.data.data||r.data.cache||{};$("autoClean").checked=!!(S.config&&S.config.autoCleanIpTest);if(c.testedAt)$("cleanInfo").textContent="آخرین: "+new Date(c.testedAt).toLocaleString("fa-IR");else $("cleanInfo").textContent="تست نشده";var full=c.full||[];if(!full.length){$("cleanBody").innerHTML='<tr><td colspan="2" class="empty">داده نیست</td></tr>';return}var h="";full.slice(0,15).forEach(function(c2){var col=c2.latency<200?"var(--ios-green)":c2.latency<500?"var(--warn)":"var(--danger)";h+='<tr><td class="mc2">'+c2.ip+'</td><td style="font-weight:800;color:'+col+'">'+c2.latency+' ms</td></tr>'});$("cleanBody").innerHTML=h}
window.lcleanResults=lcleanResults;
async function runCleanIp(){ts("تست...","info");var r=await ap("/api/cleanip/test",{method:"POST"});if(r.data.ok||r.data.success){ts("تمام شد","ok");lcleanResults()}}
window.runCleanIp=runCleanIp;

/* ══════════ ISP ══════════ */
async function lisp(){var r=await ap("/api/isp-templates");if(!(r.data.ok||r.data.success))return;S.ispTemplates=r.data.data||{};var t=S.ispTemplates;var keys=Object.keys(t);if(!keys.length){$("ispGrid").innerHTML='<div class="empty">خالی</div>';return}var h="";keys.forEach(function(k){var x=t[k];h+='<div class="nc"><div style="font-weight:800;margin-bottom:11px">'+x.name+' <span class="tm">'+k+'</span></div><div class="fg"><div class="fr"><div class="fd"><label>Fragment</label><input id="isp_'+k+'_frag" value="'+(x.fragment||"")+'"></div><div class="fd"><label>Ports</label><input id="isp_'+k+'_ports" value="'+(x.ports||"")+'"></div></div><div class="fr"><div class="fd"><label>Agent</label><input id="isp_'+k+'_agent" value="'+(x.agent||"chrome")+'"></div><div class="fd"><label>Extra SNI</label><input id="isp_'+k+'_sni" value="'+(x.extraSni||"")+'"></div></div></div></div>'});$("ispGrid").innerHTML=h}
window.lisp=lisp;
async function saveIsp(){var t={};Object.keys(S.ispTemplates).forEach(function(k){t[k]={name:S.ispTemplates[k].name,fragment:$("isp_"+k+"_frag").value,ports:$("isp_"+k+"_ports").value,agent:$("isp_"+k+"_agent").value,extraSni:$("isp_"+k+"_sni").value}});var r=await ap("/api/isp-templates",{method:"POST",body:JSON.stringify({templates:t})});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.ispTemplates=t}}
window.saveIsp=saveIsp;

/* ══════════ CRON — FIXED ══════════ */
async function lcron(){
  try{
    var r=await ap("/api/cron");
    if(!(r.data.ok||r.data.success))return;
    S.cronJobs=r.data.data||[];
    S.cronActions=r.data.actions||[];
    var j=S.cronJobs;
    if(!j.length){$("cronGrid").innerHTML='<div class="empty">'+icn("clock")+'خالی</div>';return}
    var h="";
    j.forEach(function(x){
      var st=x.lastStatus==="ok"?'<span class="bdg bok-b">'+icn("check")+'</span>':x.lastStatus==="error"?'<span class="bdg bd-b">'+icn("x")+'</span>':"";
      h+='<div class="nc"><div style="font-weight:800;margin-bottom:7px">'+x.name+' '+st+'</div><div style="font-size:11px;color:var(--text-2);line-height:1.8">'+x.action+'<br>هر '+x.intervalMinutes+' دقیقه</div><div style="display:flex;gap:6px;margin-top:11px">'+iBtn("play","runCron",x.id,"اجرا")+iBtn("trash","dcron",x.id,"حذف","bd")+'</div></div>';
    });
    $("cronGrid").innerHTML=h;
  }catch(e){console.error("lcron:",e)}
}
window.lcron=lcron;
async function ocron(){
  try{
    S.editCron=null;
    if(!S.cronActions||!S.cronActions.length){
      try{ var r0=await ap("/api/cron"); S.cronActions=r0.data.actions||[]; }catch(e){}
    }
    $("comt").textContent="Cron جدید";
    $("cj1").value="";
    $("cj4").value=60;
    $("cj5").checked=true;
    $("cj3").value="{}";
    var s=$("cj2");
    s.innerHTML="";
    (S.cronActions||[]).forEach(function(a){
      var o=document.createElement("option");
      o.value=a.id;
      o.textContent=a.label;
      s.appendChild(o);
    });
    $("com").classList.add("on");
  }catch(e){console.error("ocron:",e);ts("خطا","error")}
}
window.ocron=ocron;
function ccj(){$("com").classList.remove("on")}
window.ccj=ccj;
async function scj(){
  try{
    var n=$("cj1").value.trim();
    if(!n){ts("نام الزامی","warn");return}
    var params={};
    try{params=JSON.parse($("cj3").value||"{}")}catch(e){ts("JSON نامعتبر","warn");return}
    var p={action:S.editCron?"update":"create",id:S.editCron?S.editCron.id:null,name:n,jobAction:$("cj2").value,params:params,intervalMinutes:$("cj4").value||60,enabled:$("cj5").checked};
    var r=await ap("/api/cron",{method:"POST",body:JSON.stringify(p)});
    if(r.data.ok||r.data.success){ts("ذخیره شد","ok");ccj();lcron();Haptic.success()}
    else ts(r.data.error||"خطا","error");
  }catch(e){ts("خطا","error")}
}
window.scj=scj;
async function dcron(id){if(!confirm("حذف؟"))return;var r=await ap("/api/cron",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lcron()}}
window.dcron=dcron;
async function runCron(id){ts("اجرا...","info");var r=await ap("/api/cron",{method:"POST",body:JSON.stringify({action:"run",id:id})});if(r.data.ok||r.data.success){ts("انجام شد","ok");lcron()}}
window.runCron=runCron;

/* ══════════ WEBHOOKS — FIXED ══════════ */
async function lwh(){
  try{
    var r=await ap("/api/webhooks");
    if(!(r.data.ok||r.data.success))return;
    S.webhooks=r.data.data||[];
    S.webhookEvents=r.data.events||[];
    var w=S.webhooks;
    if(!w.length){$("whGrid").innerHTML='<div class="empty">'+icn("webhook")+'خالی</div>';return}
    var h="";
    w.forEach(function(x){
      h+='<div class="nc"><div style="font-weight:800;font-size:11.5px;margin-bottom:7px;word-break:break-all">'+x.url+'</div><div style="font-size:10px;color:var(--text-2);margin-bottom:9px">'+(x.events||[]).join(", ")+'</div><div style="margin-top:9px;display:flex;gap:9px;align-items:center"><label class="switch"><input type="checkbox" '+(x.enabled?"checked":"")+' onchange="if(window.togWh)togWh(\''+x.id+'\',this.checked)"><span class="sl2"></span></label><button class="btn bg2 bs" onclick="if(window.testWh)testWh(\''+x.id+'\')">'+icn("zap")+'</button>'+iBtn("trash","dwh",x.id,"حذف","bd")+'</div></div>';
    });
    $("whGrid").innerHTML=h;
  }catch(e){console.error("lwh:",e)}
}
window.lwh=lwh;
async function owh(){
  try{
    S.editWh=null;
    if(!S.webhookEvents||!S.webhookEvents.length){
      try{ var r0=await ap("/api/webhooks"); S.webhookEvents=r0.data.events||[]; }catch(e){}
    }
    $("wh1").value="";
    var c=$("whEvents");
    c.innerHTML="";
    (S.webhookEvents||[]).forEach(function(e){
      var d=document.createElement("div");
      d.className="perm";
      d.textContent=e;
      d.setAttribute("data-ev",e);
      d.onclick=function(){this.classList.toggle("on");Haptic.light()};
      c.appendChild(d);
    });
    $("whm").classList.add("on");
  }catch(e){console.error("owh:",e);ts("خطا","error")}
}
window.owh=owh;
function cwh(){$("whm").classList.remove("on")}
window.cwh=cwh;
async function swh(){
  try{
    var url=$("wh1").value.trim();
    if(!url){ts("URL الزامی","warn");return}
    var ev=Array.prototype.map.call($$("#whEvents .perm.on"),function(e){return e.getAttribute("data-ev")});
    if(!ev.length){ts("حداقل یک رویداد","warn");return}
    var r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"create",url:url,events:ev})});
    if(r.data.ok||r.data.success){ts("ذخیره شد","ok");cwh();lwh();Haptic.success()}
    else ts(r.data.error||"خطا","error");
  }catch(e){ts("خطا","error")}
}
window.swh=swh;
async function togWh(id,en){await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"update",id:id,enabled:en})})}
window.togWh=togWh;
async function testWh(id){ts("تست...","info");var r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"test",id:id})});if(r.data.ok||r.data.success)ts("موفق "+(r.data.status||200),"ok");else ts("خطا","error")}
window.testWh=testWh;
async function dwh(id){if(!confirm("حذف؟"))return;var r=await ap("/api/webhooks",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lwh()}}
window.dwh=dwh;

/* ══════════ WORKFLOWS — FIXED ══════════ */
async function lwf(){
  try{
    var r=await ap("/api/workflows");
    if(!(r.data.ok||r.data.success))return;
    var d=r.data.data||{};
    S.workflows=d.workflows||[];
    S.workflowTriggers=d.triggers||[];
    S.workflowActions=d.actions||[];
    var w=S.workflows;
    if(!w.length){$("wfGrid").innerHTML='<div class="empty">'+icn("workflow")+'خالی</div>';return}
    var h="";
    w.forEach(function(x){
      var st=x.enabled?' <span class="bdg bok-b">'+icn("check")+'</span>':' <span class="bdg bd-b">'+icn("x")+'</span>';
      h+='<div class="nc"><div style="font-weight:800;margin-bottom:7px">'+x.name+st+'</div><div style="font-size:11px;color:var(--text-2);margin-bottom:9px">'+x.trigger+' · '+(x.actions||[]).length+' action</div><div style="display:flex;gap:6px">'+iBtn("trash","dwf",x.id,"حذف","bd")+'</div></div>';
    });
    $("wfGrid").innerHTML=h;
  }catch(e){console.error("lwf:",e)}
}
window.lwf=lwf;
async function owf(){
  try{
    S.editWf=null;
    if(!S.workflowTriggers||!S.workflowTriggers.length){
      try{ var r0=await ap("/api/workflows/actions"); S.workflowTriggers=(r0.data.data||{}).triggers||[]; S.workflowActions=(r0.data.data||{}).actions||[]; }catch(e){}
    }
    var s=$("wf2");
    s.innerHTML="";
    (S.workflowTriggers||[]).forEach(function(t){
      var o=document.createElement("option");
      o.value=t.id;
      o.textContent=t.label;
      s.appendChild(o);
    });
    $("wf1").value="";
    $("wf3").value='[{"type":"send.telegram","params":{"message":"سلام {name}"}}]';
    $("wfm").classList.add("on");
  }catch(e){console.error("owf:",e);ts("خطا","error")}
}
window.owf=owf;
function cwf(){$("wfm").classList.remove("on")}
window.cwf=cwf;
async function swf(){
  try{
    var n=$("wf1").value.trim();
    if(!n){ts("نام الزامی","warn");return}
    var ac=[];
    try{ac=JSON.parse($("wf3").value||"[]")}catch(e){ts("JSON نامعتبر","warn");return}
    var p={action:S.editWf?"update":"create",id:S.editWf?S.editWf.id:null,name:n,trigger:$("wf2").value,actions:ac,enabled:true};
    var r=await ap("/api/workflows",{method:"POST",body:JSON.stringify(p)});
    if(r.data.ok||r.data.success){ts("ذخیره شد","ok");cwf();lwf();Haptic.success()}
    else ts(r.data.error||"خطا","error");
  }catch(e){ts("خطا","error")}
}
window.swf=swf;
async function dwf(id){if(!confirm("حذف؟"))return;var r=await ap("/api/workflows",{method:"POST",body:JSON.stringify({action:"delete",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lwf()}}
window.dwf=dwf;

/* ══════════ BANNED / CRISIS / WEATHER / PRED / SUGG / ANOM ══════════ */
async function lbanned(){var r=await ap("/api/banned");if(!(r.data.ok||r.data.success))return;S.banned=r.data.data||[];var b=S.banned;if(!b.length){$("banBody").innerHTML='<tr><td colspan="4" class="empty">خالی</td></tr>';return}var h="";b.forEach(function(x){h+='<tr><td class="mc2">'+x.ip+'</td><td style="font-size:12px">'+(x.reason||"—")+'</td><td style="font-size:11px">'+new Date(x.bannedAt).toLocaleString("fa-IR")+'</td><td style="text-align:left">'+iBtn("check","unbanOne",x.ip,"رفع")+'</td></tr>'});$("banBody").innerHTML=h}
window.lbanned=lbanned;
function oban(){$("b1").value="";$("b2").value="";$("bam").classList.add("on")}
window.oban=oban;
function cban(){$("bam").classList.remove("on")}
window.cban=cban;
async function doban(){var ip=$("b1").value.trim();if(!ip)return;var r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"ban",ip:ip,reason:$("b2").value})});if(r.data.ok||r.data.success){ts("Ban شد","ok");cban();lbanned()}}
window.doban=doban;
async function unbanOne(ip){var r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"unban",ip:ip})});if(r.data.ok||r.data.success){ts("رفع شد","ok");lbanned()}}
window.unbanOne=unbanOne;
async function clearBanned(){if(!confirm("پاک همه؟"))return;var r=await ap("/api/banned",{method:"POST",body:JSON.stringify({action:"clear"})});if(r.data.ok||r.data.success){ts("پاک شد","ok");lbanned()}}
window.clearBanned=clearBanned;
async function lcrisis(){var r=await ap("/api/crisis");if(!(r.data.ok||r.data.success))return;S.crisisPresets=r.data.presets||[];S.crisisHistory=r.data.history||[];var h="";S.crisisPresets.forEach(function(x){h+='<div class="nc"><div style="font-weight:800;font-size:12.5px;margin-bottom:7px">'+x.title+'</div><div style="font-size:10.5px;color:var(--text-2);line-height:1.7">'+x.text.slice(0,100)+'...</div><button class="btn bp bs" style="margin-top:11px" onclick="if(window.sendPreset)sendPreset(\''+x.id+'\')">ارسال</button></div>'});$("crisisPresets").innerHTML=h||'<div class="empty">خالی</div>';var hh="";(S.crisisHistory||[]).slice(0,10).forEach(function(x){hh+='<div style="padding:11px;border-radius:12px;background:rgba(255,255,255,.04);margin-bottom:7px"><div style="font-size:10.5px;color:var(--muted-2)">'+new Date(x.ts).toLocaleString("fa-IR")+'</div><div style="font-size:12px;margin-top:5px">'+x.message.slice(0,80)+'</div><div style="font-size:10px;margin-top:5px">'+icn("check")+x.sent+' · '+icn("x")+x.failed+'</div></div>'});$("crisisHistory").innerHTML=hh||'<div class="empty">خالی</div>'}
window.lcrisis=lcrisis;
async function sendPreset(id){var p=S.crisisPresets.find(function(x){return x.id===id});if(!p||!confirm("ارسال؟"))return;var r=await ap("/api/crisis",{method:"POST",body:JSON.stringify({action:"send",presetId:id})});if(r.data.success||r.data.ok){ts("ارسال به "+r.data.sent,"ok");lcrisis()}}
window.sendPreset=sendPreset;
async function sendCrisis(){var m=$("crisisMsg").value.trim();if(!m||!confirm("ارسال؟"))return;var r=await ap("/api/crisis",{method:"POST",body:JSON.stringify({action:"send",message:m})});if(r.data.success||r.data.ok){ts("ارسال به "+r.data.sent,"ok");$("crisisMsg").value="";lcrisis()}}
window.sendCrisis=sendCrisis;
async function lweather(){var r=await ap("/api/network-weather");if(!(r.data.ok||r.data.success))return;var d=r.data.data||{};var ic=d.status==="storm"?"storm":d.status==="rainy"?"rain":d.status==="cloudy"?"cloud":"sun";$("weatherBox").innerHTML='<div class="wbox"><div class="em">'+icn(ic)+'</div><div style="flex:1"><div style="font-size:21px;font-weight:900">'+d.status.toUpperCase()+'</div><div style="font-size:12.5px;color:var(--text-2);margin-top:7px">سلامت: '+d.health+'% · کاربران: '+d.active+'/'+d.total+'</div><div style="font-size:11.5px;color:var(--text-2);margin-top:5px">نودها: '+d.nodesOnline+'/'+d.nodesTotal+'</div>'+(d.cfUsage!==null?'<div style="font-size:11.5px;color:var(--text-2);margin-top:5px">CF: '+d.cfUsage+' ('+d.cfPct+'%)</div>':"")+'<div class="prg" style="margin-top:11px"><div style="width:'+d.health+'%"></div></div></div></div>'}
window.lweather=lweather;
async function lpredictive(){var r=await ap("/api/predictive");if(!(r.data.ok||r.data.success))return;var d=r.data.data||{};$("predictiveBox").innerHTML='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:13px"><div><div style="font-size:10.5px;color:var(--text-2)">میانگین</div><div style="font-size:21px;font-weight:900;color:var(--violet-2);margin-top:7px">'+d.avg.toFixed(2)+' GB</div></div><div><div style="font-size:10.5px;color:var(--text-2)">روند</div><div style="font-size:21px;font-weight:900;color:'+(d.trend>0?"var(--danger)":"var(--ios-green)")+';margin-top:7px">'+(d.trend>0?"+":"")+d.trend.toFixed(3)+'</div></div><div><div style="font-size:10.5px;color:var(--text-2)">هفته بعد</div><div style="font-size:21px;font-weight:900;color:var(--info);margin-top:7px">'+d.nextWeekTotal+' GB</div></div></div>';if(S.charts.chPred)S.charts.chPred.destroy();var cv=$("chPred");if(!cv)return;S.charts.chPred=new Chart(cv.getContext("2d"),{type:"line",data:{labels:(d.predictions||[]).map(function(x){return x.date.slice(5)}),datasets:[{label:"GB",data:(d.predictions||[]).map(function(x){return x.gb}),borderColor:"#FF2D55",backgroundColor:"rgba(255,45,85,.15)",fill:true,tension:.4,borderWidth:3,pointBackgroundColor:"#007AFF",pointRadius:5}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},plugins:{legend:{labels:{color:"#b4b4cc"}}},scales:{x:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"}},y:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"},beginAtZero:true}}}})}
window.lpredictive=lpredictive;
async function lsug(){var r=await ap("/api/suggestions");if(!(r.data.ok||r.data.success))return;var a=r.data.data||r.data.suggestions||[];if(!a.length){$("sugList").innerHTML='<div class="empty">'+icn("bulb")+'هیچ پیشنهادی</div>';return}var h="";a.forEach(function(x){var ic=x.icon==="isp"?"wifi":x.icon==="globe"?"globe":x.icon==="save"?"save":x.icon==="alert"?"alert":x.icon==="clock"?"clock":x.icon==="webhook"?"webhook":x.icon==="workflows"?"workflow":"bulb";var col=x.level==="warn"?"var(--warn)":"var(--info)";h+='<div class="sugg">'+icn(ic)+'<div style="flex:1"><div style="font-weight:800;font-size:13.5px;color:'+col+'">'+x.title+'</div><div style="font-size:12px;color:var(--text-2);margin-top:5px">'+x.desc+'</div>'+(x.action?'<button class="btn bg2 bs" style="margin-top:9px" onclick="if(window.handleSug)handleSug(\''+x.action+'\')">برو</button>':"")+'</div></div>'});$("sugList").innerHTML=h}
window.lsug=lsug;
function handleSug(a){if(a.indexOf("tab:")===0)tab(a.slice(4))}
window.handleSug=handleSug;
async function lanom(){var r=await ap("/api/anomalies");if(!(r.data.ok||r.data.success))return;var a=r.data.data||r.data.anomalies||[];var el=$("anomList");if(!a.length){el.innerHTML='<div class="empty">'+icn("check")+'هیچ هشدار</div>';return}var h="";a.forEach(function(x){h+='<div style="padding:13px;border-radius:12px;background:rgba(255,59,48,.08);border:1px solid rgba(255,59,48,.3);margin-bottom:7px;display:flex;justify-content:space-between;align-items:center;gap:9px;flex-wrap:wrap"><div><div style="font-weight:800">'+x.name+'</div><div style="font-size:11px;color:var(--text-2);margin-top:5px">امروز: '+(x.today/6000).toFixed(2)+' GB · میانگین: '+(x.avg/6000).toFixed(2)+' GB</div></div><span class="bdg bd-b">×'+x.ratio+'</span></div>'});el.innerHTML=h}
window.lanom=lanom;

/* ══════════ CHARTS ══════════ */
function setDays(d,el){S.days=d;Array.prototype.forEach.call($$("#tab-traffic .pill"),function(p){p.classList.remove("on")});if(el)el.classList.add("on");lhist()}
window.setDays=setDays;
async function lhist(){var r=await ap("/api/history?days="+S.days);if(!(r.data.ok||r.data.success))return;var s=r.data.series||r.data.data||[];if(S.charts.ch3)S.charts.ch3.destroy();var cv=$("ch3");if(!cv)return;var ctx=cv.getContext("2d");var g=ctx.createLinearGradient(0,0,0,280);g.addColorStop(0,"rgba(0,122,255,.5)");g.addColorStop(1,"rgba(0,122,255,0)");S.charts.ch3=new Chart(ctx,{type:"line",data:{labels:s.map(function(x){return x.date.slice(5)}),datasets:[{label:"GB",data:s.map(function(x){return x.gb}),borderColor:"#007AFF",backgroundColor:g,fill:true,tension:.4,borderWidth:3,pointBackgroundColor:"#5856D6",pointRadius:5}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},plugins:{legend:{labels:{color:"#b4b4cc"}}},scales:{x:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"}},y:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"},beginAtZero:true}}}})}
window.lhist=lhist;
function lcompare(){if(S.charts.ch4)S.charts.ch4.destroy();var cv=$("ch4");if(!cv)return;var u=S.users.slice(0,10);S.charts.ch4=new Chart(cv.getContext("2d"),{type:"bar",data:{labels:u.map(function(x){return x.name}),datasets:[{label:"مصرف",data:u.map(function(x){return x.usage?x.usage.total/1073741824:0}),backgroundColor:"rgba(0,122,255,.85)",borderRadius:8},{label:"محدودیت",data:u.map(function(x){return x.limitTotalReq?x.limitTotalReq/6000:0}),backgroundColor:"rgba(90,200,250,.4)",borderRadius:8}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},plugins:{legend:{labels:{color:"#b4b4cc"}}},scales:{x:{ticks:{color:"#7a7a95"},grid:{display:false}},y:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"},beginAtZero:true}}}})}
window.lcompare=lcompare;
function c1(){if(S.charts.c1)S.charts.c1.destroy();var cv=$("ch1");if(!cv)return;var u=S.users.slice(0,8);var ctx=cv.getContext("2d");var g=ctx.createLinearGradient(0,0,0,280);g.addColorStop(0,"rgba(0,122,255,.9)");g.addColorStop(1,"rgba(88,86,214,.15)");S.charts.c1=new Chart(ctx,{type:"bar",data:{labels:u.map(function(x){return x.name||"U"}),datasets:[{label:"GB",data:u.map(function(x){return x.usage?x.usage.total/1073741824:0}),backgroundColor:g,borderRadius:8}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},plugins:{legend:{labels:{color:"#b4b4cc"}}},scales:{x:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"}},y:{ticks:{color:"#7a7a95"},grid:{color:"rgba(255,255,255,.04)"},beginAtZero:true}}}})}
function c2(){if(S.charts.c2)S.charts.c2.destroy();var cv=$("ch2");if(!cv)return;var s=S.stats||{traffic:{totalGB:"0",dailyGB:"0"}};var t=parseFloat(s.traffic.totalGB)||0,d=parseFloat(s.traffic.dailyGB)||0;S.charts.c2=new Chart(cv.getContext("2d"),{type:"doughnut",data:{labels:["امروز","قبل"],datasets:[{data:[d,Math.max(0,t-d)],backgroundColor:["rgba(0,122,255,.95)","rgba(90,200,250,.25)"],borderColor:"rgba(4,4,10,1)",borderWidth:5,hoverOffset:6}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},cutout:"70%",plugins:{legend:{position:"bottom",labels:{color:"#b4b4cc",padding:14,usePointStyle:true,boxWidth:8}}}}})}

/* ══════════ APIKEYS / BACKUP / LOGS ══════════ */
async function lk(){var r=await ap("/api/keys");var b=$("kb");if(!(r.data.ok||r.data.success)){b.innerHTML='<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>';return}var k=r.data.data||r.data.keys||[];if(!k.length){b.innerHTML='<tr><td colspan="4" class="empty">خالی</td></tr>';return}var h="";k.forEach(function(x){h+='<tr><td>'+(x.name||"—")+'</td><td class="mc2">'+(x.keyPreview||"—")+'</td><td style="font-size:12px">'+(x.createdAt?new Date(x.createdAt).toLocaleDateString("fa-IR"):"—")+'</td><td style="text-align:left">'+iBtn("trash","rk",x.id,"حذف","bd")+'</td></tr>'});b.innerHTML=h}
window.lk=lk;
async function ck(){var n=prompt("نام کلید:");if(!n)return;var r=await ap("/api/keys",{method:"POST",body:JSON.stringify({action:"create",name:n})});if(r.data.ok||r.data.success){ts("ساخته شد","ok");var k=r.data.data||r.data.key||{};alert("کلید:\n\n"+k.key);lk()}}
window.ck=ck;
async function rk(id){if(!confirm("حذف؟"))return;var r=await ap("/api/keys",{method:"POST",body:JSON.stringify({action:"revoke",id:id})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lk()}}
window.rk=rk;
async function lbackup(){var r=await ap("/api/backup");if(!(r.data.ok||r.data.success)){$("backupBody").innerHTML='<tr><td colspan="4" class="empty">دسترسی نیست</td></tr>';return}var b=r.data.data||r.data.backups||[];if(!b.length){$("backupBody").innerHTML='<tr><td colspan="4" class="empty">خالی</td></tr>';return}var h="";b.forEach(function(x){var kb=(x.size/1024).toFixed(1);var n=x.key.split("/").pop();h+='<tr><td class="mc2" style="font-size:10px">'+n+'</td><td>'+kb+' KB</td><td style="font-size:11px">'+new Date(x.uploaded).toLocaleString("fa-IR")+'</td><td style="text-align:left">'+iBtn("download","restoreB",x.key,"بازیابی")+iBtn("trash","delB",x.key,"حذف","bd")+'</td></tr>'});$("backupBody").innerHTML=h}
window.lbackup=lbackup;
async function makeBackup(){var r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"create",encrypt:false})});if(r.data.ok||r.data.success){ts("ساخته شد","ok");lbackup()}else ts("خطا","error")}
window.makeBackup=makeBackup;
async function restoreB(key){if(!confirm("بازیابی؟"))return;var r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"restore",key:key})});if(r.data.ok||r.data.success){ts("بازیابی شد","ok");setTimeout(function(){location.reload()},1000)}else ts(r.data.error||"خطا","error")}
window.restoreB=restoreB;
async function delB(key){if(!confirm("حذف؟"))return;var r=await ap("/api/backup",{method:"POST",body:JSON.stringify({action:"delete",key:key})});if(r.data.ok||r.data.success){ts("حذف شد","ok");lbackup()}}
window.delB=delB;
function exportConfig(){window.open("/"+AR+"/api/config/export","_blank")}
window.exportConfig=exportConfig;
function openImportConfig(){$("jsonData").value="";$("imc").classList.add("on")}
window.openImportConfig=openImportConfig;
function cic(){$("imc").classList.remove("on")}
window.cic=cic;
async function doImportConfig(){try{var d=JSON.parse($("jsonData").value);var r=await ap("/api/config/import",{method:"POST",body:JSON.stringify({data:d})});if(r.data.ok||r.data.success){ts("ورود انجام شد","ok");cic();setTimeout(function(){location.reload()},1000)}else ts(r.data.error||"خطا","error")}catch(e){ts("JSON نامعتبر","error")}}
window.doImportConfig=doImportConfig;
async function ll(){var r=await ap("/api/logs",{method:"POST",body:JSON.stringify({})});var c=$("lc");if(!(r.data.ok||r.data.success)){c.innerHTML='<div class="empty">دسترسی نیست</div>';return}var l=r.data.logs||[];if(!l.length){c.innerHTML='<div class="empty">لاگی نیست</div>';return}var h="";l.slice(0,50).forEach(function(x){h+='<div style="padding:11px 13px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid var(--bglass)"><div style="display:flex;justify-content:space-between;gap:9px;flex-wrap:wrap"><span style="font-weight:800;color:var(--violet-2);font-size:11.5px">'+x.type+'</span><span style="font-size:10px;color:var(--muted-2)">'+new Date(x.ts).toLocaleString("fa-IR")+'</span></div><div style="font-size:12px;color:var(--text-2);margin-top:5px">'+(x.detail||"")+'</div></div>'});c.innerHTML=h}
window.ll=ll;

/* ══════════ INBOUNDS ══════════ */
async function linbounds(){
  try{
    var r=await ap("/api/inbounds");
    if(!(r.data.ok||r.data.success)){ts("دسترسی ندارید","warn");return}
    var d=r.data.data||{};
    S.inbound=d.config||{};
    S.inboundUsers=d.users||[];
    var cfg=S.inbound;
    var g=cfg.global||{};
    $("inb-template").value=g.nameTemplate||"{FLAG} {PREFIX}-{INDEX}";
    $("inb-prefix").value=g.prefix||(S.config.namePrefix||"Hamed");
    $("inb-maxlen").value=g.maxNameLength||60;
    $("inb-ascii").checked=!!g.asciiOnly;
    renderInboundTags(cfg.availableTags||[]);
    updateInbPreview();
    lcustomInbounds();
  }catch(e){console.error("linbounds:",e)}
}
window.linbounds=linbounds;
function renderInboundTags(tags){var c=$("inb-tags");if(!c)return;c.innerHTML="";tags.forEach(function(t){var e=document.createElement("div");e.className="chip";e.textContent="{"+t.tag+"}";e.title=t.desc+" · مثال: "+t.example;e.onclick=function(){var el=$("inb-template");el.value=el.value+" {"+t.tag+"}";updateInbPreview();Haptic.light()};c.appendChild(e)})}
function updateInbPreview(){var t=$("inb-template").value,p=$("inb-prefix").value||"Hamed";var preview=t.replace(/\{FLAG\}/g,"🇩🇪").replace(/\{PREFIX\}/g,p).replace(/\{INDEX\}/g,"1").replace(/\{USER\}/g,"ali").replace(/\{PORT\}/g,"443").replace(/\{REGION\}/g,"آلمان").replace(/\{PROTOCOL\}/g,"VLESS").replace(/\{COUNTRY\}/g,"Germany").replace(/\{CITY\}/g,"Frankfurt").replace(/\{ISP\}/g,"Cloudflare").replace(/\{IP\}/g,"188.114.96.1").replace(/\{HOST\}/g,"panel.workers.dev").replace(/\{DATE\}/g,new Date().toISOString().split("T")[0]).replace(/\{TAG\}/g,"VIP").replace(/\{WORKER\}/g,"hamed-panel").replace(/\{RELAY\}/g,"🇩🇪").replace(/\{PANEL\}/g,PN).replace(/\{VERSION\}/g,"1.0.8").trim();$("inb-preview").textContent=preview||"بدون نام"}
window.updateInbPreview=updateInbPreview;
async function saveInboundGlobal(){var g={nameTemplate:$("inb-template").value,prefix:$("inb-prefix").value,maxNameLength:parseInt($("inb-maxlen").value)||60,asciiOnly:$("inb-ascii").checked};var r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateGlobal",global:g})});if(r.data.ok||r.data.success){ts("ذخیره شد","ok");S.inbound.global=g}}
window.saveInboundGlobal=saveInboundGlobal;

/* ══════════ CUSTOM INBOUNDS ══════════ */
async function lcustomInbounds(){
  try{
    var list = (S.inbound && S.inbound.customInbounds) || [];
    var box = $("customInboundsList");
    if(!box) return;
    if(!list.length){
      box.innerHTML='<div class="empty" style="padding:24px">'+icn("tag")+'هنوز کارت سفارشی نساختی</div>';
      return;
    }
    var h="";
    list.forEach(function(c){
      var col = c.enabled ? "rgba(0,122,255,.4)" : "var(--bglass)";
      h+='<div class="nc" style="border-color:'+col+'">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:11px;margin-bottom:10px">' +
          '<div style="font-weight:800;font-size:13.5px;display:flex;align-items:center;gap:8px"><span style="font-size:18px">'+(c.flagPrefix||"🚀")+'</span>'+c.name+'</div>' +
          '<label class="switch"><input type="checkbox" '+(c.enabled?"checked":"")+' onchange="if(window.toggleCustomInb)toggleCustomInb(\''+c.id+'\',this.checked)"><span class="sl2"></span></label>' +
        '</div>' +
        '<div style="font-size:11.5px;color:var(--text-2);line-height:1.7;padding:10px;border-radius:10px;background:rgba(0,0,0,.25);font-family:JetBrains Mono,monospace;direction:ltr;text-align:left;word-break:break-all;min-height:40px">'+ (c.content || "—").replace(/</g,"&lt;") +'</div>' +
        '<div style="display:flex;gap:6px;margin-top:11px;flex-wrap:wrap;align-items:center">' +
          '<span class="tm">'+(c.position==="end"?"انتها":"ابتدا")+'</span>' +
          '<button class="btn bg2 bs" onclick="if(window.editCustomInb)editCustomInb(\''+c.id+'\')">'+icn("edit")+' ویرایش</button>' +
          '<button class="btn bd bs" onclick="if(window.delCustomInb)delCustomInb(\''+c.id+'\')">'+icn("trash")+' حذف</button>' +
        '</div></div>';
    });
    box.innerHTML=h;
  }catch(e){console.error("lcustomInbounds:",e)}
}
window.lcustomInbounds=lcustomInbounds;
async function ocustomInb(existing){
  try{
    var isEdit = !!existing;
    var name = prompt("نام کارت:", isEdit ? existing.name : "کارت جدید");
    if(name===null) return;
    var content = prompt("متن کارت (placeholders: {USER} {DATE} {PREFIX} {PANEL} {VERSION}):", isEdit ? existing.content : "🎁 THIS PANEL MADE BY HAMED TEAM");
    if(content===null) return;
    var flag = prompt("پرچم/آیکون:", isEdit ? existing.flagPrefix : "🚀");
    if(flag===null) return;
    var position = prompt("موقعیت (start/end):", isEdit ? existing.position : "start");
    if(position!==null && position!=="start" && position!=="end") position="start";
    var p = {
      action: isEdit ? "updateCustom" : "addCustom",
      id: isEdit ? existing.id : undefined,
      name: name || "کارت",
      content: content || "",
      flagPrefix: flag || "🚀",
      position: position || "start",
      enabled: true
    };
    var r;
    if(isEdit){
      r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateCustom",id:existing.id,data:p})});
    } else {
      r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify(p)});
    }
    if(r.data.ok||r.data.success){ts(isEdit?"ذخیره شد":"ساخته شد","ok");linbounds();Haptic.success()}
    else ts(r.data.error||"خطا","error");
  }catch(e){ts("خطا","error")}
}
window.ocustomInb=ocustomInb;
function editCustomInb(id){
  var c = (S.inbound && S.inbound.customInbounds || []).find(function(x){return x.id===id});
  if(c) ocustomInb(c);
}
window.editCustomInb=editCustomInb;
async function delCustomInb(id){
  if(!confirm("حذف کارت؟"))return;
  var r=await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"removeCustom",id:id})});
  if(r.data.ok||r.data.success){ts("حذف شد","ok");linbounds()}
}
window.delCustomInb=delCustomInb;
async function toggleCustomInb(id,en){
  var c = (S.inbound && S.inbound.customInbounds || []).find(function(x){return x.id===id});
  if(!c) return;
  c.enabled = en;
  await ap("/api/inbounds",{method:"POST",body:JSON.stringify({action:"updateCustom",id:id,data:{enabled:en}})});
}
window.toggleCustomInb=toggleCustomInb;

/* ══════════ INIT (SAFE) ══════════ */
function initLogin(){
  try{
    $("lu").value="admin";
    $("loginBtn").addEventListener("click",doLogin);
    $("lp").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin()});
    $("lu").addEventListener("keydown",function(e){if(e.key==="Enter")$("lp").focus()});
    $("capA").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin()});
    $("capR").addEventListener("click",function(){loadCaptcha();Haptic.light()});
    loadCaptcha();
    setTimeout(function(){$("lp").focus()},300);
  }catch(e){console.error("initLogin:",e)}
}
function attachHaptics(){
  try{
    var els=document.querySelectorAll(".btn, .lp-btn, .nv, .pill, .chip, .bcard, .rc");
    for(var i=0;i<els.length;i++){(function(el){
      if(el.hasAttribute("data-haptic"))return;
      el.setAttribute("data-haptic","1");
      el.addEventListener("pointerdown",function(){Haptic.light()},{passive:true});
    })(els[i])}
  }catch(e){}
}
function restoreSession(){
  var saved=null;
  try{saved=sessionStorage.getItem("hp_token")}catch(e){}
  if(!saved)return;
  S.token=saved;
  ap("/api/me").then(function(r){
    var data=(r.data&&r.data.data)||r.data.user||{};
    if((r.data.ok||r.data.success)&&data.username){
      S.me=data;S.config=data.config||{};show();
    } else {
      try{sessionStorage.removeItem("hp_token")}catch(e){}
    }
  }).catch(function(){try{sessionStorage.removeItem("hp_token")}catch(e){}});
}
function init(){
  var steps = [
    ["initLogin", initLogin],
    ["bind-logout", function(){safeBind("logoutBtn",lo)}],
    ["bind-menu", function(){safeBind("menuBtn",tg)}],
    ["bind-ov", function(){safeBind("ov",tg)}],
    ["bind-refresh", function(){safeBind("refBtn",ls)}],
    ["bind-export", function(){safeBind("expBtn",exportCsv)}],
    ["bind-import", function(){safeBind("impBtn",openImport)}],
    ["bind-adduser", function(){safeBind("addUserBtn",ou)}],
    ["bind-addgroup", function(){safeBind("addGroupBtn",og)}],
    ["bind-addmgr", function(){safeBind("addMgrBtn",om)}],
    ["bind-addnode", function(){safeBind("addNodeBtn",onNode)}],
    ["bind-addban", function(){safeBind("addBanBtn",oban)}],
    ["bind-addwf", function(){safeBind("addWfBtn",owf)}],
    ["bind-addcron", function(){safeBind("addCronBtn",ocron)}],
    ["bind-addwh", function(){safeBind("addWhBtn",owh)}],
    ["bind-addreg", function(){safeBind("addRegBtn",oregion)}],
    ["bind-addcustominb", function(){safeBind("addCustomInbBtn",function(){ocustomInb(null)})}],
    ["bind-selall", function(){ safeBind("selAll", function(){
      var q=($("userSearch")&&$("userSearch").value||"").toLowerCase();
      var gf=$("groupFilter")&&$("groupFilter").value||"";
      var arr=S.users.filter(function(u){
        if(q&&u.name.toLowerCase().indexOf(q)===-1&&u.id.toLowerCase().indexOf(q)===-1)return false;
        if(gf&&(u.groupId||"default")!==gf)return false;
        return true;
      });
      var ck=$("selAll").checked;
      arr.forEach(function(u){if(ck)S.selectedUsers[u.id]=1;else delete S.selectedUsers[u.id]});
      ru();updateBulkBar();
    })}],
    ["bind-search", function(){ var e=$("userSearch"); if(e)e.addEventListener("input",ru); }],
    ["bind-groupfilter", function(){ var e=$("groupFilter"); if(e)e.addEventListener("change",ru); }],
    ["bind-traffic-pills", function(){
      var pills=$$("#tab-traffic .pill");
      for(var i=0;i<pills.length;i++){(function(p){
        p.addEventListener("click",function(){setDays(parseInt(p.getAttribute("data-days"))||7,p)});
      })(pills[i])}
    }],
    ["bind-autoclean", function(){ var e=$("autoClean"); if(e)e.addEventListener("change",async function(){
      await ap("/api/sync",{method:"POST",body:JSON.stringify({config:{autoCleanIpTest:this.checked}})});
      if(S.config)S.config.autoCleanIpTest=this.checked;
      ts(this.checked?"فعال":"خاموش","ok");
    });}],
    ["bind-newport", function(){ var e=$("newPortInput"); if(e)e.addEventListener("keydown",function(ev){if(ev.key==="Enter"){ev.preventDefault();addPort()}}); }],
    ["bind-inbtemplate", function(){ var e=$("inb-template"); if(e)e.addEventListener("input",updateInbPreview); }],
    ["bind-inbprefix", function(){ var e=$("inb-prefix"); if(e)e.addEventListener("input",updateInbPreview); }],
    ["bind-escape", function(){ document.addEventListener("keydown",function(e){
      if(e.key==="Escape"){
        ["um","gml","mm2","nm","rm","com","whm","bam","im","imc","wfm"].forEach(function(id){
          var el=$(id);if(el)el.classList.remove("on");
        });
      }
    }); }],
    ["bind-haptics", function(){ attachHaptics(); }],
    ["restore-session", restoreSession]
  ];
  var failed = [];
  for(var i=0;i<steps.length;i++){
    try { steps[i][1](); }
    catch(e){ failed.push(steps[i][0]+": "+e.message); console.error("Init step failed:",steps[i][0],e); }
  }
  if(failed.length) console.warn("Some init steps failed:", failed);
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init);
else init();
</script>
</body></html>`;
const SUBSCRIPTION_HTML = String.raw`<!DOCTYPE html>
<html lang="fa" dir="rtl"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="format-detection" content="telephone=no">
<meta name="theme-color" content="#04040a">
<title>__PANEL_NAME__ · Subscription</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%A6%A6%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --ios-blue:#007AFF;--ios-indigo:#5856D6;--ios-purple:#AF52DE;--ios-pink:#FF2D55;
  --ios-red:#FF3B30;--ios-orange:#FF9500;--ios-yellow:#FFCC00;--ios-green:#34C759;
  --ios-teal:#5AC8FA;--ios-mint:#00C7BE;
  --g1:rgba(142,142,147,.2);--g2:rgba(142,142,147,.32);--g3:rgba(142,142,147,.46);
  --g4:rgba(142,142,147,.6);--g5:rgba(142,142,147,.75);--g6:rgba(142,142,147,.9);
  --mat-ultra:rgba(28,28,30,.42);--mat-thin:rgba(28,28,30,.56);
  --mat-reg:rgba(28,28,30,.72);--mat-thick:rgba(28,28,30,.86);--mat-chrome:rgba(28,28,30,.94);
  --blur-reg:blur(30px) saturate(180%);--blur-thick:blur(50px) saturate(180%);--blur-chrome:blur(80px) saturate(200%);
  --bglass:rgba(255,255,255,.14);--bglass-hi:rgba(255,255,255,.24);
  --bg:#04040a;--text:#fafaff;--text-2:#b8b8cc;--muted:#7d7d96;--muted-2:#4d4d66;
  --violet:#8b5cf6;--violet-2:#a78bfa;--cyan:#06b6d4;--pink:#ec4899;--amber:#f59e0b;
  --grad:linear-gradient(135deg,#007AFF 0%,#5856D6 48%,#AF52DE 100%);
  --spring-smooth:cubic-bezier(.22,1,.36,1);
  --spring-bouncy:cubic-bezier(.34,1.56,.64,1);
  --spring-snappy:cubic-bezier(.4,0,.2,1);
  --r-md:14px;--r-lg:18px;--r-xl:22px;--r-2xl:28px;--r-c:34px;
  --sh-2:0 4px 12px rgba(0,0,0,.4);--sh-3:0 12px 32px rgba(0,0,0,.5);
  --sh-4:0 24px 60px rgba(0,0,0,.6);
  --sh-glass:0 20px 60px -20px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.08);
  --safe-top:env(safe-area-inset-top,0px);--safe-bottom:env(safe-area-inset-bottom,0px);
  --safe-left:env(safe-area-inset-left,0px);--safe-right:env(safe-area-inset-right,0px);
}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;-webkit-touch-callout:none;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility;-webkit-text-size-adjust:100%;font-family:'Vazirmatn',-apple-system,'SF Pro Display',system-ui,sans-serif}
html,body{background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;overflow-y:auto;line-height:1.6;letter-spacing:-.005em;padding-top:var(--safe-top);padding-bottom:var(--safe-bottom);padding-left:var(--safe-left);padding-right:var(--safe-right);overscroll-behavior-y:auto;-webkit-overflow-scrolling:touch}
.mono,code{font-family:'JetBrains Mono',ui-monospace,monospace!important}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}

/* ══════════ BEAUTIFUL iOS SCROLLBAR ══════════ */
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:rgba(255,255,255,.03);border-radius:10px}
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,rgba(0,122,255,.65),rgba(88,86,214,.65));border-radius:10px;border:2px solid transparent;background-clip:content-box;transition:background .3s}
::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,rgba(0,122,255,.95),rgba(88,86,214,.95));background-clip:content-box}
::-webkit-scrollbar-thumb:active{background:linear-gradient(180deg,#007AFF,#5856D6);background-clip:content-box}
::-webkit-scrollbar-corner{background:transparent}
*{scrollbar-width:thin;scrollbar-color:rgba(0,122,255,.6) rgba(255,255,255,.03)}
::-webkit-scrollbar-button{display:none}
::selection{background:rgba(0,122,255,.4);color:#fff}

/* ══════════ BG AURORA ══════════ */
.bgA{position:fixed;inset:0;z-index:-4;pointer-events:none;overflow:hidden;contain:strict}
.bgA span{position:absolute;border-radius:50%;filter:blur(120px);opacity:.45;will-change:transform}
.bgA .a1{width:720px;height:720px;top:-40%;right:-20%;background:radial-gradient(circle,rgba(0,122,255,.6),transparent 65%);animation:au1 30s ease-in-out infinite}
.bgA .a2{width:620px;height:620px;bottom:-30%;left:-20%;background:radial-gradient(circle,rgba(175,82,222,.5),transparent 65%);animation:au2 34s ease-in-out infinite}
@keyframes au1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-70px,50px) scale(1.1)}}
@keyframes au2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(60px,-40px) scale(1.12)}}
.bgG{position:fixed;inset:0;z-index:-3;pointer-events:none;background-image:linear-gradient(rgba(0,122,255,.028) 1px,transparent 1px),linear-gradient(90deg,rgba(0,122,255,.028) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse 75% 65% at 50% 40%,black,transparent 90%);mask-image:radial-gradient(ellipse 75% 65% at 50% 40%,black,transparent 90%)}
.bgN{position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:.03;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
@media(prefers-reduced-motion:reduce){.bgA span{animation:none!important}}

.icn{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;line-height:0;vertical-align:middle}
.icn svg{display:block;width:1em;height:1em;stroke-width:1.85;stroke:currentColor;fill:none;stroke-linecap:round;stroke-linejoin:round}

/* ══════════ LAYOUT ══════════ */
.wrap{max-width:680px;margin:0 auto;padding:24px 16px 60px;position:relative;z-index:1}

/* ══════════ WALLET CARD HERO ══════════ */
.wallet{position:relative;padding:26px 24px 24px;border-radius:var(--r-c);background:linear-gradient(135deg,rgba(0,122,255,.35) 0%,rgba(88,86,214,.28) 40%,rgba(175,82,222,.22) 100%);backdrop-filter:var(--blur-thick);-webkit-backdrop-filter:var(--blur-thick);border:1px solid rgba(255,255,255,.22);box-shadow:0 30px 80px -30px rgba(0,122,255,.6),0 20px 60px -20px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.18);overflow:hidden;margin-bottom:16px;transform-style:preserve-3d;transition:transform .4s var(--spring-bouncy)}
.wallet:hover{transform:translateY(-4px) scale(1.01)}
.wallet::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 20% 10%,rgba(255,255,255,.22),transparent 40%),radial-gradient(circle at 80% 90%,rgba(0,0,0,.25),transparent 40%);pointer-events:none}
.wallet::after{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);pointer-events:none}
.wallet>*{position:relative;z-index:1}
.wallet-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;gap:12px}
.wallet-brand{display:flex;align-items:center;gap:12px;min-width:0;flex:1}
.wallet-logo{width:52px;height:52px;border-radius:16px;background:linear-gradient(135deg,rgba(255,255,255,.25),rgba(255,255,255,.1));border:1px solid rgba(255,255,255,.28);backdrop-filter:blur(10px);display:flex;align-items:center;justify-content:center;overflow:hidden;box-shadow:0 8px 20px -8px rgba(0,0,0,.4);flex-shrink:0}
.wallet-logo svg,.wallet-logo img{width:44px;height:44px;border-radius:12px;object-fit:cover;filter:drop-shadow(0 4px 10px rgba(0,0,0,.4))}
.wallet-name{font-size:17px;font-weight:900;letter-spacing:-.3px;color:#fff;line-height:1.15;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wallet-sub{font-size:10px;color:rgba(255,255,255,.75);margin-top:3px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase}
.wallet-status{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:999px;font-size:11.5px;font-weight:800;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.24);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);color:#fff;letter-spacing:.3px;flex-shrink:0}
.wallet-status .dot{width:7px;height:7px;border-radius:50%;background:#fff;box-shadow:0 0 10px rgba(255,255,255,.9);animation:wdot 2s infinite}
@keyframes wdot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.85)}}
.wallet-user{display:flex;align-items:center;gap:14px;padding:14px;border-radius:18px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);margin-bottom:18px}
.wallet-avatar{width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,rgba(255,255,255,.32),rgba(255,255,255,.12));border:1.5px solid rgba(255,255,255,.3);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900;color:#fff;flex-shrink:0;box-shadow:0 6px 16px -6px rgba(0,0,0,.4)}
.wallet-user-info{flex:1;min-width:0}
.wallet-user-name{font-size:15.5px;font-weight:900;color:#fff;letter-spacing:-.2px}
.wallet-user-id{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:rgba(255,255,255,.65);margin-top:4px;direction:ltr;text-align:left;word-break:break-all;line-height:1.4}
.wallet-progress{display:flex;align-items:center;gap:16px}
.wallet-ring{position:relative;width:88px;height:88px;flex-shrink:0}
.wallet-ring svg{transform:rotate(-90deg);width:100%;height:100%;filter:drop-shadow(0 0 12px rgba(255,255,255,.3))}
.wallet-ring circle{fill:none;stroke-width:8;stroke-linecap:round}
.wallet-ring .bg{stroke:rgba(255,255,255,.15)}
.wallet-ring .fg{stroke:#fff;transition:stroke-dashoffset 1.2s var(--spring-smooth)}
.wallet-ring-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.wallet-ring-val{font-size:17px;font-weight:900;color:#fff;letter-spacing:-.5px;line-height:1}
.wallet-ring-unit{font-size:9px;color:rgba(255,255,255,.7);font-weight:700;margin-top:2px;letter-spacing:.5px}
.wallet-info{flex:1;min-width:0}
.wallet-info-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;font-size:12.5px;color:rgba(255,255,255,.95)}
.wallet-info-row+.wallet-info-row{border-top:1px solid rgba(255,255,255,.1)}
.wallet-info-label{font-weight:600;color:rgba(255,255,255,.7)}
.wallet-info-value{font-weight:800;color:#fff;font-variant-numeric:tabular-nums;direction:ltr;text-align:left}

/* ══════════ META CHIPS ══════════ */
.meta-row{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:16px;position:relative;z-index:1}
.mchip{display:inline-flex;align-items:center;gap:6px;padding:7px 13px;border-radius:12px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);font-size:11px;font-weight:700;color:rgba(255,255,255,.95);letter-spacing:.15px}
.mchip .cl{color:rgba(255,255,255,.55);font-weight:800;font-size:9px;text-transform:uppercase;letter-spacing:.7px}
.mchip code{background:rgba(0,0,0,.25);padding:2px 7px;border-radius:6px;font-size:10.5px;color:#fff}
.mchip.relay{background:linear-gradient(135deg,rgba(0,199,190,.32),rgba(90,200,250,.24));border-color:rgba(90,200,250,.5);color:#fff}
.mchip.relay .cl{color:rgba(255,255,255,.75)}

/* ══════════ CARDS ══════════ */
.card{background:linear-gradient(165deg,var(--mat-thin),rgba(255,255,255,.012));backdrop-filter:var(--blur-reg);-webkit-backdrop-filter:var(--blur-reg);border:1px solid var(--bglass);border-radius:var(--r-2xl);padding:22px;margin-bottom:16px;box-shadow:var(--sh-2);position:relative;overflow:hidden}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);pointer-events:none}
.ctitle{font-size:14.5px;font-weight:900;margin-bottom:18px;display:flex;align-items:center;gap:10px;padding-bottom:14px;border-bottom:1px solid var(--bglass);letter-spacing:-.2px}
.ctitle .em{font-size:18px;filter:drop-shadow(0 3px 8px rgba(0,122,255,.4))}

/* ══════════ QR ══════════ */
.qr-wrap{text-align:center;padding:22px;border-radius:20px;background:rgba(8,8,20,.4);border:1px solid var(--bglass);margin-bottom:18px;position:relative}
.qr-box{width:240px;height:240px;margin:0 auto;border-radius:18px;background:#fff;padding:12px;box-shadow:0 20px 55px -15px rgba(0,122,255,.7),0 8px 24px -8px rgba(0,0,0,.5);position:relative;display:flex;align-items:center;justify-content:center;overflow:hidden;transition:transform .3s var(--spring-bouncy)}
.qr-box:hover{transform:scale(1.02)}
.qr-box img{width:100%;height:100%;object-fit:contain;display:block;border-radius:8px;transition:opacity .4s}
.qr-box.loading img{opacity:0}
.qr-box.loading::before{content:"";position:absolute;inset:12px;background:linear-gradient(90deg,transparent,rgba(0,122,255,.15),transparent);animation:qshine 1.5s infinite;border-radius:8px}
@keyframes qshine{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.qr-box.error::after{content:"⚠";position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:52px;color:#FF3B30}
.qr-box.error img{opacity:0}
.qr-logo{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#007AFF,#5856D6);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900;color:#fff;box-shadow:0 6px 18px rgba(0,0,0,.45);z-index:2;border:3.5px solid #fff;overflow:hidden}
.qr-logo img{width:100%;height:100%;object-fit:cover;border-radius:8px}
.qr-hint{font-size:12px;color:var(--muted);margin-top:14px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:6px}
.qr-status{font-size:10.5px;color:var(--muted-2);margin-top:6px;font-weight:600;min-height:15px;display:flex;align-items:center;justify-content:center;gap:5px}
.qr-status .spin{width:10px;height:10px;border:1.5px solid rgba(0,122,255,.3);border-top-color:#007AFF;border-radius:50%;animation:spn .7s linear infinite}
@keyframes spn{to{transform:rotate(360deg)}}
.qr-status.ok{color:var(--ios-green)}
.qr-status.err{color:var(--ios-red)}

/* ══════════ LINKS ══════════ */
.lsec{margin-top:16px}
.llabel{font-size:12px;color:var(--muted);margin-bottom:9px;font-weight:800;display:flex;align-items:center;gap:7px}
.llabel .em{font-size:14px}
.lbox{display:flex;align-items:center;gap:9px;padding:13px;border-radius:14px;background:rgba(8,8,20,.55);border:1px solid var(--bglass);transition:border-color .2s}
.lbox:hover{border-color:rgba(0,122,255,.4)}
.lbox code{flex:1;font-size:11px;color:var(--text-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;direction:ltr;text-align:left;line-height:1.5;min-width:0}
.cbtn{padding:9px 14px;border-radius:11px;background:rgba(0,122,255,.14);color:#a5d8ff;border:1px solid rgba(0,122,255,.36);cursor:pointer;font-family:inherit;font-size:11.5px;font-weight:800;transition:all .2s var(--spring-snappy);flex-shrink:0;display:inline-flex;align-items:center;gap:5px;touch-action:manipulation}
.cbtn:hover{background:rgba(0,122,255,.24)}
.cbtn:active{transform:scale(.95)}
.cbtn.ok{background:rgba(52,199,89,.24);color:#6ee7b7;border-color:rgba(52,199,89,.55)}
.cbtn .icn{font-size:13px}

/* ══════════ APPS ══════════ */
.apps{display:grid;gap:9px}
.arow{display:flex;align-items:center;gap:13px;padding:13px 16px;border-radius:16px;background:rgba(8,8,20,.4);border:1px solid var(--bglass);text-decoration:none;color:var(--text);transition:all .24s var(--spring-snappy);position:relative;overflow:hidden}
.arow:hover{background:rgba(0,122,255,.09);border-color:rgba(0,122,255,.42);transform:translateX(-4px)}
.arow::after{content:"←";position:absolute;left:16px;color:var(--muted);font-size:15px;transition:all .22s;opacity:.5}
.arow:hover::after{transform:translateX(-4px);color:#fff;opacity:1}
.aicon{width:42px;height:42px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:16px;color:#fff;flex-shrink:0;box-shadow:0 8px 18px -8px rgba(0,0,0,.55);letter-spacing:-.5px}
.ainfo{flex:1;padding-left:26px;min-width:0}
.aname{font-weight:800;font-size:13.5px;line-height:1.3}
.adesc{font-size:10.5px;color:var(--muted);font-weight:500;margin-top:2px}

/* ══════════ FOOTER ══════════ */
.madeby{margin-top:14px;padding:13px 16px;border-radius:16px;background:linear-gradient(135deg,rgba(0,199,190,.1),rgba(255,45,85,.06));border:1px dashed rgba(0,122,255,.4);font-size:12px;color:#a5d8ff;font-weight:800;text-align:center;letter-spacing:.6px;display:flex;align-items:center;justify-content:center;gap:8px}
.foot{text-align:center;padding:26px 0 8px;font-size:11.5px;color:var(--muted-2);line-height:2;font-weight:500}
.foot strong{color:var(--violet-2)}

/* ══════════ TOAST ══════════ */
.toast{position:fixed;bottom:calc(22px + var(--safe-bottom));left:50%;transform:translateX(-50%);padding:14px 22px;border-radius:14px;background:var(--mat-chrome);backdrop-filter:var(--blur-thick);-webkit-backdrop-filter:var(--blur-thick);border:1px solid var(--bglass-hi);color:var(--text);font-size:13px;font-weight:700;box-shadow:var(--sh-3);z-index:1000;animation:ti .32s var(--spring-bouncy);display:flex;align-items:center;gap:10px;max-width:92vw}
.toast .icn{font-size:16px}
@keyframes ti{from{opacity:0;transform:translate(-50%,28px) scale(.92)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
</style></head><body>

<div class="bgA"><span class="a1"></span><span class="a2"></span></div>
<div class="bgG"></div>
<div class="bgN"></div>

<div class="wrap">

  <!-- ══════════ WALLET HERO ══════════ -->
  <div class="wallet">
    <div class="wallet-top">
      <div class="wallet-brand">
        <div class="wallet-logo" id="walletLogo">
          __CUSTOM_LOGO_BLOCK__
          <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" id="defaultLogo">
            <defs>
              <linearGradient id="fs1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/></linearGradient>
              <linearGradient id="fs2" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#5AC8FA"/><stop offset="100%" stop-color="#AF52DE"/></linearGradient>
            </defs>
            <circle cx="26" cy="30" r="10" fill="url(#fs2)"/><circle cx="74" cy="30" r="10" fill="url(#fs2)"/>
            <circle cx="26" cy="30" r="5" fill="#0a0e1a"/><circle cx="74" cy="30" r="5" fill="#0a0e1a"/>
            <ellipse cx="50" cy="55" rx="34" ry="34" fill="url(#fs1)"/>
            <circle cx="39" cy="52" r="4.5" fill="#0a0e1a"/><circle cx="61" cy="52" r="4.5" fill="#0a0e1a"/>
            <circle cx="40.5" cy="50.5" r="1.6" fill="#fff"/><circle cx="62.5" cy="50.5" r="1.6" fill="#fff"/>
            <ellipse cx="50" cy="66" rx="13" ry="10" fill="#fff" opacity=".9"/><ellipse cx="50" cy="62" rx="3.5" ry="2.5" fill="#0a0e1a"/>
          </svg>
        </div>
        <div style="min-width:0">
          <div class="wallet-name">__PANEL_NAME__</div>
          <div class="wallet-sub">Subscription</div>
        </div>
      </div>
      <div class="wallet-status" id="walletStatus"><span class="dot"></span><span>—</span></div>
    </div>

    <div class="wallet-user">
      <div class="wallet-avatar" id="walletAvatar">?</div>
      <div class="wallet-user-info">
        <div class="wallet-user-name">__USER_NAME__</div>
        <div class="wallet-user-id">__USER_ID__</div>
      </div>
    </div>

    <div class="wallet-progress">
      <div class="wallet-ring">
        <svg viewBox="0 0 100 100">
          <circle class="bg" cx="50" cy="50" r="42"/>
          <circle class="fg" cx="50" cy="50" r="42" id="usageRing" stroke-dasharray="264" stroke-dashoffset="264"/>
        </svg>
        <div class="wallet-ring-text">
          <div class="wallet-ring-val">__TOTAL_PERCENT__</div>
          <div class="wallet-ring-unit">مصرف</div>
        </div>
      </div>
      <div class="wallet-info">
        <div class="wallet-info-row">
          <span class="wallet-info-label">📥 ترافیک</span>
          <span class="wallet-info-value">__TOTAL_GB__ / __LIMIT_TOTAL_GB__ GB</span>
        </div>
        <div class="wallet-info-row">
          <span class="wallet-info-label">📅 امروز</span>
          <span class="wallet-info-value">__DAILY_GB__ / __LIMIT_DAILY_GB__ GB</span>
        </div>
        <div class="wallet-info-row">
          <span class="wallet-info-label">⏰ انقضا</span>
          <span class="wallet-info-value">__EXPIRY_DATE__</span>
        </div>
        <div class="wallet-info-row">
          <span class="wallet-info-label">⏳ باقیمانده</span>
          <span class="wallet-info-value">__DAYS_LEFT__ روز</span>
        </div>
      </div>
    </div>

    <div class="meta-row" id="metaRow">__META_CHIPS__</div>
  </div>

  <!-- ══════════ SUBSCRIPTION LINK + QR ══════════ -->
  <div class="card">
    <div class="ctitle"><span class="em">🔗</span> لینک اشتراک</div>
    <div class="qr-wrap">
      <div class="qr-box loading" id="qrBox">
        <img id="qrImg" alt="QR Code" style="display:none">
        <div class="qr-logo" id="qrLogo">🦦</div>
      </div>
      <div class="qr-hint">📱 اسکن کنید یا لینک را کپی نمایید</div>
      <div class="qr-status" id="qrStatus"><span class="spin"></span><span>در حال بارگذاری...</span></div>
    </div>

    <div class="lsec">
      <div class="llabel"><span class="em">🎯</span> لینک اصلی (V2Ray / Clash / Sing-Box)</div>
      <div class="lbox">
        <code id="linkNormal">__SYNC_NORMAL__</code>
        <button class="cbtn" id="cp1"><span class="icn" id="cp1i"></span><span>کپی</span></button>
      </div>
    </div>

    <div class="lsec">
      <div class="llabel"><span class="em">📄</span> لینک خام (بدون فرمت)</div>
      <div class="lbox">
        <code id="linkRaw">__SYNC_RAW__</code>
        <button class="cbtn" id="cp2"><span class="icn" id="cp2i"></span><span>کپی</span></button>
      </div>
    </div>
  </div>

  <!-- ══════════ APPS ══════════ -->
  <div class="card">
    <div class="ctitle"><span class="em">📱</span> اپلیکیشن‌های پیشنهادی</div>
    <div class="apps">
      <a class="arow" href="https://github.com/KaringX/karing/releases" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#5AC8FA,#007AFF)">K</span>
        <div class="ainfo"><div class="aname">Karing</div><div class="adesc">iOS · Android · Windows · macOS</div></div>
      </a>
      <a class="arow" href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#FF9500,#FF3B30)">N</span>
        <div class="ainfo"><div class="aname">NekoBox</div><div class="adesc">Android · NekoRay</div></div>
      </a>
      <a class="arow" href="https://github.com/2dust/v2rayNG/releases" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#34C759,#00C7BE)">V</span>
        <div class="ainfo"><div class="aname">v2rayNG</div><div class="adesc">Android · پایدار و سبک</div></div>
      </a>
      <a class="arow" href="https://github.com/MetaCubeX/ClashMetaForAndroid/releases" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#5856D6,#AF52DE)">C</span>
        <div class="ainfo"><div class="aname">Clash Meta</div><div class="adesc">Android · Mihomo</div></div>
      </a>
      <a class="arow" href="https://github.com/hiddify/hiddify-next/releases" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#FFCC00,#FF9500)">H</span>
        <div class="ainfo"><div class="aname">Hiddify</div><div class="adesc">Multi-Platform · Sing-Box</div></div>
      </a>
      <a class="arow" href="https://apps.apple.com/app/shadowrocket/id932747118" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#FF2D55,#AF52DE)">S</span>
        <div class="ainfo"><div class="aname">Shadowrocket</div><div class="adesc">iOS · پرداختی</div></div>
      </a>
      <a class="arow" href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#5AC8FA,#00C7BE)">St</span>
        <div class="ainfo"><div class="aname">Streisand</div><div class="adesc">iOS · رایگان</div></div>
      </a>
      <a class="arow" href="https://apps.apple.com/app/loon/id1373567447" target="_blank" rel="noopener">
        <span class="aicon" style="background:linear-gradient(135deg,#AF52DE,#5856D6)">L</span>
        <div class="ainfo"><div class="aname">Loon</div><div class="adesc">iOS · پرداختی</div></div>
      </a>
    </div>
  </div>

  <div class="madeby"><span>🦦</span> THIS PANEL MADE BY HAMED TEAM</div>
  <div class="foot">© 2025 <strong>__PANEL_NAME__</strong><br>v__CURRENT_VERSION__ · Aurora Edition</div>

</div>

<div id="tb"></div>

<script>
'use strict';
(function(){
  var userName="__USER_NAME__";
  var userId="__USER_ID__";
  var statusCode="__STATUS_CODE__";
  var totalPercent=parseFloat("__TOTAL_PERCENT__")||0;
  var dailyPercent=parseFloat("__DAILY_PERCENT__")||0;
  var syncNormal="__SYNC_NORMAL__";
  var customLogoBlock="__CUSTOM_LOGO_BLOCK__";

  /* ══════ ICONS ══════ */
  var ICO={
    copy:'<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    check:'<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>'
  };
  function icn(n){return '<span class="icn">'+(ICO[n]||'')+'</span>'}
  function hap(ms){try{if(navigator.vibrate)navigator.vibrate(ms||10)}catch(e){}}

  /* ══════ Custom logo ══════ */
  if(customLogoBlock&&customLogoBlock.length>10){
    var dl=document.getElementById("defaultLogo");
    if(dl)dl.style.display="none";
    var m=customLogoBlock.match(/src="([^"]+)"/);
    if(m&&m[1]){
      var ql=document.getElementById("qrLogo");
      if(ql){ql.innerHTML='<img src="'+m[1]+'" alt="logo">'}
    }
  }

  /* ══════ Avatar ══════ */
  var av=document.getElementById("walletAvatar");
  if(av&&userName)av.textContent=userName.charAt(0).toUpperCase();

  /* ══════ Status ══════ */
  var statusMap={
    active:["#34C759","فعال"],
    paused:["#FF9500","متوقف"],
    expired:["#FF3B30","منقضی"],
    limit:["#FF3B30","اتمام ترافیک"],
    dailyLimit:["#FF9500","اتمام روزانه"]
  };
  var sv=statusMap[statusCode]||statusMap.active;
  var ws=document.getElementById("walletStatus");
  if(ws)ws.innerHTML='<span class="dot" style="background:'+sv[0]+';box-shadow:0 0 10px '+sv[0]+'"></span><span>'+sv[1]+'</span>';

  /* ══════ Progress ring ══════ */
  var ring=document.getElementById("usageRing");
  if(ring){
    var circumference=264;
    var offset=circumference*(1-Math.min(100,Math.max(0,totalPercent))/100);
    setTimeout(function(){ring.style.strokeDashoffset=offset;},200);
    if(totalPercent>=90)ring.style.stroke="#FF3B30";
    else if(totalPercent>=70)ring.style.stroke="#FF9500";
  }

  /* ══════ Copy buttons ══════ */
  var cp1=document.getElementById("cp1");
  var cp2=document.getElementById("cp2");
  var cp1i=document.getElementById("cp1i");
  var cp2i=document.getElementById("cp2i");
  if(cp1i)cp1i.innerHTML=ICO.copy;
  if(cp2i)cp2i.innerHTML=ICO.copy;

  function copyText(text,btn){
    var orig=btn.innerHTML;
    var done=function(){
      btn.innerHTML=icn("check")+'<span>کپی شد</span>';
      btn.classList.add("ok");
      hap([10,40,10]);
      toast("✓ لینک کپی شد");
      setTimeout(function(){btn.innerHTML=orig;btn.classList.remove("ok")},1800);
    };
    var fallback=function(){
      var ta=document.createElement("textarea");
      ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
      document.body.appendChild(ta);ta.select();
      try{document.execCommand("copy");done()}catch(e){toast("❌ کپی نشد")}
      document.body.removeChild(ta);
    };
    if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(text).then(done).catch(fallback);
    else fallback();
  }
  if(cp1)cp1.addEventListener("click",function(){copyText(syncNormal,cp1)});
  if(cp2)cp2.addEventListener("click",function(){var raw=document.getElementById("linkRaw").textContent;copyText(raw,cp2)});

  /* ══════ Toast ══════ */
  function toast(m){
    var t=document.createElement("div");
    t.className="toast";
    t.innerHTML=icn("check")+'<span>'+m+'</span>';
    var box=document.getElementById("tb");
    if(box){box.appendChild(t);setTimeout(function(){t.style.opacity="0";t.style.transition=".3s";setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t)},300)},2200)}
  }

  /* ═══════════════════════════════════════════════════════════════
     QR CODE — 3-Layer Fallback System
     ═══════════════════════════════════════════════════════════════ */
  var qrBox=document.getElementById("qrBox");
  var qrImg=document.getElementById("qrImg");
  var qrStatus=document.getElementById("qrStatus");
  var qrSize=240;

  var QR_SERVICES=[
    {name:"QRServer",build:function(data,size){return "https://api.qrserver.com/v1/create-qr-code/?size="+size+"x"+size+"&bgcolor=ffffff&color=080b12&margin=8&qzone=2&ecc=M&data="+encodeURIComponent(data)}},
    {name:"QuickChart",build:function(data,size){return "https://quickchart.io/qr?size="+size+"&dark=080b12&light=ffffff&margin=2&ecLevel=M&text="+encodeURIComponent(data)}},
    {name:"Google",build:function(data,size){return "https://chart.googleapis.com/chart?chs="+size+"x"+size+"&chld=M|2&cht=qr&chl="+encodeURIComponent(data)}}
  ];

  var svcIdx=0;
  var qrTimeoutHandle=null;

  function setStatus(text,cls,showSpin){
    if(!qrStatus)return;
    qrStatus.className="qr-status"+(cls?" "+cls:"");
    if(showSpin)qrStatus.innerHTML='<span class="spin"></span><span>'+text+'</span>';
    else qrStatus.textContent=text;
  }

  function loadQR(){
    if(svcIdx>=QR_SERVICES.length){
      if(qrBox)qrBox.classList.remove("loading");
      if(qrBox)qrBox.classList.add("error");
      setStatus("خطا در بارگذاری QR — از لینک زیر استفاده کنید","err",false);
      return;
    }
    var svc=QR_SERVICES[svcIdx];
    if(qrBox){qrBox.classList.add("loading");qrBox.classList.remove("error")}
    if(qrImg)qrImg.style.display="none";
    setStatus("بارگذاری از "+svc.name+"...","",true);

    var url=svc.build(syncNormal,qrSize);
    var loaded=false;

    if(qrImg){
      qrImg.onload=function(){
        loaded=true;
        if(qrTimeoutHandle)clearTimeout(qrTimeoutHandle);
        qrImg.style.display="block";
        if(qrBox)qrBox.classList.remove("loading","error");
        setStatus("✓ آماده اسکن ("+svc.name+")","ok",false);
      };
      qrImg.onerror=function(){
        loaded=true;
        if(qrTimeoutHandle)clearTimeout(qrTimeoutHandle);
        svcIdx++;
        setTimeout(loadQR,150);
      };
      qrImg.src=url;
    }

    qrTimeoutHandle=setTimeout(function(){
      if(loaded)return;
      svcIdx++;
      loadQR();
    },5000);
  }

  if(syncNormal&&syncNormal.length>5)loadQR();
  else{
    if(qrBox)qrBox.classList.remove("loading");
    setStatus("لینک اشتراک یافت نشد","err",false);
  }

  /* ══════ Meta row RTL ══════ */
  var mr=document.getElementById("metaRow");
  if(mr)mr.setAttribute("dir","rtl");

  /* ══════ Prevent zoom on double-tap iOS ══════ */
  var lastTouch=0;
  document.addEventListener("touchend",function(e){
    var now=Date.now();
    if(now-lastTouch<=300)e.preventDefault();
    lastTouch=now;
  },{passive:false});

})();
</script>
</body></html>`;