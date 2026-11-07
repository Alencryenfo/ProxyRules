// Egern generic widget: proxy status overview (small / medium).
// env: POLICY_1/2 policy group names, NAME_1/2 labels, SERVICES_1/2 service checks,
//      CHECK_URL latency target for policy groups, MASK_IP hide the tail of IPs.
const PROXY_PING = "http://www.gstatic.com/generate_204";
const DIRECT_PING = "http://connect.rom.miui.com/generate_204";
const PING_COUNT = 3;
const PING_TIMEOUT = 4000;
const LOOKUP_TIMEOUT = 6000;
const SERVICE_TIMEOUT = 9000;
const REFRESH_MINUTES = 15;
const DEFAULT_SERVICES = "chatgpt,claude,gemini,youtube,netflix";
const MAX_SERVICES = 5;
const USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";

// blocked(): explicit region / access denial; anything else below HTTP 500 only counts as reachable.
const SERVICES = {
  chatgpt: {
    label: "GPT",
    url: "https://api.openai.com/compliance/cookie_requirements",
    readBody: true,
    blocked: (status, body) => status === 403 || /unsupported_country/i.test(body),
  },
  claude: { label: "Claude", url: "https://api.anthropic.com/", blocked: status => status === 403 },
  gemini: { label: "Gemini", url: "https://gemini.google.com/app" },
  youtube: { label: "YT", url: "https://www.youtube.com/generate_204" },
  netflix: { label: "NF", url: "https://www.netflix.com/title/81215567" },
  disney: { label: "D+", url: "https://www.disneyplus.com/" },
  github: { label: "GH", url: "https://github.com/" },
};

const pair = (light, dark) => ({ light, dark });
const C = {
  background: pair("#FFFFFF", "#1C1C1E"),
  card: pair("#F2F2F7", "#2C2C2E"),
  text: pair("#000000", "#FFFFFF"),
  sub: pair("#6C6C70", "#98989D"),
  faint: pair("#AEAEB2", "#636366"),
  green: pair("#248A3D", "#30D158"),
  greenSoft: pair("#E3F5E8", "#17352A"),
  orange: pair("#C25400", "#FF9F0A"),
  orangeSoft: pair("#FFF1DD", "#3D2B12"),
  red: pair("#D70015", "#FF453A"),
  blue: pair("#0066CC", "#0A84FF"),
  blueSoft: pair("#E3EFFF", "#13304F"),
};

const text = (value, size, color, weight = "regular", props = {}) => ({
  type: "text",
  text: String(value),
  font: { size, weight },
  textColor: color,
  maxLines: 1,
  minScale: 0.6,
  ...props,
});
const stack = (direction, children, props = {}) => ({ type: "stack", direction, alignItems: "center", children, ...props });
const row = (children, props) => stack("row", children, props);
const column = (children, props) => stack("column", children, { alignItems: "start", ...props });
const spacer = () => ({ type: "spacer" });
const symbol = (name, size, color) => ({ type: "image", src: `sf-symbol:${name}`, width: size, height: size, color });
const pill = (label, tone, soft) =>
  row([text(label, 8, tone, "semibold")], { padding: [1, 4], backgroundColor: soft, borderRadius: 4 });

const request = (ctx, url, policy, timeout, headers) =>
  ctx.http.get(url, { timeout, ...(policy ? { policy } : {}), ...(headers ? { headers } : {}) });

async function ping(ctx, url, policy) {
  const times = await Promise.all(Array.from({ length: PING_COUNT }, async () => {
    const start = Date.now();
    try {
      const response = await request(ctx, url, policy, PING_TIMEOUT);
      return response.status < 500 ? Date.now() - start : null;
    } catch (_) {
      return null;
    }
  }));
  const ok = times.filter(time => time !== null).sort((a, b) => a - b);
  return { ms: ok.length ? ok[Math.floor(ok.length / 2)] : null, lost: PING_COUNT - ok.length };
}

async function lookupIpApi(ctx, policy) {
  const fields = "status,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query";
  const response = await request(ctx, `http://ip-api.com/json/?lang=zh-CN&fields=${fields}`, policy, LOOKUP_TIMEOUT);
  const data = await response.json();
  if (response.status >= 300 || data.status !== "success" || !data.query) return null;
  return {
    ip: data.query,
    cc: data.countryCode,
    city: data.city || data.regionName || data.country,
    isp: data.isp || data.org,
    asn: String(data.as || "").split(" ")[0],
    kind: data.hosting ? "机房" : data.mobile ? "移动" : data.proxy ? "代理" : "非机房",
  };
}

async function lookupIpWho(ctx, policy) {
  const response = await request(ctx, "https://ipwho.is/?lang=zh-CN", policy, LOOKUP_TIMEOUT);
  const data = await response.json();
  if (response.status >= 300 || data.success === false || !data.ip) return null;
  const connection = data.connection || {};
  return {
    ip: data.ip,
    cc: data.country_code,
    city: data.city || data.region || data.country,
    isp: connection.org || connection.isp,
    asn: connection.asn ? `AS${connection.asn}` : "",
    kind: "",
  };
}

async function lookupIpify(ctx, policy) {
  const response = await request(ctx, "https://api64.ipify.org?format=json", policy, LOOKUP_TIMEOUT);
  const { ip } = await response.json();
  if (response.status >= 300 || !ip) return null;
  const info = await ctx.lookupIP(ip);
  return {
    ip,
    cc: info?.country,
    city: info?.country,
    isp: info?.organization,
    asn: info?.asn ? `AS${info.asn}` : "",
    kind: "",
  };
}

// ip-api carries the hosting / mobile / proxy flags, so it wins when both answer.
async function queryExit(ctx, policy) {
  const attempt = lookup => lookup(ctx, policy).catch(() => null);
  const [primary, secondary] = await Promise.all([attempt(lookupIpApi), attempt(lookupIpWho)]);
  return primary || secondary || (await attempt(lookupIpify));
}

async function checkService(ctx, key, policy) {
  const service = SERVICES[key];
  try {
    const response = await request(ctx, service.url, policy, SERVICE_TIMEOUT, { "User-Agent": USER_AGENT });
    const body = service.readBody ? await response.text() : "";
    if (service.blocked?.(response.status, body)) return "blocked";
    return response.status < 500 ? "ok" : "fail";
  } catch (_) {
    return "fail";
  }
}

function readRoute(ctx, index) {
  const env = ctx.env || {};
  const policy = (env[`POLICY_${index}`] || "").trim();
  const services = (env[`SERVICES_${index}`] || DEFAULT_SERVICES)
    .split(/[,，\s]+/)
    .map(key => key.toLowerCase())
    .filter(key => SERVICES[key])
    .slice(0, MAX_SERVICES);
  return { index, policy, name: (env[`NAME_${index}`] || "").trim() || policy || `策略组 ${index}`, services };
}

async function probeRoute(ctx, route) {
  const [exit, states] = await Promise.all([
    queryExit(ctx, route.policy),
    Promise.all(route.services.map(key => checkService(ctx, key, route.policy))),
  ]);
  return { exit, states };
}

function flag(code) {
  if (!/^[A-Za-z]{2}$/.test(code || "")) return "";
  return String.fromCodePoint(...code.toUpperCase().split("").map(char => 0x1f1a5 + char.charCodeAt(0)));
}

function shortName(value) {
  const raw = String(value || "");
  const cleaned = raw
    .replace(/^AS\d+\s+/i, "")
    .replace(/[,.]?\s*\b(Corporation|Corp|Co|Ltd|Limited|Inc|LLC|GmbH|Company|Communications?)\b\.?/gi, "")
    .replace(/\s+/g, " ")
    .trim();
  return (cleaned || raw).slice(0, 16);
}

function showIP(ip, mask) {
  if (!ip) return "—";
  if (ip.includes(":")) {
    const groups = ip.split(":");
    return mask ? `${groups.slice(0, 2).join(":")}:*` : groups.length > 5 ? `${groups[0]}:${groups[1]}…${groups[groups.length - 1]}` : ip;
  }
  const parts = ip.split(".");
  return mask && parts.length === 4 ? `${parts[0]}.${parts[1]}.*.*` : ip;
}

function radioGeneration(radio) {
  const tech = String(radio || "").replace(/^CTRadioAccessTechnology/, "");
  if (/^NR/.test(tech)) return "5G";
  if (/^LTE/.test(tech)) return "4G";
  if (/^(WCDMA|HSDPA|HSUPA|CDMAEVDO|eHRPD)/.test(tech)) return "3G";
  if (/^(GPRS|Edge|CDMA1x)/.test(tech)) return "2G";
  return tech;
}

// The API has no connection-type field, so this is a best-effort guess from SSID / interface / carrier.
function readLocal(ctx, direct) {
  const device = ctx.device || {};
  const ssid = device.wifi?.ssid;
  const carrier = device.cellular?.carrier;
  const generation = radioGeneration(device.cellular?.radio);
  const iface = device.ipv4?.interface || device.ipv6?.interface || "";
  const base = {
    ip: device.ipv4?.address || device.ipv6?.address || "—",
    ipv6: Boolean(device.ipv6?.address),
  };
  if (ssid || /^en\d/.test(iface)) return { ...base, symbol: "wifi", title: "Wi-Fi", sub: ssid || "无线局域网" };
  if (/^pdp_ip/.test(iface) || carrier || generation) {
    const sub = [carrier, generation].filter(Boolean).join(" ") || shortName(direct?.isp) || "移动数据";
    return { ...base, symbol: "antenna.radiowaves.left.and.right", title: "蜂窝网络", sub };
  }
  return { ...base, symbol: "network", title: "网络未知", sub: iface || "未获取到接口" };
}

function latencyView(result) {
  if (!result || result.ms === null) return { label: "超时", color: C.red };
  const color = result.ms < 250 ? C.green : result.ms < 600 ? C.orange : C.red;
  return { label: `${result.ms} ms${result.lost ? ` · 丢${result.lost}` : ""}`, color: result.lost ? C.orange : color };
}

function statusColor(route) {
  const good = (route.exit ? 1 : 0) + (route.ping?.ms !== null && route.ping?.ms !== undefined ? 1 : 0);
  return good === 2 ? C.green : good === 1 ? C.orange : C.red;
}

function kindPill(kind) {
  if (!kind) return null;
  if (kind === "非机房") return pill(kind, C.green, C.greenSoft);
  if (kind === "移动") return pill(kind, C.blue, C.blueSoft);
  return pill(kind, C.orange, C.orangeSoft);
}

function chips(route) {
  return row(
    route.services.map((key, i) => {
      const state = route.states[i];
      const label = SERVICES[key].label;
      if (state === "ok") return text(label, 8.5, C.green, "semibold");
      return text(`${state === "blocked" ? "✕" : "?"}${label}`, 8.5, state === "blocked" ? C.red : C.orange, "semibold");
    }),
    { gap: 5 },
  );
}

function summary(route) {
  const total = route.states.length;
  if (!total) return null;
  const ok = route.states.filter(state => state === "ok").length;
  return text(`服务 ${ok}/${total}`, 9, ok === total ? C.green : ok === 0 ? C.red : C.orange, "semibold", { minScale: 0.7 });
}

function card(children, props = {}) {
  return column(children, { flex: 1, gap: 2, backgroundColor: C.card, borderRadius: 14, ...props });
}

function emptyCard(route, padding) {
  return card([
    row([symbol("circle.fill", 6, C.faint), text(route.name, 11, C.text, "semibold"), spacer()], { gap: 4 }),
    row([text("未配置", 14, C.sub, "semibold"), spacer()]),
    row([text(`在模块 env 填写 POLICY_${route.index}`, 9, C.faint), spacer()]),
  ], { padding });
}

function routeCard(route, mask, compact) {
  const padding = compact ? [6, 9] : [7, 10];
  if (!route.policy) return emptyCard(route, padding);

  const latency = latencyView(route.ping);
  const exit = route.exit;
  const where = exit ? [exit.city, shortName(exit.isp)].filter(Boolean).join(" · ") : "";
  const header = row([
    symbol("circle.fill", 6, statusColor(route)),
    text(route.name, 11, C.text, "semibold", { flex: 1, minScale: 0.7 }),
    text(latency.label, 10.5, latency.color, "semibold"),
  ], { gap: 4 });

  if (compact) {
    const services = summary(route);
    return card([
      header,
      row([text(exit ? showIP(exit.ip, mask) : "查询失败", 14, exit ? C.text : C.sub, "bold", { flex: 1 })]),
      row([
        text([flag(exit?.cc), where].filter(Boolean).join(" ") || "地区未知", 9, C.sub, "regular", { flex: 1 }),
        ...(services ? [services] : []),
      ], { gap: 4 }),
    ], { padding });
  }

  const pillView = kindPill(exit?.kind);
  return card([
    header,
    row([
      ...(exit && flag(exit.cc) ? [text(flag(exit.cc), 12, C.text)] : []),
      text(exit ? showIP(exit.ip, mask) : "查询失败", 15, exit ? C.text : C.sub, "bold", { flex: 1 }),
      ...(pillView ? [pillView] : []),
    ], { gap: 4 }),
    row([
      text(where || "地区未知", 9.5, C.sub, "regular", { flex: 1 }),
      ...(route.services.length ? [chips(route)] : []),
    ], { gap: 6 }),
  ], { padding });
}

function kv(label, value, color = C.text) {
  return row([text(label, 9, C.sub), spacer(), text(value, 9, color, "semibold")], { gap: 4 });
}

function localPanel(local, direct, directPing, mask, updated) {
  const latency = latencyView(directPing);
  const where = direct ? [flag(direct.cc), direct.city, shortName(direct.isp)].filter(Boolean).join(" ") : "";
  const badge = row([spacer(), symbol(local.symbol, 12, C.blue), spacer()], {
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: C.blueSoft,
  });
  return column([
    row([badge, column([text(local.title, 12, C.text, "bold"), text(local.sub, 9, C.sub)], { gap: 1, flex: 1 })], { gap: 6 }),
    spacer(),
    column([
      text("直连出口", 8.5, C.sub),
      text(direct ? showIP(direct.ip, mask) : "查询失败", 13, direct ? C.text : C.sub, "bold"),
      text(where || "地区未知", 9.5, C.sub),
    ], { gap: 1 }),
    spacer(),
    column([
      kv("延迟", latency.label, latency.color),
      kv("内网", local.ip),
      kv("IPv6", local.ipv6 ? "可用" : "无", local.ipv6 ? C.green : C.sub),
    ], { gap: 2 }),
    row([
      text("更新", 8, C.faint),
      { type: "date", date: updated.toISOString(), format: "time", font: { size: 8 }, textColor: C.faint },
    ], { gap: 2 }),
  ], { flex: 1, gap: 4 });
}

export default async function (ctx) {
  const family = ctx.widgetFamily;
  const accessory = Boolean(family?.startsWith("accessory"));
  const small = family === "systemSmall";
  const wantDirect = !small && !accessory;
  const mask = /^(1|true|yes|on)$/i.test((ctx.env?.MASK_IP || "").trim());
  const pingUrl = (ctx.env?.CHECK_URL || "").trim() || PROXY_PING;
  const routes = [readRoute(ctx, 1), readRoute(ctx, 2)];

  // Latency first, on its own, so the lookups below do not distort it.
  const pings = await Promise.all([
    ...routes.map(route => (route.policy ? ping(ctx, pingUrl, route.policy) : null)),
    wantDirect ? ping(ctx, DIRECT_PING, "DIRECT") : null,
  ]);
  const probes = await Promise.all([
    ...routes.map(route => (route.policy && !accessory ? probeRoute(ctx, route) : null)),
    wantDirect ? queryExit(ctx, "DIRECT") : null,
  ]);
  const results = routes.map((route, i) => ({ ...route, ping: pings[i], exit: probes[i]?.exit || null, states: probes[i]?.states || [] }));
  const direct = probes[2] || null;
  const updated = new Date();
  const widget = (children, props = {}) => ({
    type: "widget",
    children,
    refreshAfter: new Date(updated.getTime() + REFRESH_MINUTES * 60 * 1000).toISOString(),
    ...props,
  });

  if (accessory) {
    const brief = route => `${route.name} ${route.policy ? latencyView(route.ping).label : "未配置"}`;
    if (family === "accessoryInline") return widget([text(results.map(brief).join(" · "), 12, C.text)]);
    return widget(results.map(route => text(brief(route), 12, C.text, "semibold")));
  }

  if (small) {
    return widget(results.map(route => routeCard(route, mask, true)), { backgroundColor: C.background, padding: 10, gap: 6 });
  }

  return widget([
    row([
      localPanel(readLocal(ctx, direct), direct, pings[2], mask, updated),
      column(results.map(route => routeCard(route, mask, false)), { flex: 2, gap: 5 }),
    ], { flex: 1, gap: 10, alignItems: "start" }),
  ], { backgroundColor: C.background, padding: 10 });
}
