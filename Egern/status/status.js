// Egern generic widget: proxy status overview (small / medium).
// env: POLICY_1 / POLICY_2 policy group names, NAME_1 / NAME_2 labels, CHECK_URL latency target.
const IP_URL = "https://ipwho.is/?lang=zh-CN";
const IP_FALLBACK_URL = "https://api64.ipify.org?format=json";
const DEFAULT_CHECK_URL = "https://www.gstatic.com/generate_204";
const TIMEOUT = 5000;
const REFRESH_MINUTES = 15;

const C = {
  background: ["#0B1020", "#18213D"],
  text: "#F8FAFC",
  sub: "#94A3B8",
  dim: "#64748B",
  ok: "#34D399",
  warn: "#FBBF24",
  bad: "#F87171",
  local: "#34D399",
  accents: ["#38BDF8", "#A78BFA"],
};

const text = (value, size, color, weight = "regular") => ({
  type: "text",
  text: String(value),
  font: { size, weight },
  textColor: color,
  maxLines: 1,
  minScale: 0.6,
});
const stack = (direction, children, props = {}) => ({ type: "stack", direction, alignItems: "center", children, ...props });
const row = (children, props) => stack("row", children, props);
const column = (children, props) => stack("column", children, { alignItems: "start", ...props });
const spacer = () => ({ type: "spacer" });
const icon = (name, size, color) => ({ type: "image", src: `sf-symbol:${name}`, width: size, height: size, color });

function get(ctx, url, policy) {
  const options = { timeout: TIMEOUT };
  if (policy) options.policy = policy;
  return ctx.http.get(url, options);
}

function flag(code) {
  if (!/^[A-Za-z]{2}$/.test(code || "")) return "";
  return String.fromCodePoint(...code.toUpperCase().split("").map(char => 0x1f1a5 + char.charCodeAt(0)));
}

function networkName(asn, organization) {
  return [asn ? `AS${asn}` : "", organization].filter(Boolean).join(" ");
}

async function queryExit(ctx, policy) {
  try {
    const response = await get(ctx, IP_URL, policy);
    const data = await response.json();
    if (response.status < 300 && data.success !== false && data.ip) {
      const connection = data.connection || {};
      return {
        ip: data.ip,
        flag: flag(data.country_code),
        place: [data.country, data.city].filter(Boolean).join(" · "),
        network: networkName(connection.asn, connection.org || connection.isp),
      };
    }
  } catch (_) {}
  try {
    const response = await get(ctx, IP_FALLBACK_URL, policy);
    const { ip } = await response.json();
    if (response.status >= 300 || !ip) return null;
    const info = await ctx.lookupIP(ip);
    return {
      ip,
      flag: flag(info?.country),
      place: info?.country || "",
      network: info ? networkName(info.asn, info.organization) : "",
    };
  } catch (_) {
    return null;
  }
}

async function measure(ctx, policy) {
  const start = Date.now();
  try {
    const response = await get(ctx, ctx.env?.CHECK_URL || DEFAULT_CHECK_URL, policy);
    return response.status < 400 ? Date.now() - start : null;
  } catch (_) {
    return null;
  }
}

async function probeSlot(ctx, index) {
  const env = ctx.env || {};
  const policy = (env[`POLICY_${index}`] || "").trim();
  const name = (env[`NAME_${index}`] || "").trim() || policy || `策略组 ${index}`;
  const key = `POLICY_${index}`;
  if (!policy) return { name, key, configured: false };
  const [exit, ms] = await Promise.all([queryExit(ctx, policy), measure(ctx, policy)]);
  return { name, key, configured: true, exit, ms };
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
function readLocal(ctx) {
  const device = ctx.device || {};
  const ssid = device.wifi?.ssid;
  const carrier = device.cellular?.carrier;
  const generation = radioGeneration(device.cellular?.radio);
  const iface = device.ipv4?.interface || device.ipv6?.interface || "";
  const address = device.ipv4?.address || device.ipv6?.address || "—";
  if (ssid || /^en\d/.test(iface)) return { icon: "wifi", title: "Wi-Fi", sub: ssid || "无线局域网", address };
  if (/^pdp_ip/.test(iface) || carrier || generation) {
    return {
      icon: "antenna.radiowaves.left.and.right",
      title: "蜂窝网络",
      sub: [carrier, generation].filter(Boolean).join(" · ") || "移动数据",
      address,
    };
  }
  return { icon: "network", title: "网络未知", sub: iface || "未获取到接口", address };
}

function describe(slot) {
  const reachable = slot.ms !== null;
  return {
    color: reachable && slot.exit ? C.ok : reachable || slot.exit ? C.warn : C.bad,
    latency: reachable ? `${slot.ms} ms` : "失败",
    latencyColor: !reachable ? C.bad : slot.ms < 300 ? C.ok : slot.ms < 800 ? C.warn : C.bad,
  };
}

function policyCard(slot, accent, detailed) {
  const props = {
    flex: 1,
    padding: [6, 10],
    gap: 2,
    backgroundColor: `${accent}1F`,
    borderRadius: 14,
    borderWidth: 0.5,
    borderColor: `${accent}44`,
  };

  if (!slot.configured) {
    return column([
      spacer(),
      row([icon("circle.fill", 6, C.dim), { ...text(slot.name, 11, accent, "semibold"), flex: 1 }], { gap: 4 }),
      text("未配置", detailed ? 15 : 13, C.sub, "semibold"),
      text(`填写 ${slot.key} 环境变量`, 9, C.dim),
      spacer(),
    ], props);
  }

  const state = describe(slot);
  const exit = slot.exit;
  const detail = detailed ? [exit?.place, exit?.network].filter(Boolean).join(" · ") : exit?.place;
  return column([
    spacer(),
    row([
      icon("circle.fill", 6, state.color),
      { ...text(slot.name, 11, accent, "semibold"), flex: 1 },
      text(state.latency, 10, state.latencyColor, "medium"),
    ], { gap: 4 }),
    row([
      ...(exit?.flag ? [text(exit.flag, 12, C.text)] : []),
      { ...text(exit ? exit.ip : "查询失败", detailed ? 15 : 13, exit ? C.text : C.sub, "semibold"), flex: 1 },
    ], { gap: 4 }),
    ...(detail ? [text(detail, 10, C.sub)] : []),
    spacer(),
  ], props);
}

function block(label, value, note) {
  return column([
    text(label, 9, C.dim),
    text(value, 11, C.text, "medium"),
    ...(note ? [text(note, 9, C.sub)] : []),
  ], { gap: 1 });
}

function localPanel(local, direct, updated) {
  const badge = row([spacer(), icon(local.icon, 14, C.local), spacer()], {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: `${C.local}26`,
  });
  return column([
    row([badge, column([text(local.title, 13, C.text, "bold"), text(local.sub, 9, C.sub)], { gap: 1, flex: 1 })], { gap: 6 }),
    spacer(),
    block("本机 IP", local.address),
    block(
      "直连出口",
      direct ? direct.ip : "查询失败",
      direct ? [direct.flag, direct.place].filter(Boolean).join(" ") : "",
    ),
    spacer(),
    row([
      icon("arrow.clockwise", 8, C.dim),
      { type: "date", date: updated.toISOString(), format: "time", font: { size: 9 }, textColor: C.dim },
    ], { gap: 3 }),
  ], { flex: 1, gap: 4 });
}

export default async function (ctx) {
  const family = ctx.widgetFamily;
  const accessory = Boolean(family?.startsWith("accessory"));
  const small = family === "systemSmall";
  const [first, second, direct] = await Promise.all([
    probeSlot(ctx, 1),
    probeSlot(ctx, 2),
    small || accessory ? null : queryExit(ctx, "DIRECT"),
  ]);
  const slots = [first, second];
  const updated = new Date();
  const widget = (children, props = {}) => ({
    type: "widget",
    children,
    refreshAfter: new Date(updated.getTime() + REFRESH_MINUTES * 60 * 1000).toISOString(),
    ...props,
  });

  if (accessory) {
    const brief = slot => `${slot.name} ${slot.configured ? describe(slot).latency : "未配置"}`;
    if (family === "accessoryInline") return widget([text(slots.map(brief).join(" · "), 12, C.text)]);
    return widget(slots.map(slot => text(brief(slot), 12, C.text, "semibold")));
  }

  const background = {
    backgroundGradient: {
      type: "linear",
      colors: C.background,
      startPoint: { x: 0, y: 0 },
      endPoint: { x: 1, y: 1 },
    },
  };

  if (small) {
    return widget(slots.map((slot, i) => policyCard(slot, C.accents[i], false)), { ...background, padding: 10, gap: 6 });
  }

  return widget([
    row([
      localPanel(readLocal(ctx), direct, updated),
      column(slots.map((slot, i) => policyCard(slot, C.accents[i], true)), { flex: 2, gap: 6 }),
    ], { flex: 1, gap: 10 }),
  ], { ...background, padding: 12 });
}
