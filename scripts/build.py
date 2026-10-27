#!/usr/bin/env python3
"""按 sources.yaml 拉取上游规则，合并去重排序后输出 Clash / Loon 规则文件。

用法: [MIHOMO_BIN=mihomo 路径] build.py <输出目录>
设置了 MIHOMO_BIN 时，Clash 额外输出 .mrs（域名、IP）和 -other.yaml（其余规则）。
任一上游拉取失败，或某个集合规则数低于 min_rules，则以非零状态退出，不产出该集合。

去重规则（同一集合内策略相同，所以以下规则都是冗余的）：
  - 大小写不同的域名、重复行
  - 被更短 DOMAIN-SUFFIX 覆盖的 DOMAIN / DOMAIN-SUFFIX
  - 包含某个 DOMAIN-KEYWORD 的 DOMAIN / DOMAIN-SUFFIX，以及被更短关键字包含的关键字
  - 被更大网段覆盖或可合并的 IP 段
IP / GEOIP / IP-ASN 规则统一带 no-resolve。输出顺序固定，相同输入产出相同文件。

sources.yaml 中集合可写 exclude: [规则, ...]，在去重前从该集合剔除完全相同的规则，
用于解决上游把整个域名划进错误集合的问题（如 proxy 上游带了 DOMAIN-SUFFIX,apple.com）。
"""
import gzip
import ipaddress
import os
import re
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

LOGIC = {"AND", "OR", "NOT"}
CLASH_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "PROCESS-NAME", "PROCESS-PATH",
} | LOGIC
LOON_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "USER-AGENT", "URL-REGEX",
} | LOGIC
NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}

# 输出顺序：匹配开销小的在前，关键字和正则在后
TYPE_ORDER = {
    t: i for i, t in enumerate([
        "DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
        "DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH",
        "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT",
    ])
}

IPV4_BARE = re.compile(r"[\d.]+(/\d+)?")

warnings = []


def fetch(url, retries=3):
    headers = {"User-Agent": "ProxyRules-build", "Accept-Encoding": "gzip"}
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data.decode("utf-8")
        except Exception as e:
            if attempt == retries:
                raise RuntimeError(f"拉取失败: {url}: {e}") from e
            time.sleep(2 * attempt)


def normalize(line):
    """把一行原始文本规范成 (类型, 值)，无法识别返回 None。

    域名转小写；策略组和 no-resolve 一律丢弃，输出时统一补上 no-resolve。
    """
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")) or s in ("payload:", "rules:"):
        return None
    if s.startswith("- "):
        s = s[2:].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]

    # domain / ipcidr behavior 的裸写法
    if "," not in s:
        if s.startswith("+."):
            return ("DOMAIN-SUFFIX", s[2:].lower().rstrip("."))
        if s.startswith("."):
            return ("DOMAIN-SUFFIX", s[1:].lower().rstrip("."))
        if ":" in s or "/" in s or IPV4_BARE.fullmatch(s):
            return ("IP-CIDR6" if ":" in s else "IP-CIDR", s)
        if "." in s and not any(c in s for c in "*? "):
            return ("DOMAIN", s.lower().rstrip("."))
        warnings.append(f"无法识别: {s}")
        return None

    rtype, _, rest = s.partition(",")
    rtype = rtype.strip().upper()
    if rtype in LOGIC:
        return (rtype, s)
    rest = rest.strip()
    if rtype in DOMAIN_TYPES or rtype in NO_RESOLVE_TYPES:
        value = rest.split(",", 1)[0].strip()
    else:
        value = rest
    if rtype in ("DOMAIN", "DOMAIN-SUFFIX"):
        value = value.lower().rstrip(".")
    elif rtype == "DOMAIN-KEYWORD":
        value = value.lower()
    elif rtype == "GEOIP":
        value = value.upper()
    return (rtype, value)


def parse(text):
    return [r for r in map(normalize, text.splitlines()) if r]


def has_parent(domain, suffixes):
    """domain 的任一上级域名（不含自身）是否在 suffixes 里。"""
    i = domain.find(".")
    while i != -1:
        if domain[i + 1:] in suffixes:
            return True
        i = domain.find(".", i + 1)
    return False


def merge(chunks):
    """合并并去重，返回按固定顺序排序的 [(类型, 值)]。"""
    suffixes, domains, keywords, others = set(), set(), set(), set()
    nets = {4: [], 6: []}
    for rules in chunks:
        for t, v in rules:
            if t == "DOMAIN-SUFFIX":
                suffixes.add(v)
            elif t == "DOMAIN":
                domains.add(v)
            elif t == "DOMAIN-KEYWORD":
                keywords.add(v)
            elif t in ("IP-CIDR", "IP-CIDR6"):
                try:
                    net = ipaddress.ip_network(v, strict=False)
                except ValueError:
                    warnings.append(f"无效 IP 段: {v}")
                    continue
                nets[net.version].append(net)
            else:
                others.add((t, v))

    # 被更短关键字包含的关键字是冗余的
    keywords = {k for k in keywords if not any(o != k and o in k for o in keywords)}
    kw_re = re.compile("|".join(map(re.escape, sorted(keywords)))) if keywords else None

    def redundant(d):
        return kw_re is not None and kw_re.search(d) is not None

    out_suffix = sorted(
        (d for d in suffixes if not has_parent(d, suffixes) and not redundant(d)),
        key=lambda d: d.split(".")[::-1],
    )
    out_domain = sorted(
        (d for d in domains
         if d not in suffixes and not has_parent(d, suffixes) and not redundant(d)),
        key=lambda d: d.split(".")[::-1],
    )

    out = [("DOMAIN", d) for d in out_domain]
    out += [("DOMAIN-SUFFIX", d) for d in out_suffix]
    for version, rtype in ((4, "IP-CIDR"), (6, "IP-CIDR6")):
        out += [(rtype, str(n)) for n in ipaddress.collapse_addresses(nets[version])]
    out += sorted(
        [("DOMAIN-KEYWORD", k) for k in keywords] + list(others),
        key=lambda r: (TYPE_ORDER.get(r[0], 99), r[0], r[1]),
    )
    out.sort(key=lambda r: TYPE_ORDER.get(r[0], 99))  # 稳定排序，只按类型分组
    return out


def build_set(chunks, allowed, exclude=()):
    """过滤不支持的类型和 exclude 规则后合并。在子进程里运行，返回 (规则, 被丢弃类型计数, 警告)。

    exclude 在去重之前生效，被剔除规则所覆盖的子域名会保留下来。
    """
    exclude = set(exclude)
    dropped = Counter()
    kept = []
    for rules in chunks:
        keep = []
        for r in rules:
            if r in exclude:
                continue
            if r[0] in allowed:
                keep.append(r)
            else:
                dropped[r[0]] += 1
        kept.append(keep)
    warnings.clear()
    rules = merge(kept)
    return rules, dropped, list(warnings)


def fmt(rule):
    t, v = rule
    if t in LOGIC:
        return v
    if t in NO_RESOLVE_TYPES:
        return f"{t},{v},no-resolve"
    return f"{t},{v}"


def render_clash(rules):
    body = "".join("  - '%s'\n" % fmt(r).replace("'", "''") for r in rules)
    return "payload:\n" + body


def render_loon(rules):
    return "".join(fmt(r) + "\n" for r in rules)


def split_for_mrs(rules):
    """拆成 (域名, IP, 其余规则)，对应 mrs 的 domain / ipcidr 两种 behavior。"""
    domains, ips, rest = [], [], []
    for r in rules:
        t, v = r
        if t == "DOMAIN-SUFFIX":
            domains.append("+." + v)
        elif t == "DOMAIN":
            domains.append(v)
        elif t in ("IP-CIDR", "IP-CIDR6"):
            ips.append(v)
        else:
            rest.append(r)
    return domains, ips, rest


def to_mrs(mihomo, behavior, lines, target):
    src = target.with_suffix(".txt")
    src.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
    try:
        subprocess.run(
            [mihomo, "convert-ruleset", behavior, "text", str(src), str(target)],
            check=True,
        )
    finally:
        src.unlink()


def main():
    out_dir = Path(sys.argv[1])
    config = yaml.safe_load((ROOT / "sources.yaml").read_text(encoding="utf-8"))
    sets = config["sets"]

    urls = sorted({u for s in sets.values() for u in s.get("upstream", [])})
    with ThreadPoolExecutor(max_workers=16) as pool:
        upstream = dict(zip(urls, pool.map(lambda u: parse(fetch(u)), urls)))

    platforms = {
        "clash": ("yaml", CLASH_TYPES, render_clash),
        "loon": ("lsr", LOON_TYPES, render_loon),
    }
    mihomo = os.environ.get("MIHOMO_BIN")
    if not mihomo:
        print("未设置 MIHOMO_BIN，跳过 .mrs 输出")

    with ProcessPoolExecutor() as pool:
        jobs = {}
        for name, spec in sets.items():
            for plat, (_, allowed, _) in platforms.items():
                chunks = []
                custom = spec.get("custom", {}).get(plat, [])
                if isinstance(custom, str):
                    custom = [custom]
                for path in custom:
                    chunks.append(parse((ROOT / path).read_text(encoding="utf-8")))
                chunks += [upstream[u] for u in spec.get("upstream", [])]
                exclude = parse("\n".join(spec.get("exclude", [])))
                jobs[(name, plat)] = pool.submit(build_set, chunks, allowed, exclude)

        failed = False
        all_warnings = set(warnings)
        for (name, plat), job in jobs.items():
            ext, _, render = platforms[plat]
            rules, dropped, warns = job.result()
            all_warnings.update(f"[{plat}/{name}] {w}" for w in warns)
            for t, n in dropped.items():
                all_warnings.add(f"[{plat}/{name}] 丢弃不支持的规则类型 {t}: {n} 条")

            print(f"{plat}/{name}: {len(rules)} 条")
            min_rules = sets[name]["min_rules"]
            if len(rules) < min_rules:
                print(f"错误: {plat}/{name} 少于 min_rules={min_rules}", file=sys.stderr)
                failed = True
                continue

            target = out_dir / plat / f"{name}.{ext}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(render(rules), encoding="utf-8")

            if plat == "clash" and mihomo:
                domains, ips, rest = split_for_mrs(rules)
                if domains:
                    to_mrs(mihomo, "domain", domains, out_dir / plat / f"{name}.mrs")
                if ips:
                    to_mrs(mihomo, "ipcidr", ips, out_dir / plat / f"{name}-ip.mrs")
                if rest:
                    (out_dir / plat / f"{name}-other.yaml").write_text(
                        render_clash(rest), encoding="utf-8"
                    )
                print(f"  mrs: 域名 {len(domains)} / IP {len(ips)} / 其余 {len(rest)}")

    for w in sorted(all_warnings):
        print(f"警告: {w}", file=sys.stderr)
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
