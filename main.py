#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ArsipClash CLI (fixed) - supports VMess, VLESS, Trojan

import sys, re, json, base64
from urllib.parse import urlparse, parse_qs, unquote

def b64_normalize(s: str):
    s = s.replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return s

LINK_REGEX = re.compile(r"(vmess://[A-Za-z0-9\-\_\=\/\+]+|vless://[^\s]+|trojan://[^\s]+)", re.IGNORECASE)

def extract_links(text: str):
    found = LINK_REGEX.findall(text or "")
    out = []
    for x in found:
        t = x.strip()
        if t and t not in out:
            out.append(t)
    return out

# ---------------- VMESS ----------------
def parse_vmess(link: str):
    try:
        payload = link[len("vmess://"):].split('#')[0].strip()
        decoded = base64.b64decode(b64_normalize(payload)).decode("utf-8", errors="ignore")
        obj = json.loads(decoded)
        return obj
    except Exception as e:
        print("❌ vmess parse error:", e)
        return None

def vmess_to_clash(v):
    name = v.get("ps") or f"VMess {v.get('add','')}"
    tlsEnabled = v.get("tls") in ("tls", "TLS", "1", True)
    net = (v.get("net") or "ws").lower()
    proxy = {
        "name": str(name),
        "type": "vmess",
        "server": v.get("add"),
        "port": int(v.get("port") or 0),
        "uuid": v.get("id"),
        "alterId": int(v.get("aid") or 0),
        "cipher": "auto",
        "tls": tlsEnabled,
        "skip-cert-verify": True,
        "udp": True,
        "network": net
    }
    sni = v.get("sni") or v.get("host") or None
    if tlsEnabled and sni:
        proxy["servername"] = sni
    if net == "ws":
        path = v.get("path") or "/"
        host = v.get("host") or sni or v.get("add")
        proxy["ws-opts"] = {"path": path, "headers": {"Host": host}}
    return proxy

# ---------------- VLESS ----------------
def parse_vless(link: str):
    try:
        u = urlparse(link)
        uuid = u.username or ""
        hostname = u.hostname
        port = int(u.port) if u.port else 443
        params = parse_qs(u.query)
        net = (params.get("type") or ["tcp"])[0].lower()
        security = (params.get("security") or [""])[0].lower()
        tls = security in ("tls", "reality", "xtls")
        sni = (params.get("sni") or [hostname])[0]
        path = (params.get("path") or ["/"])[0]
        hostHeader = (params.get("host") or [sni or hostname])[0]
        name = unquote(u.fragment) if u.fragment else f"VLESS {hostname}:{port}"
        d = {
            "name": name,
            "type": "vless",
            "server": hostname,
            "port": port,
            "uuid": uuid,
            "tls": tls,
            "udp": True,
            "network": net
        }
        if tls and sni:
            d["servername"] = sni
        if net == "ws":
            d["ws-opts"] = {"path": path, "headers": {"Host": hostHeader}}
        return d
    except Exception as e:
        print("❌ vless parse error:", e)
        return None

# ---------------- TROJAN ----------------
def parse_trojan(link: str):
    try:
        u = urlparse(link)
        password = unquote(u.username or "")
        hostname = u.hostname
        port = int(u.port) if u.port else 443
        params = parse_qs(u.query)
        net = (params.get("type") or ["tcp"])[0].lower()
        security = (params.get("security") or ["tls"])[0].lower()
        tls = security == "tls"
        sni = (params.get("sni") or [hostname])[0]
        path = (params.get("path") or ["/"])[0]
        hostHeader = (params.get("host") or [sni or hostname])[0]
        name = unquote(u.fragment) if u.fragment else f"TROJAN {hostname}:{port}"
        d = {
            "name": name,
            "type": "trojan",
            "server": hostname,
            "port": port,
            "password": password,
            "tls": tls,
            "sni": sni,
            "udp": True,
            "network": net
        }
        if net == "ws":
            d["ws-opts"] = {"path": path, "headers": {"Host": hostHeader}}
        return d
    except Exception as e:
        print("❌ trojan parse error:", e)
        return None

# ---------------- YAML BUILD ----------------
HEADER = """redir-port: 9797
tproxy-port: 9898
mode: global
allow-lan: true
bind-address: '*'
log-level: silent
unified-delay: true
geodata-mode: true
geodata-loader: memconservative
ipv6: false
external-controller: 0.0.0.0:9090
secret: ''
external-ui: /data/adb/box/clash/dashboard
global-client-fingerprint: chrome
find-process-mode: strict
keep-alive-interval: 15
geo-auto-update: false
geo-update-interval: 24
tcp-concurrent: true

proxies:
"""

def build_clash_yaml(proxies_list):
    lines = [HEADER]
    for p in proxies_list:
        lines.append(f"- name: \"{p.get('name','Proxy')}\"")
        for key in p:
            if key not in ("name", "ws-opts") and p[key] is not None:
                lines.append(f"  {key}: {p[key]}")
        if "ws-opts" in p:
            ws = p["ws-opts"]
            lines.append("  ws-opts:")
            lines.append(f"    path: \"{ws['path']}\"")
            lines.append("    headers:")
            lines.append(f"      Host: \"{ws['headers']['Host']}\"")
    lines.append("proxy-groups:")
    lines.append("  - name: \"🆃🆆🅾🅿🅴🅽\"")
    lines.append("    type: select")
    lines.append("    proxies:")
    for p in proxies_list:
        lines.append(f"      - \"{p['name']}\"")
    lines.append("      - DIRECT")
    lines.append("rules:")
    lines.append("- MATCH,🆃🆆🅾🅿🅴🅽")
    return "\n".join(lines)

# --------------- MAIN ---------------
def main():
    proxies = []
    print("Masukkan link VMess/VLESS/Trojan (kosongkan untuk selesai):")
    while True:
        try:
            link = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not link:
            break
        if link.startswith("vmess://"):
            obj = parse_vmess(link)
            if obj: proxies.append(vmess_to_clash(obj))
        elif link.startswith("vless://"):
            obj = parse_vless(link)
            if obj: proxies.append(obj)
        elif link.startswith("trojan://"):
            obj = parse_trojan(link)
            if obj: proxies.append(obj)
        else:
            print("❌ Link tidak dikenal")

    if proxies:
        print("\n===== Hasil Config =====\n")
        print(build_clash_yaml(proxies))
    else:
        print("❌ Tidak ada link valid")

if __name__ == "__main__":
    main()
