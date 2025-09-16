#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64, json, sys
from urllib.parse import urlparse, parse_qs

HEADER = '''redir-port: 9797
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
tun:
  exclude-package: [
    ]
  enable: false
  mtu: 9000
  device: clash
  stack: mixed
  dns-hijack:
  - any:53
  - tcp://any:53
  auto-route: true
  strict-route: false
  auto-redirect: true
  auto-detect-interface: true
profile:
  store-selected: true
  store-fake-ip: false
dns:
  cache-algorithm: arc
  enable: true
  prefer-h3: false
  ipv6: false
  default-nameserver:
  - 8.8.8.8
  - 1.1.1.1
  listen: 0.0.0.0:1053
  use-hosts: true
  enhanced-mode: redir-host
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
  - '*.lan'
  - '*.ntp.*'
  nameserver:
  - 1.1.1.1
  - 8.8.8.8
  proxy-server-nameserver:
  - 112.215.203.246
'''

def _ensure_path(p):
    if not p:
        return "/"
    return p if p.startswith("/") else ("/" + p)

def _lower_or_none(x):
    return x.lower() if isinstance(x, str) else x

def parse_vmess(link):
    b64 = link.split("://",1)[1].strip()
    b64 += "=" * (-len(b64) % 4)
    data = json.loads(base64.b64decode(b64).decode("utf-8"))
    name = data.get("ps") or "Proxy1"
    server = data.get("add") or ""
    port = int(data.get("port", 443))
    uuid = data.get("id") or ""
    aid  = int(data.get("aid") or 0)
    net  = data.get("net") or "ws"
    path = _ensure_path(data.get("path"))
    host = _lower_or_none(data.get("host") or data.get("sni"))
    sni  = _lower_or_none(data.get("sni") or host)

    return {
        "name": name,
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": aid,
        "cipher": "auto",
        "tls": True,
        "skip-cert-verify": True,
        "udp": True,
        "network": net,
        "ws-opts": {"path": path, "headers": {"Host": host or ""}},
        "servername": sni or "",
    }

def parse_vless(link):
    u = urlparse(link)
    name = (u.fragment or "ProxyVLESS").strip()
    uuid = u.username or ""
    server = u.hostname or ""
    port = int(u.port or 443)
    q = parse_qs(u.query)
    typ = q.get("type",["ws"])[0]
    path = _ensure_path(q.get("path",["/"])[0])
    host = _lower_or_none(q.get("host",[None])[0])
    sni  = _lower_or_none(q.get("sni",[host])[0])

    return {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "tls": True,
        "skip-cert-verify": True,
        "udp": True,
        "network": typ,
        "ws-opts": {"path": path, "headers": {"Host": host or ""}},
        "servername": sni or "",
    }

def parse_trojan(link):
    u = urlparse(link)
    name = (u.fragment or "ProxyTrojan").strip()
    pwd = u.username or ""
    server = u.hostname or ""
    port = int(u.port or 443)
    q = parse_qs(u.query)
    typ = q.get("type",["ws"])[0]
    path = _ensure_path(q.get("path",["/"])[0])
    host = _lower_or_none(q.get("host",[None])[0])
    sni  = _lower_or_none(q.get("sni",[host])[0])

    return {
        "name": name,
        "type": "trojan",
        "server": server,
        "port": port,
        "password": pwd,
        "tls": True,
        "skip-cert-verify": True,
        "udp": True,
        "network": typ,
        "ws-opts": {"path": path, "headers": {"Host": host or ""}},
        "servername": sni or "",
    }

def parse_link(link):
    scheme = link.split("://",1)[0].lower()
    if scheme == "vmess": return parse_vmess(link)
    if scheme == "vless": return parse_vless(link)
    if scheme == "trojan": return parse_trojan(link)
    return None

def collect_proxies():
    print("Masukkan link VMess/VLESS/Trojan (Enter kosong untuk selesai):")
    items, idx = [], 1
    while True:
        try:
            raw = input("> ").strip()
        except EOFError:
            break
        if raw == "" or raw.lower() == "selesai":
            break
        p = parse_link(raw)
        if not p:
            print("❌ Link tidak dikenal")
            continue
        if not p.get("name"):
            p["name"] = f"Proxy{idx}"
        items.append(p); idx += 1
    return items

def emit_yaml(proxies):
    print(HEADER, end="")
    print("proxies:")
    for p in proxies:
        print(f"- name: {p['name']}")
        print(f"  type: {p['type']}")
        print(f"  server: {p['server']}")
        print(f"  port: {p['port']}")
        if p["type"] == "vmess":
            print(f"  uuid: {p['uuid']}")
            print(f"  alterId: {p.get('alterId',0)}")
            print("  cipher: auto")
        elif p["type"] == "vless":
            print(f"  uuid: {p['uuid']}")
        elif p["type"] == "trojan":
            print(f"  password: {p['password']}")
        print("  tls: true")
        print("  skip-cert-verify: true")
        print("  udp: true")
        print(f"  network: {p.get('network','ws')}")
        path = p["ws-opts"]["path"]
        host = p["ws-opts"]["headers"]["Host"]
        print("  ws-opts:")
        print(f"    path: {path}")
        print("    headers:")
        print(f"      Host: {host}")
        print(f"  servername: {p.get('servername','')}")
    print("proxy-groups:")
    print("- name: 🆃🆆🅾🅿🅴🅽")
    print("  type: select")
    print("  proxies:")
    print("  - DIRECT")
    for p in proxies:
        print(f"  - {p['name']}")
    print("rules:")
    print("- MATCH,🆃🆆🅾🅿🅴🅽")


def main():
    proxies = collect_proxies()
    if not proxies:
        print("Tidak ada link.")
        sys.exit(1)
    emit_yaml(proxies)

if __name__ == "__main__":
    main()
