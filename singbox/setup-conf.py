#!/usr/bin/env python3
"""Generate a sing-box server config.json and client links.txt."""
from __future__ import annotations

import argparse
import base64
import json
import logging
import secrets
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode

log = logging.getLogger("setup-conf")

DEFAULT_INBOUND_PORTS: dict[str, int] = {
    "mixed": 9200,
    "vless": 9201,
    # "shadowsocks": 9202,
    "hysteria2": 443,
}


def read_tags(path: Path) -> list[str]:
    tags: list[str] = []
    if path.is_file():
        lines = (ln.strip() for ln in path.read_text(encoding="utf-8").splitlines())
        tags = list(dict.fromkeys(ln for ln in lines if ln and not ln.startswith("#")))
    if not tags:
        log.info("no tags in %s, skipping", path)
    return tags


def _gen_password() -> str:
    return secrets.token_urlsafe(16)


def make_inbounds(ports: dict[str, int]) -> dict[str, dict[str, Any]]:
    tls = {
        "enabled": True,
        "server_name": "dobro.ru",
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/cert.pem",
        "key_path": "/etc/sing-box/key.pem",
    }
    available: dict[str, dict[str, Any]] = {
        "mixed": {
            "type": "mixed",
            "tag": "g-mx-i",
            "listen": "::",
            "users": [],
        },
        "shadowsocks": {
            "type": "shadowsocks",
            "tag": "g-ss-i",
            "listen": "::",
            "method": "aes-128-gcm",
            "password": _gen_password(),
            "users": [],
            "multiplex": {"enabled": True},
        },
        "vless": {
            "type": "vless",
            "tag": "g-vs-i",
            "listen": "::",
            "users": [],
            "tls": {**tls, "alpn": ["h2", "http/1.1"]},
            "multiplex": {"enabled": True},
        },
        "hysteria2": {
            "type": "hysteria2",
            "tag": "g-h2-i",
            "listen": "::",
            "users": [],
            "tls": dict(tls),
        },
    }
    unknown = [t for t in ports if t not in available]
    if unknown:
        raise SystemExit(f"unknown inbound types: {unknown}")
    invalid = {t: p for t, p in ports.items() if not 1 <= p <= 65535}
    if invalid:
        raise SystemExit(f"invalid ports: {invalid}")
    return {t: {**available[t], "listen_port": p} for t, p in ports.items()}


def make_template() -> dict[str, Any]:
    return {
        "log": {"level": "warn"},
        "experimental": {
            "cache_file": {"enabled": True},
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "cloudflare-doh",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                },
                {
                    "type": "https",
                    "tag": "google-doh",
                    "server": "8.8.8.8",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "dns.google"},
                },
                {
                    "type": "https",
                    "tag": "yandex-doh",
                    "server": "77.88.8.8",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": {
                        "enabled": True,
                        "server_name": "common.dot.dns.yandex.net",
                    },
                },
            ],
            "rules": [
                {
                    "domain_suffix": [".ru", ".рф", ".su"],
                    "action": "route",
                    "server": "yandex-doh",
                }
            ],
            "final": "cloudflare-doh",
            "strategy": "prefer_ipv4",
            "optimistic": {"enabled": True},
        },
        "inbounds": [],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "default_domain_resolver": "cloudflare-doh",
            "rules": [{"port": 53, "action": "hijack-dns"}],
            "final": "block",
        },
    }


def new_user(inbound_type: str, name: str) -> dict[str, str]:
    if inbound_type == "mixed":
        return {"username": name, "password": _gen_password()}
    if inbound_type == "vless":
        return {"name": name, "uuid": str(uuid.uuid4())}
    return {"name": name, "password": _gen_password()}


def add_route(
    template: dict[str, Any],
    inbounds: dict[str, dict[str, Any]],
    user: str,
    outbound: str,
) -> None:
    template["route"]["rules"].append(
        {
            "inbound": [inb["tag"] for inb in inbounds.values()],
            "auth_user": [user],
            "action": "route",
            "outbound": outbound,
        }
    )


def _q(value: str) -> str:
    return quote(value, safe="")


def _fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def link_mixed(inb: dict[str, Any], host: str, user: dict[str, str], mixed_http: bool) -> list[str]:
    name = user["username"]
    auth = f"{_q(name)}:{_q(user['password'])}@{host}:{inb['listen_port']}"
    links = [f"socks5://{auth}#{_q(name + '-mixed-socks5')}"]
    if mixed_http:
        links.append(f"http://{auth}#{_q(name + '-mixed-http')}")
    return links


def link_shadowsocks(inb: dict[str, Any], host: str, user: dict[str, str], _: bool) -> list[str]:
    method = inb["method"]
    if method.startswith("2022-"):
        raise SystemExit("links for 2022 methods are not supported")
    userinfo = base64.urlsafe_b64encode(f"{method}:{user['password']}".encode())
    return [
        f"ss://{userinfo.decode().rstrip('=')}@{host}:{inb['listen_port']}"
        f"#{_q(user['name'] + '-ss')}"
    ]


def link_vless(inb: dict[str, Any], host: str, user: dict[str, str], insecure: bool) -> list[str]:
    tls = inb["tls"]
    params = [
        ("encryption", "none"),
        ("security", "tls"),
        ("sni", tls["server_name"]),
        ("alpn", ",".join(tls["alpn"])),
        ("type", "tcp"),
    ]
    if insecure:
        params.append(("allowInsecure", "1"))
    return [
        f"vless://{user['uuid']}@{host}:{inb['listen_port']}"
        f"?{urlencode(params, quote_via=quote)}#{_q(user['name'] + '-vless')}"
    ]


def link_hysteria2(inb: dict[str, Any], host: str, user: dict[str, str], insecure: bool) -> list[str]:
    tls = inb["tls"]
    params = [("sni", tls["server_name"]), ("alpn", ",".join(tls["alpn"]))]
    if insecure:
        params.append(("insecure", "1"))
    return [
        f"hysteria2://{_q(user['password'])}@{host}:{inb['listen_port']}/"
        f"?{urlencode(params, quote_via=quote)}#{_q(user['name'] + '-hy2')}"
    ]


LINK_BUILDERS: dict[str, Callable[[dict[str, Any], str, dict[str, str], bool], list[str]]] = {
    "mixed": link_mixed,
    "shadowsocks": link_shadowsocks,
    "vless": link_vless,
    "hysteria2": link_hysteria2,
}

# for each inbound type: which link flag it consumes ("mixed_http" or "insecure")
LINK_FLAG: dict[str, str] = {
    "mixed": "mixed_http",
    "shadowsocks": "insecure",  # unused, but keep mapping total
    "vless": "insecure",
    "hysteria2": "insecure",
}


def build_accounts(direct: bool, tor_path: Path, ss_path: Path) -> list[tuple[str, str]]:
    accounts = [("direct", "direct")] if direct else []
    for prefix, path in (("tor", tor_path), ("ss", ss_path)):
        accounts += [(f"{prefix}{n+1}", tag) for n, tag in enumerate(read_tags(path))]
    return accounts


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("host", nargs="?", default="0.0.0.0",
                   help="server IP or domain (SERVER_HOST)")
    p.add_argument("--direct", dest="direct", action="store_true", default=False,
                   help="add a 'direct' account")
    p.add_argument("--no-direct", dest="direct", action="store_false",
                   help="do not add a 'direct' account")
    p.add_argument("--insecure", dest="insecure", action="store_true", default=True,
                   help="emit allowInsecure/insecure flags in links")
    p.add_argument("--secure", dest="insecure", action="store_false",
                   help="omit allowInsecure/insecure flags in links")
    p.add_argument("--mixed-http-link", dest="mixed_http", action="store_true", default=False,
                   help="also emit http:// links for mixed inbound")
    p.add_argument("--super-selector-tags", type=Path,
                   default=Path("super-selector-tags.txt"),
                   help="tags file for super-selector outbound")
    p.add_argument("--tor-tags", type=Path, default=Path("tor-tags.txt"),
                   help="tags file for tor outbound")
    p.add_argument("--output", type=Path, default=Path("config.json"),
                   help="server config output path")
    p.add_argument("--links", type=Path, default=Path("links.txt"),
                   help="client links output path")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(message)s")

    host = args.host.strip()
    if not host:
        raise SystemExit("server host is required (argument)")
    host = _fmt_host(host)

    accounts = build_accounts(args.direct, args.tor_tags, args.super_selector_tags)
    if not accounts:
        raise SystemExit("no users: inbounds without users would be open")

    template = make_template()
    inbounds = make_inbounds(DEFAULT_INBOUND_PORTS)

    flag_values = {"mixed_http": args.mixed_http, "insecure": args.insecure}

    links: list[str] = []
    for name, outbound in accounts:
        for inbound_type, inb in inbounds.items():
            user = new_user(inbound_type, name)
            inb["users"].append(user)
            builder = LINK_BUILDERS[inbound_type]
            links += builder(inb, host, user, flag_values[LINK_FLAG[inbound_type]])
        add_route(template, inbounds, name, outbound)

    template["inbounds"] = list(inbounds.values())

    args.output.write_text(
        json.dumps(template, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    args.links.write_text("\n".join(links) + "\n", encoding="utf-8")
    log.info("%s: %d users, %s: %d links", args.output, len(accounts), args.links, len(links))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
