from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from fastapi import Request

from .settings import get_setting


def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
    parts = []
    for chunk in raw.replace(",", "\n").splitlines():
        s = chunk.strip()
        if not s:
            continue
        parts.append(s)

    nets: list[ipaddress._BaseNetwork] = []
    for p in parts:
        try:
            nets.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue
    return nets


def get_trusted_proxy_networks() -> list[ipaddress._BaseNetwork]:
    raw = get_setting("trusted_proxy_cidrs").strip()
    if not raw:
        return []
    return _parse_cidrs(raw)


def is_trusted_proxy_peer(request: Request) -> bool:
    peer_ip = request.client.host if request.client else ""
    if not peer_ip:
        return False
    trusted = get_trusted_proxy_networks()
    if not trusted:
        return False
    return _ip_in_any(peer_ip, trusted)


def _ip_in_any(ip: str, nets: Iterable[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        if addr in n:
            return True
    return False


def _first_non_trusted(
    chain: list[str],
    trusted_nets: list[ipaddress._BaseNetwork],
) -> Optional[str]:
    for ip in reversed(chain):
        if not _ip_in_any(ip, trusted_nets):
            return ip
    return None


def get_real_client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else ""
    if not peer_ip:
        return ""

    trusted = get_trusted_proxy_networks()
    if not trusted:
        return peer_ip

    if not _ip_in_any(peer_ip, trusted):
        return peer_ip

    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer_ip

    forwarded = [p.strip() for p in xff.split(",") if p.strip()]
    chain = forwarded + [peer_ip]

    chosen = _first_non_trusted(chain, trusted)
    if chosen:
        return chosen

    return forwarded[0] if forwarded else peer_ip
