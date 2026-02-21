from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Iterable

from .db import get_conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_default_rules() -> None:
    with get_conn() as conn:
        count = conn.execute("select count(*) as c from ip_rules").fetchone()["c"]
        if int(count) > 0:
            return
        conn.execute(
            "insert into ip_rules(action, cidr, created_at) values(?, ?, ?)",
            ("allow", "192.168.250.0/24", _now_iso()),
        )
        conn.commit()


def add_rule(action: str, cidr: str) -> None:
    action = action.strip().lower()
    if action not in {"allow", "deny"}:
        raise ValueError("invalid action")

    net = ipaddress.ip_network(cidr, strict=False)
    with get_conn() as conn:
        conn.execute(
            "insert into ip_rules(action, cidr, created_at) values(?, ?, ?)",
            (action, str(net), _now_iso()),
        )
        conn.commit()


def delete_rule(rule_id: int) -> None:
    with get_conn() as conn:
        conn.execute("delete from ip_rules where id = ?", (rule_id,))
        conn.commit()


def list_rules() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("select id, action, cidr, created_at from ip_rules order by id asc").fetchall()
        return [
            {
                "id": int(r["id"]),
                "action": str(r["action"]),
                "cidr": str(r["cidr"]),
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]


def is_ip_allowed(ip: str, rules: Iterable[dict]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    deny_nets = []
    allow_nets = []

    for r in rules:
        try:
            net = ipaddress.ip_network(str(r["cidr"]), strict=False)
        except ValueError:
            continue
        if str(r.get("action", "")).lower() == "deny":
            deny_nets.append(net)
        elif str(r.get("action", "")).lower() == "allow":
            allow_nets.append(net)

    for net in deny_nets:
        if addr in net:
            return False

    for net in allow_nets:
        if addr in net:
            return True

    return False
