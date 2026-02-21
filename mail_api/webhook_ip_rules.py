from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from .db import get_conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_rule(*, webhook_id: int, action: str, cidr: str) -> None:
    action_norm = action.strip().lower()
    if action_norm not in {"allow", "deny"}:
        raise ValueError("invalid action")

    net = ipaddress.ip_network(cidr, strict=False)
    with get_conn() as conn:
        conn.execute(
            (
                "insert into webhook_ip_rules("
                "webhook_id, action, cidr, created_at"
                ") "
                "values(?, ?, ?, ?)"
            ),
            (int(webhook_id), action_norm, str(net), _now_iso()),
        )
        conn.commit()


def delete_rule(*, rule_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "delete from webhook_ip_rules where id = ?",
            (int(rule_id),),
        )
        conn.commit()


def list_rules(*, webhook_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "select id, action, cidr, created_at "
            "from webhook_ip_rules where webhook_id = ? "
            "order by id asc",
            (int(webhook_id),),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "action": str(r["action"]),
                "cidr": str(r["cidr"]),
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]


def has_any_rules(*, webhook_id: int) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "select count(*) as c from webhook_ip_rules where webhook_id = ?",
            (int(webhook_id),),
        ).fetchone()
        return int(row["c"]) > 0


def is_ip_allowed(ip: str, rules: list[dict]) -> bool:
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
