#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any


ENV_FILE = "/etc/translife-haproxy.env"
STATE_DIR = "/var/lib/translife-haproxy"
STATE_JSON = os.path.join(STATE_DIR, "hosts.json")
GEN_CFG = "/etc/haproxy/translife-backends.cfg"
HAPROXY_RELOAD_CMD = ["/bin/systemctl", "reload", "haproxy"]
HAPROXY_RESTART_CMD = ["/bin/systemctl", "restart", "haproxy"]


@dataclass(frozen=True)
class HostResult:
    ip: str
    ok: bool
    connect_ok: bool
    http_ok: bool
    status_code: int | None
    latency_ms: int | None
    error: str


def _load_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                k, v = raw.split("=", 1)
                env[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return env


def _tcp_connect_ok(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _http_health(ip: str, port: int, path: str, timeout: float) -> tuple[bool, int | None, int | None, str]:
    url = f"http://{ip}:{port}{path}"
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = int(getattr(r, "status", 0) or 0)
            latency_ms = int((time.time() - t0) * 1000)
            return (200 <= code < 300), code, latency_ms, ""
    except Exception as e:
        latency_ms = int((time.time() - t0) * 1000)
        return False, None, latency_ms, str(e)


def _scan_one(ip: str, *, port: int, health_path: str, timeout: float) -> HostResult:
    connect_ok = _tcp_connect_ok(ip, port, timeout)
    if not connect_ok:
        return HostResult(
            ip=ip,
            ok=False,
            connect_ok=False,
            http_ok=False,
            status_code=None,
            latency_ms=None,
            error="tcp connect failed",
        )

    http_ok, code, latency_ms, err = _http_health(ip, port, health_path, timeout)
    ok = bool(http_ok)
    return HostResult(
        ip=ip,
        ok=ok,
        connect_ok=True,
        http_ok=http_ok,
        status_code=code,
        latency_ms=latency_ms,
        error=err,
    )


def _write_state(results: list[HostResult]) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    payload: dict[str, Any] = {
        "updated_at": time.time(),
        "hosts": [
            {
                "ip": r.ip,
                "ok": r.ok,
                "connect_ok": r.connect_ok,
                "http_ok": r.http_ok,
                "status_code": r.status_code,
                "latency_ms": r.latency_ms,
                "error": r.error,
            }
            for r in results
        ],
    }
    tmp = STATE_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_JSON)


def _generate_haproxy_cfg(
    *,
    bind_ip: str,
    frontend_ports: list[int],
    backend_port: int,
    backend_hosts: list[str],
    health_path: str,
    stats_bind: str,
    stats_port: int,
    stats_user: str,
    stats_pass: str,
) -> str:
    # One backend used for all frontends (ports) for simplicity.
    # HAProxy will still do per-server health checks.
    lines: list[str] = []

    # Stats frontend (local by default)
    lines.append("frontend fe_haproxy_stats")
    lines.append(f"    bind {stats_bind}:{stats_port}")
    lines.append("    stats enable")
    lines.append("    stats uri /stats")
    lines.append(f"    stats auth {stats_user}:{stats_pass}")
    lines.append("")

    for p in frontend_ports:
        lines.append(f"frontend fe_translife_{p}")
        lines.append(f"    bind {bind_ip}:{p}")
        lines.append(f"    default_backend be_translife_{p}")
        lines.append("")

        lines.append(f"backend be_translife_{p}")
        lines.append("    balance roundrobin")
        lines.append("    option httpchk")
        lines.append(f"    http-check send meth GET uri {health_path}")
        lines.append("    http-check expect status 200")
        lines.append("    default-server inter 2s fall 3 rise 2")

        if not backend_hosts:
            lines.append(
                "    http-request return status 503 content-type text/plain "
                'lf-string "no backends discovered"'
            )
        else:
            for i, ip in enumerate(backend_hosts, start=1):
                lines.append(
                    f"    server n{i} {ip}:{backend_port} check"
                )
        lines.append("")

    return "\n".join(lines) + "\n"


def _reload_haproxy() -> None:
    p = subprocess.run(HAPROXY_RELOAD_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if p.returncode == 0:
        return
    subprocess.run(HAPROXY_RESTART_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="run one scan + update, then exit")
    args = ap.parse_args()

    env = _load_env(ENV_FILE)

    bind_ip = env.get("TRANS_BIND_IP", "192.168.250.201").strip() or "192.168.250.201"
    backend_net = env.get("TRANS_BACKEND_NET", "10.0.50.0/24").strip() or "10.0.50.0/24"
    backend_port = int(env.get("TRANS_BACKEND_PORT", "2555").strip() or "2555")

    frontend_ports_raw = env.get("TRANS_FRONTEND_PORTS", "2555").strip() or "2555"
    frontend_ports = [int(p.strip()) for p in frontend_ports_raw.split(",") if p.strip()]

    health_path = env.get("TRANS_HEALTH_PATH", "/healthz").strip() or "/healthz"
    timeout = float(env.get("TRANS_SCAN_TIMEOUT_SECONDS", "1.0").strip() or "1.0")
    concurrency = int(env.get("TRANS_SCAN_CONCURRENCY", "128").strip() or "128")
    interval = float(env.get("TRANS_SCAN_INTERVAL_SECONDS", "20").strip() or "20")

    stats_bind = env.get("TRANS_STATS_BIND", "127.0.0.1").strip() or "127.0.0.1"
    stats_port = int(env.get("TRANS_STATS_PORT", "8404").strip() or "8404")
    stats_user = env.get("TRANS_STATS_USER", "admin").strip() or "admin"
    stats_pass = env.get("TRANS_STATS_PASS", "change-me").strip() or "change-me"

    try:
        net = ipaddress.ip_network(backend_net, strict=False)
    except Exception:
        print("invalid TRANS_BACKEND_NET", file=sys.stderr)
        return 2

    def _iter_hosts() -> list[str]:
        # User requirement: .1 through .254
        ips: list[str] = []
        for ip in net.hosts():
            s = str(ip)
            last = int(s.split(".")[-1])
            if 1 <= last <= 254:
                ips.append(s)
        return ips

    while True:
        ips = _iter_hosts()
        results: list[HostResult] = []

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(_scan_one, ip, port=backend_port, health_path=health_path, timeout=timeout) for ip in ips]
            for fut in as_completed(futs):
                results.append(fut.result())

        results.sort(key=lambda r: r.ip)
        ok_hosts = [r.ip for r in results if r.ok]

        _write_state(results)

        cfg = _generate_haproxy_cfg(
            bind_ip=bind_ip,
            frontend_ports=frontend_ports,
            backend_port=backend_port,
            backend_hosts=ok_hosts,
            health_path=health_path,
            stats_bind=stats_bind,
            stats_port=stats_port,
            stats_user=stats_user,
            stats_pass=stats_pass,
        )

        tmp = GEN_CFG + ".tmp"
        os.makedirs(os.path.dirname(GEN_CFG), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(cfg)
        os.replace(tmp, GEN_CFG)

        _reload_haproxy()

        if args.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
