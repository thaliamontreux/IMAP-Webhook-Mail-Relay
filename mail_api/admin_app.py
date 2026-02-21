from __future__ import annotations

from datetime import datetime, timezone
import io
import os
import secrets
import sqlite3
import time
from typing import Any, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from .db import get_conn
from .ip_rules import (
    add_rule,
    delete_rule,
    ensure_default_rules,
    is_ip_allowed,
    list_rules,
)
from .security import (
    get_csrf_serializer,
    get_session_serializer,
    hash_password,
    verify_password,
)
from .settings import DEFAULTS, get_setting, set_setting
from .client_ip import get_real_client_ip, is_trusted_proxy_peer
from .delivery_log import iter_recent_lines, append_log_line
from .emailer import build_message
from .smtp_delivery import send_via_smtp
from .rate_limit import SqliteFixedWindowRateLimiter
from .totp import build_provisioning_uri, generate_base32_secret, verify_totp
from .webhooks import (
    create_webhook,
    ensure_default_webhook,
    get_webhook_by_id,
    list_webhooks,
    update_webhook,
    update_webhook_smtp,
    update_webhook_imap,
    update_webhook_pop3,
    update_webhook_relay_scenario,
)
from .webhook_ip_rules import (
    add_rule as add_webhook_ip_rule,
    delete_rule as delete_webhook_ip_rule,
    list_rules as list_webhook_ip_rules,
)

try:
    import segno  # type: ignore
except Exception:
    segno = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(actor: str, action: str, details: str) -> None:
    with get_conn() as conn:
        conn.execute(
            (
                "insert into audit_log(actor, action, details, created_at) "
                "values(?, ?, ?, ?)"
            ),
            (actor, action, details, _now_iso()),
        )
        conn.commit()


def _recovery_code_hash(*, username: str, code: str) -> str:
    # Store a non-reversible hash for recovery codes.
    # We use bcrypt for passwords, but recovery codes are intended to be fast
    # to check and are already high-entropy.
    from hashlib import sha256

    u = (username or "").strip().lower()
    c = (code or "").strip().replace("-", "").replace(" ", "").upper()
    return sha256(f"{u}:{c}".encode("utf-8")).hexdigest()


def _delete_all_recovery_codes(username: str) -> None:
    u = (username or "").strip()
    with get_conn() as conn:
        conn.execute(
            "delete from admin_recovery_codes where username = ?",
            (u,),
        )
        conn.commit()


def _count_unused_recovery_codes(username: str) -> int:
    u = (username or "").strip()
    with get_conn() as conn:
        row = conn.execute(
            (
                "select count(*) as c from admin_recovery_codes "
                "where username = ? and used_at is null"
            ),
            (u,),
        ).fetchone()
        return int(row["c"])


def _create_recovery_codes(*, username: str, count: int = 10) -> list[str]:
    # Human-friendly codes (no O/0, I/1) in 3 groups.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    u = (username or "").strip()
    codes: list[str] = []
    for _ in range(max(1, int(count))):
        raw = "".join(secrets.choice(alphabet) for __ in range(12))
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")

    with get_conn() as conn:
        conn.execute(
            "delete from admin_recovery_codes where username = ?",
            (u,),
        )
        for c in codes:
            conn.execute(
                (
                    "insert into admin_recovery_codes("
                    "username, code_hash, created_at, used_at"
                    ") values(?, ?, ?, null)"
                ),
                (u, _recovery_code_hash(username=u, code=c), _now_iso()),
            )
        conn.commit()

    return codes


def _consume_recovery_code(*, username: str, code: str) -> bool:
    u = (username or "").strip()
    h = _recovery_code_hash(username=u, code=code)
    now = _now_iso()
    with get_conn() as conn:
        row = conn.execute(
            (
                "select id from admin_recovery_codes "
                "where username = ? and code_hash = ? and used_at is null"
            ),
            (u, h),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "update admin_recovery_codes set used_at = ? where id = ?",
            (now, int(row["id"])),
        )
        conn.commit()
        return True


def _get_client_ip(request: Request) -> str:
    return get_real_client_ip(request)


def _require_ip_allowed(request: Request) -> None:
    rules = list_rules()
    if not is_ip_allowed(_get_client_ip(request), rules):
        raise HTTPException(status_code=403, detail="forbidden")


def _get_forwarded_prefix(request: Request) -> str:
    if not is_trusted_proxy_peer(request):
        return ""
    raw = (request.headers.get("x-forwarded-prefix") or "").strip()
    if not raw:
        return ""
    if not raw.startswith("/"):
        return ""
    if raw == "/":
        return ""
    return raw.rstrip("/")


def _prefixed(request: Request, path: str) -> str:
    prefix = _get_forwarded_prefix(request)
    if not path.startswith("/"):
        path = "/" + path
    return prefix + path


def _get_current_user(request: Request) -> Optional[str]:
    cookie = request.cookies.get("mail_api_session")
    if not cookie:
        return None
    s = get_session_serializer()
    try:
        data = s.loads(cookie)
    except (ValueError, TypeError):
        return None
    username = str(data.get("u", "")).strip()
    if not username:
        return None
    return username


def _require_login(request: Request) -> str:
    u = _get_current_user(request)
    if not u:
        raise HTTPException(
            status_code=302,
            headers={"Location": _prefixed(request, "/login")},
        )
    return u


def _has_any_admin() -> bool:
    with get_conn() as conn:
        row = conn.execute("select count(*) as c from admin_users").fetchone()
        return int(row["c"]) > 0


def _create_admin(username: str, password: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "insert into admin_users("
            "username, password_hash, is_active, created_at"
            ") values(?, ?, 1, ?)",
            (username, hash_password(password), _now_iso()),
        )
        conn.commit()


def _set_admin_active(username: str, active: bool) -> None:
    with get_conn() as conn:
        conn.execute(
            "update admin_users set is_active = ? where username = ?",
            (1 if active else 0, username),
        )
        conn.commit()


def _list_admins() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "select username, is_active, created_at "
            "from admin_users "
            "order by username asc"
        ).fetchall()
        return [
            {
                "username": str(r["username"]),
                "is_active": int(r["is_active"]) == 1,
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]


def _get_admin_totp(username: str) -> tuple[bool, str]:
    u = (username or "").strip()
    if not u:
        return (False, "")
    with get_conn() as conn:
        row = conn.execute(
            "select totp_enabled, totp_secret from admin_users where username = ?",
            (u,),
        ).fetchone()
        if row is None:
            return (False, "")
        return (int(row["totp_enabled"]) == 1, str(row["totp_secret"] or ""))


def _set_admin_totp_secret(username: str, secret: str) -> None:
    u = (username or "").strip()
    s = (secret or "").strip()
    with get_conn() as conn:
        conn.execute(
            "update admin_users set totp_secret = ?, totp_enabled = 0 where username = ?",
            (s, u),
        )
        conn.commit()


def _enable_admin_totp(username: str) -> None:
    u = (username or "").strip()
    with get_conn() as conn:
        conn.execute(
            "update admin_users set totp_enabled = 1 where username = ?",
            (u,),
        )
        conn.commit()


def _disable_admin_totp(username: str) -> None:
    u = (username or "").strip()
    with get_conn() as conn:
        conn.execute(
            "update admin_users set totp_enabled = 0, totp_secret = '' where username = ?",
            (u,),
        )
        conn.commit()


def _authenticate(username: str, password: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            (
                "select password_hash, is_active "
                "from admin_users where username = ?"
            ),
            (username,),
        ).fetchone()
        if row is None:
            return False
        if int(row["is_active"]) != 1:
            return False
        return verify_password(password, str(row["password_hash"]))


def create_admin_app() -> FastAPI:
    ensure_default_rules()
    ensure_default_webhook()
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    templates = Jinja2Templates(directory=templates_dir)

    app = FastAPI(title="MAIL_API Control Panel")

    limiter = SqliteFixedWindowRateLimiter(
        scope="admin",
        max_requests=240,
        window_seconds=60,
    )

    def _csrf_token_for_request(request: Request) -> str:
        s = get_csrf_serializer()
        ip = _get_client_ip(request)
        u = _get_current_user(request)
        if u:
            return s.dumps({"ip": ip, "u": u})
        return s.dumps({"ip": ip})

    def _is_csrf_valid(request: Request, token: str) -> bool:
        token = (token or "").strip()
        if not token:
            return False

        s = get_csrf_serializer()
        try:
            data = s.loads(token)
        except (ValueError, TypeError):
            return False

        ip = _get_client_ip(request)
        if str(data.get("ip", "")).strip() != ip:
            return False

        u = _get_current_user(request)
        if u:
            return str(data.get("u", "")).strip() == u

        return "u" not in data

    def _login_is_allowed(*, ip: str, username: str) -> tuple[bool, int]:
        key_ip = ip.strip()
        key_user = username.strip().lower()
        if not key_ip or not key_user:
            return (True, 0)

        now = time.time()
        with get_conn() as conn:
            row = conn.execute(
                (
                    "select attempts, until_monotonic "
                    "from login_failures where ip = ? and username = ?"
                ),
                (key_ip, key_user),
            ).fetchone()
            if row is None:
                return (True, 0)
            until = float(row["until_monotonic"])
            if now >= until:
                return (True, 0)
            return (False, int(max(1.0, until - now)))

    def _record_login_failure(*, ip: str, username: str) -> None:
        key_ip = ip.strip()
        key_user = username.strip().lower()
        if not key_ip or not key_user:
            return

        now = time.time()
        with get_conn() as conn:
            row = conn.execute(
                (
                    "select attempts from login_failures "
                    "where ip = ? and username = ?"
                ),
                (key_ip, key_user),
            ).fetchone()
            attempts = int(row["attempts"]) if row is not None else 0
            attempts += 1
            backoff = min(300.0, float(2 ** min(attempts, 8)))
            until = now + backoff
            conn.execute(
                (
                    "insert into login_failures(" 
                    "ip, username, attempts, until_monotonic" 
                    ") values(?, ?, ?, ?) "
                    "on conflict(ip, username) do update set "
                    "attempts = excluded.attempts, "
                    "until_monotonic = excluded.until_monotonic"
                ),
                (key_ip, key_user, attempts, until),
            )
            conn.commit()

    def _clear_login_failures(*, ip: str, username: str) -> None:
        key_ip = ip.strip()
        key_user = username.strip().lower()
        if not key_ip or not key_user:
            return

        with get_conn() as conn:
            conn.execute(
                "delete from login_failures where ip = ? and username = ?",
                (key_ip, key_user),
            )
            conn.commit()

    @app.middleware("http")
    async def _security_middleware(request: Request, call_next):
        request.state.csrf_token = _csrf_token_for_request(request)

        ip = _get_client_ip(request)
        r = limiter.check(key=ip)
        if not r.ok:
            return PlainTextResponse(
                content="rate limited",
                status_code=429,
                headers={"Retry-After": str(r.retry_after_seconds)},
            )

        if request.method.upper() == "POST":
            form: Any = {}
            try:
                form = await request.form()
            except Exception:
                pass
            token = str(form.get("csrf_token", ""))
            if not _is_csrf_valid(request, token):
                return PlainTextResponse(
                    content="invalid csrf token",
                    status_code=403,
                )

        return await call_next(request)

    @app.get("/healthz")
    async def healthz(request: Request):
        _require_ip_allowed(request)
        try:
            with get_conn() as conn:
                conn.execute("select 1").fetchone()
        except Exception:
            raise HTTPException(status_code=503, detail="db unavailable")
        return {"ok": True}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics(request: Request):
        _require_ip_allowed(request)

        lines: list[str] = [
            "# TYPE mail_api_admin_up gauge",
            "mail_api_admin_up 1",
        ]

        try:
            with get_conn() as conn:
                conn.execute("select 1").fetchone()
            lines.append("mail_api_admin_db_up 1")
        except Exception:
            lines.append("mail_api_admin_db_up 0")
            return "\n".join(lines) + "\n"

        with get_conn() as conn:
            rows = conn.execute(
                "select status, count(*) as c from outbound_queue group by status"
            ).fetchall()
            for r in rows:
                st = str(r["status"])
                c = int(r["c"])
                lines.append(
                    f"mail_api_outbound_queue_total{{status=\"{st}\"}} {c}"
                )

        return "\n".join(lines) + "\n"

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.get("/webhooks", response_class=HTMLResponse)
    async def webhooks_list(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        return templates.TemplateResponse(
            "webhooks.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhooks": list_webhooks(),
            },
        )

    @app.post("/webhooks/create")
    async def webhooks_create(request: Request, name: str = Form("")):
        _require_ip_allowed(request)
        u = _require_login(request)
        webhook_id = create_webhook(name=name)
        _audit(u, "create_webhook", f"id={webhook_id}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}"),
            status_code=302,
        )

    @app.get("/webhooks/{webhook_id}", response_class=HTMLResponse)
    async def webhooks_get(request: Request, webhook_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        return templates.TemplateResponse(
            "webhook_edit.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
            },
        )

    @app.post("/webhooks/{webhook_id}")
    async def webhooks_post(
        request: Request,
        webhook_id: int,
        name: str = Form(""),
        is_active: str = Form(""),
        sender_email: str = Form(""),
        webhook_secret: str = Form(""),
        timestamp_skew_seconds: str = Form("300"),
        allow_from_override: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")

        truthy = {"1", "true", "on", "yes"}
        active = is_active.strip().lower() in truthy
        allow_override = allow_from_override.strip().lower() in truthy
        try:
            skew = int(timestamp_skew_seconds.strip() or "300")
        except ValueError:
            skew = 300

        update_webhook(
            webhook_id=webhook_id,
            name=name,
            is_active=active,
            sender_email=sender_email,
            webhook_secret=webhook_secret,
            timestamp_skew_seconds=skew,
            allow_from_override=allow_override,
        )
        _audit(u, "update_webhook", f"id={webhook_id}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}"),
            status_code=302,
        )

    def _webhook_smtp_preset(port: int) -> tuple[str, str]:
        if port == 25:
            return ("Port 25 (Plain)", "plain")
        if port == 465:
            return ("Port 465 (SSL)", "ssl")
        return ("Port 587 (STARTTLS)", "starttls")

    @app.get("/webhooks/{webhook_id}/smtp")
    async def webhook_smtp_root(request: Request, webhook_id: int):
        _require_ip_allowed(request)
        _require_login(request)
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/smtp/587"),
            status_code=302,
        )

    @app.get("/webhooks/{webhook_id}/smtp/{port}", response_class=HTMLResponse)
    async def webhook_smtp_get(request: Request, webhook_id: int, port: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        if port not in {25, 465, 587}:
            raise HTTPException(
                status_code=404,
                detail="not found",
            )
        preset_label, _ = _webhook_smtp_preset(port)
        return templates.TemplateResponse(
            "webhook_smtp.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
                "preset_port": port,
                "preset_label": preset_label,
            },
        )

    @app.post("/webhooks/{webhook_id}/smtp/{port}")
    async def webhook_smtp_post(
        request: Request,
        webhook_id: int,
        port: int,
        smtp_host: str = Form(""),
        smtp_username: str = Form(""),
        smtp_password: str = Form(""),
        smtp_ignore_certificates: str = Form(""),
        smtp_sender_name: str = Form(""),
        smtp_envelope_from_override: str = Form(""),
        smtp_timeout_seconds: str = Form("15"),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        if port not in {25, 465, 587}:
            raise HTTPException(status_code=404, detail="not found")

        _, security = _webhook_smtp_preset(port)
        truthy = {"1", "true", "on", "yes"}
        ignore_value = (
            "1" if smtp_ignore_certificates.strip().lower() in truthy else "0"
        )

        update_webhook_smtp(
            webhook_id=webhook_id,
            smtp_host=smtp_host,
            smtp_port=str(port),
            smtp_security=security,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            smtp_timeout_seconds=smtp_timeout_seconds,
            smtp_ignore_certificates=ignore_value,
            smtp_sender_name=smtp_sender_name,
            smtp_envelope_from_override=smtp_envelope_from_override,
        )
        _audit(u, "update_webhook_smtp", f"id={webhook_id};port={port}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/smtp/{port}"),
            status_code=302,
        )

    @app.post(
        "/webhooks/{webhook_id}/smtp/{port}/test",
        response_class=HTMLResponse,
    )
    async def webhook_smtp_test(
        request: Request,
        webhook_id: int,
        port: int,
        test_to: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(
                status_code=404,
                detail="not found",
            )
        if port not in {25, 465, 587}:
            raise HTTPException(status_code=404, detail="not found")
        if not test_to.strip() or "@" not in test_to:
            raise HTTPException(
                status_code=400,
                detail="invalid test recipient",
            )

        preset_label, security = _webhook_smtp_preset(port)

        from_addr = (wh.sender_email or "").strip()
        if not from_addr or "@" not in from_addr:
            raise HTTPException(
                status_code=503,
                detail="sender email not configured",
            )

        envelope_from = from_addr
        if wh.smtp_envelope_from_override.strip():
            envelope_from = wh.smtp_envelope_from_override.strip()

        sender_name = wh.smtp_sender_name.strip() or None
        msg = build_message(
            from_addr=from_addr,
            to_addr=test_to.strip(),
            subject="MAIL_API Webhook SMTP Test",
            body_text="This is a test message from MAIL_API.\n",
            from_name=sender_name,
        )

        ok = False
        err = ""
        try:
            send_via_smtp(
                envelope_from=envelope_from,
                to_addr=test_to.strip(),
                message_bytes=msg,
                smtp_settings={
                    "smtp_host": wh.smtp_host,
                    "smtp_port": str(port),
                    "smtp_security": security,
                    "smtp_username": wh.smtp_username,
                    "smtp_password": wh.smtp_password,
                    "smtp_timeout_seconds": wh.smtp_timeout_seconds,
                    "smtp_ignore_certificates": wh.smtp_ignore_certificates,
                },
            )
            ok = True
        except Exception as e:
            err = str(e)

        if ok:
            append_log_line(
                f"TEST OK wh={webhook_id} to={test_to.strip()} "
                f"port={port} sec={security}"
            )
            _audit(
                u,
                "webhook_smtp_test",
                f"ok id={webhook_id} to={test_to.strip()} port={port}",
            )
            result = "SMTP test succeeded"
        else:
            msg = (
                f"TEST FAIL wh={webhook_id} to={test_to.strip()} "
                f"port={port} sec={security} err={err}"
            )
            append_log_line(msg)
            _audit(
                u,
                "webhook_smtp_test",
                (
                    f"fail id={webhook_id} to={test_to.strip()} "
                    f"port={port} err={err}"
                ),
            )
            result = f"SMTP test failed: {err}"

        wh = get_webhook_by_id(webhook_id)
        return templates.TemplateResponse(
            "webhook_smtp.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
                "preset_port": port,
                "preset_label": preset_label,
                "test_result": result,
            },
        )

    @app.get("/webhooks/{webhook_id}/protocols", response_class=HTMLResponse)
    async def webhook_protocols_get(request: Request, webhook_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        return templates.TemplateResponse(
            "webhook_protocols.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
            },
        )

    @app.post("/webhooks/{webhook_id}/protocols")
    async def webhook_protocols_post(
        request: Request,
        webhook_id: int,
        relay_scenario: str = Form("smtp"),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        update_webhook_relay_scenario(
            webhook_id=webhook_id,
            relay_scenario=relay_scenario,
        )
        _audit(
            u,
            "update_webhook_protocols",
            f"id={webhook_id};sc={relay_scenario}",
        )
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/protocols"),
            status_code=302,
        )

    @app.post("/webhooks/{webhook_id}/imap")
    async def webhook_imap_post(
        request: Request,
        webhook_id: int,
        imap_host: str = Form(""),
        imap_port: str = Form("993"),
        imap_security: str = Form("ssl"),
        imap_username: str = Form(""),
        imap_password: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        update_webhook_imap(
            webhook_id=webhook_id,
            imap_host=imap_host,
            imap_port=imap_port,
            imap_security=imap_security,
            imap_username=imap_username,
            imap_password=imap_password,
        )
        _audit(u, "update_webhook_imap", f"id={webhook_id}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/protocols"),
            status_code=302,
        )

    @app.post("/webhooks/{webhook_id}/imap/test", response_class=HTMLResponse)
    async def webhook_imap_test(request: Request, webhook_id: int):
        import imaplib

        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")

        result = "IMAP test failed"
        try:
            port = int((wh.imap_port or "").strip() or "993")
        except ValueError:
            port = 993

        try:
            c: Any
            if (wh.imap_security or "ssl") == "ssl":
                c = imaplib.IMAP4_SSL(host=wh.imap_host, port=port)
            else:
                c = imaplib.IMAP4(host=wh.imap_host, port=port)
                if (wh.imap_security or "").strip().lower() == "starttls":
                    c.starttls()

            typ, _ = c.login(wh.imap_username, wh.imap_password)
            c.logout()
            result = f"IMAP test succeeded ({typ})"
        except Exception as e:
            result = f"IMAP test failed: {e}"

        wh = get_webhook_by_id(webhook_id)
        return templates.TemplateResponse(
            "webhook_protocols.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
                "test_result_imap": result,
            },
        )

    @app.post("/webhooks/{webhook_id}/pop3")
    async def webhook_pop3_post(
        request: Request,
        webhook_id: int,
        pop3_host: str = Form(""),
        pop3_port: str = Form("995"),
        pop3_security: str = Form("ssl"),
        pop3_username: str = Form(""),
        pop3_password: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        update_webhook_pop3(
            webhook_id=webhook_id,
            pop3_host=pop3_host,
            pop3_port=pop3_port,
            pop3_security=pop3_security,
            pop3_username=pop3_username,
            pop3_password=pop3_password,
        )
        _audit(u, "update_webhook_pop3", f"id={webhook_id}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/protocols"),
            status_code=302,
        )

    @app.post("/webhooks/{webhook_id}/pop3/test", response_class=HTMLResponse)
    async def webhook_pop3_test(request: Request, webhook_id: int):
        import poplib

        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")

        result = "POP3 test failed"
        try:
            port = int((wh.pop3_port or "").strip() or "995")
        except ValueError:
            port = 995

        try:
            c: Any
            if (wh.pop3_security or "ssl") == "ssl":
                c = poplib.POP3_SSL(
                    host=wh.pop3_host,
                    port=port,
                    timeout=10,
                )
            else:
                c = poplib.POP3(
                    host=wh.pop3_host,
                    port=port,
                    timeout=10,
                )
                if (wh.pop3_security or "").strip().lower() == "starttls":
                    c.stls()
            c.user(wh.pop3_username)
            c.pass_(wh.pop3_password)
            c.quit()
            result = "POP3 test succeeded"
        except Exception as e:
            result = f"POP3 test failed: {e}"

        wh = get_webhook_by_id(webhook_id)
        return templates.TemplateResponse(
            "webhook_protocols.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
                "test_result_pop3": result,
            },
        )

    @app.get("/webhooks/{webhook_id}/ip-rules", response_class=HTMLResponse)
    async def webhook_ip_rules_get(request: Request, webhook_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        return templates.TemplateResponse(
            "webhook_ip_rules.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "webhook": wh,
                "rules": list_webhook_ip_rules(webhook_id=webhook_id),
            },
        )

    @app.post("/webhooks/{webhook_id}/ip-rules/add")
    async def webhook_ip_rules_add(
        request: Request,
        webhook_id: int,
        action: str = Form("deny"),
        cidr: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        try:
            add_webhook_ip_rule(
                webhook_id=webhook_id,
                action=action,
                cidr=cidr,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        _audit(
            u,
            "add_webhook_ip_rule",
            f"id={webhook_id};{action};{cidr}",
        )
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/ip-rules"),
            status_code=302,
        )

    @app.post("/webhooks/{webhook_id}/ip-rules/delete")
    async def webhook_ip_rules_delete(
        request: Request,
        webhook_id: int,
        rule_id: int = Form(0),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        wh = get_webhook_by_id(webhook_id)
        if wh is None:
            raise HTTPException(status_code=404, detail="not found")
        delete_webhook_ip_rule(rule_id=int(rule_id))
        _audit(u, "delete_webhook_ip_rule", f"id={webhook_id};rule={rule_id}")
        return RedirectResponse(
            url=_prefixed(request, f"/webhooks/{webhook_id}/ip-rules"),
            status_code=302,
        )

    @app.get("/queue", response_class=HTMLResponse)
    async def queue_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        qp = request.query_params
        webhook_id_raw = (qp.get("webhook_id") or "").strip()
        status_raw = (qp.get("status") or "").strip()
        params: list[object] = []
        where = []
        if webhook_id_raw:
            try:
                wid = int(webhook_id_raw)
                where.append("q.webhook_id = ?")
                params.append(wid)
            except ValueError:
                pass
        if status_raw:
            where.append("q.status = ?")
            params.append(status_raw)

        where_sql = ""
        if where:
            where_sql = " where " + " and ".join(where)

        sql = (
            "select q.id, q.created_at, q.updated_at, q.status, "
            "q.webhook_id, q.to_addr, q.from_addr, q.subject, "
            "q.attempts, q.next_attempt_at, q.last_error "
            "from outbound_queue q" + where_sql + " "
            "order by q.next_attempt_at asc, q.id asc "
            "limit 200"
        )
        with get_conn() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        items = [dict(r) for r in rows]
        return templates.TemplateResponse(
            "queue.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "items": items,
                "filter_webhook_id": webhook_id_raw,
                "filter_status": status_raw,
            },
        )

    @app.get("/queue/{queue_id}", response_class=HTMLResponse)
    async def queue_detail(request: Request, queue_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        with get_conn() as conn:
            row = conn.execute(
                (
                    "select id, created_at, updated_at, status, webhook_id, "
                    "to_addr, from_addr, subject, body_text, attempts, "
                    "next_attempt_at, last_error "
                    "from outbound_queue where id = ?"
                ),
                (int(queue_id),),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        item = dict(row)
        return templates.TemplateResponse(
            "queue_detail.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "item": item,
            },
        )

    @app.post("/queue/{queue_id}/retry")
    async def queue_retry(request: Request, queue_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        now = _now_iso()
        with get_conn() as conn:
            conn.execute(
                (
                    "update outbound_queue "
                    "set status = 'pending', updated_at = ?, "
                    "next_attempt_at = ?, last_error = '' "
                    "where id = ?"
                ),
                (now, now, int(queue_id)),
            )
            conn.commit()
        _audit(u, "queue_retry", str(queue_id))
        return RedirectResponse(
            url=_prefixed(request, f"/queue/{queue_id}"),
            status_code=302,
        )

    @app.post("/queue/{queue_id}/delete")
    async def queue_delete(request: Request, queue_id: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        with get_conn() as conn:
            conn.execute(
                "delete from outbound_queue where id = ?",
                (int(queue_id),),
            )
            conn.commit()
        _audit(u, "queue_delete", str(queue_id))
        return RedirectResponse(
            url=_prefixed(request, "/queue"),
            status_code=302,
        )

    def _smtp_values() -> dict[str, str]:
        keys = [
            "smtp_host",
            "smtp_username",
            "smtp_timeout_seconds",
            "smtp_ignore_certificates",
            "smtp_sender_name",
        ]
        vals = {k: get_setting(k) for k in keys}
        defaults = {k: DEFAULTS.get(k, "") for k in keys}
        for k in keys:
            if not vals.get(k):
                vals[k] = defaults.get(k, "")
        return vals

    def _smtp_preset_info(port: int) -> tuple[str, str]:
        if port == 25:
            return ("Port 25 (Plain)", "plain")
        if port == 465:
            return ("Port 465 (SSL)", "ssl")
        return ("Port 587 (STARTTLS)", "starttls")

    @app.get("/smtp")
    async def smtp_root(request: Request):
        _require_ip_allowed(request)
        _require_login(request)
        return RedirectResponse(
            url=_prefixed(request, "/smtp/587"),
            status_code=302,
        )

    @app.get("/smtp/{port}", response_class=HTMLResponse)
    async def smtp_get(request: Request, port: int):
        _require_ip_allowed(request)
        u = _require_login(request)
        if port not in {25, 465, 587}:
            raise HTTPException(
                status_code=404,
                detail="not found",
            )
        preset_label, _ = _smtp_preset_info(port)
        return templates.TemplateResponse(
            "smtp.html",
            {
                "request": request,
                "user": u,
                "values": _smtp_values(),
                "preset_port": port,
                "preset_label": preset_label,
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.post("/smtp/{port}")
    async def smtp_post(
        request: Request,
        port: int,
        smtp_host: str = Form(""),
        smtp_username: str = Form(""),
        smtp_password: str = Form(""),
        smtp_ignore_certificates: str = Form(""),
        smtp_sender_name: str = Form(""),
        smtp_timeout_seconds: str = Form("15"),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        if port not in {25, 465, 587}:
            raise HTTPException(
                status_code=404,
                detail="not found",
            )

        _, security = _smtp_preset_info(port)
        set_setting("smtp_port", str(port))
        set_setting("smtp_security", security)
        set_setting("smtp_host", smtp_host.strip())
        set_setting("smtp_username", smtp_username.strip())
        set_setting(
            "smtp_timeout_seconds",
            smtp_timeout_seconds.strip() or "15",
        )
        truthy = {"1", "true", "on", "yes"}
        ignore_value = (
            "1"
            if smtp_ignore_certificates.strip().lower() in truthy
            else "0"
        )
        set_setting("smtp_ignore_certificates", ignore_value)
        set_setting("smtp_sender_name", smtp_sender_name.strip())
        if smtp_password.strip():
            set_setting("smtp_password", smtp_password)

        _audit(
            u,
            "update_smtp",
            f"port={port};security={security}",
        )
        return RedirectResponse(
            url=_prefixed(request, f"/smtp/{port}"),
            status_code=302,
        )

    @app.post("/smtp/{port}/test", response_class=HTMLResponse)
    async def smtp_test(
        request: Request,
        port: int,
        test_to: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        if port not in {25, 465, 587}:
            raise HTTPException(
                status_code=404,
                detail="not found",
            )
        if not test_to.strip() or "@" not in test_to:
            raise HTTPException(
                status_code=400,
                detail="invalid test recipient",
            )

        # Ensure preset is applied before testing.
        _, security = _smtp_preset_info(port)
        set_setting("smtp_port", str(port))
        set_setting("smtp_security", security)

        from_localpart_setting = get_setting("default_from_localpart").strip()
        from_localpart = from_localpart_setting or "no-reply"
        domain = get_setting("allowed_sender_domain").strip()
        if not domain:
            raise HTTPException(
                status_code=503,
                detail="allowed sender domain not configured",
            )
        from_addr = f"{from_localpart}@{domain}"

        sender_name = get_setting("smtp_sender_name").strip() or None
        msg = build_message(
            from_addr=from_addr,
            to_addr=test_to.strip(),
            subject="MAIL_API SMTP Test",
            body_text=(
                "This is a test message from MAIL_API.\n"
            ),
            from_name=sender_name,
        )

        ok = False
        err = ""
        try:
            send_via_smtp(
                envelope_from=from_addr,
                to_addr=test_to.strip(),
                message_bytes=msg,
            )
            ok = True
        except Exception as e:
            err = str(e)

        if ok:
            append_log_line(
                f"TEST OK to={test_to.strip()} port={port} sec={security}"
            )
            _audit(
                u,
                "smtp_test",
                f"ok to={test_to.strip()} port={port}",
            )
            result = "SMTP test succeeded"
        else:
            append_log_line(
                f"TEST FAIL to={test_to.strip()} port={port} sec={security} "
                f"err={err}"
            )
            _audit(
                u,
                "smtp_test",
                f"fail to={test_to.strip()} port={port} err={err}",
            )
            result = f"SMTP test failed: {err}"

        preset_label, _ = _smtp_preset_info(port)
        return templates.TemplateResponse(
            "smtp.html",
            {
                "request": request,
                "user": u,
                "values": _smtp_values(),
                "preset_port": port,
                "preset_label": preset_label,
                "prefix": _get_forwarded_prefix(request),
                "test_result": result,
            },
        )

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        lines = list(iter_recent_lines())
        return templates.TemplateResponse(
            "logs.html",
            {
                "request": request,
                "user": u,
                "lines": lines,
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.get("/2fa", response_class=HTMLResponse)
    async def totp_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        enabled, secret = _get_admin_totp(u)
        uri = ""
        if secret:
            uri = build_provisioning_uri(
                secret=secret,
                account=u,
                issuer="MAIL_API",
            )
        return templates.TemplateResponse(
            "totp.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "totp_enabled": enabled,
                "totp_secret": secret,
                "otpauth_uri": uri,
                "qr_available": segno is not None,
                "recovery_unused": _count_unused_recovery_codes(u),
            },
        )

    @app.get("/2fa/qr")
    async def totp_qr(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        _enabled, secret = _get_admin_totp(u)
        if not secret:
            raise HTTPException(status_code=404, detail="no totp secret")
        if segno is None:
            raise HTTPException(status_code=500, detail="qr not available")

        uri = build_provisioning_uri(
            secret=secret,
            account=u,
            issuer="MAIL_API",
        )
        qr = segno.make(uri)  # type: ignore[union-attr]
        buf = io.BytesIO()
        qr.save(buf, kind="svg", scale=6, border=2)  # type: ignore[union-attr]
        return Response(content=buf.getvalue(), media_type="image/svg+xml")

    @app.post("/2fa/generate")
    async def totp_generate(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        secret = generate_base32_secret()
        _set_admin_totp_secret(u, secret)
        _audit(u, "totp_generate", "")
        return RedirectResponse(
            url=_prefixed(request, "/2fa"),
            status_code=302,
        )

    @app.post("/2fa/recovery/generate", response_class=HTMLResponse)
    async def recovery_generate(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        enabled, secret = _get_admin_totp(u)
        if not enabled or not secret:
            raise HTTPException(status_code=400, detail="enable 2fa first")

        new_codes = _create_recovery_codes(username=u, count=10)
        _audit(u, "recovery_generate", "")

        uri = build_provisioning_uri(
            secret=secret,
            account=u,
            issuer="MAIL_API",
        )
        return templates.TemplateResponse(
            "totp.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "totp_enabled": True,
                "totp_secret": secret,
                "otpauth_uri": uri,
                "qr_available": segno is not None,
                "recovery_unused": _count_unused_recovery_codes(u),
                "new_recovery_codes": new_codes,
                "message": (
                    "recovery codes generated "
                    "(store them now; they won't be shown again)"
                ),
            },
        )

    @app.post("/2fa/enable", response_class=HTMLResponse)
    async def totp_enable(request: Request, code: str = Form("")):
        _require_ip_allowed(request)
        u = _require_login(request)
        enabled, secret = _get_admin_totp(u)
        if enabled:
            return RedirectResponse(
                url=_prefixed(request, "/2fa"),
                status_code=302,
            )
        if not secret:
            return templates.TemplateResponse(
                "totp.html",
                {
                    "request": request,
                    "user": u,
                    "prefix": _get_forwarded_prefix(request),
                    "totp_enabled": False,
                    "totp_secret": "",
                    "otpauth_uri": "",
                    "error": "generate a secret first",
                },
                status_code=400,
            )

        if not verify_totp(secret=secret, code=code):
            uri = build_provisioning_uri(
                secret=secret,
                account=u,
                issuer="MAIL_API",
            )
            return templates.TemplateResponse(
                "totp.html",
                {
                    "request": request,
                    "user": u,
                    "prefix": _get_forwarded_prefix(request),
                    "totp_enabled": False,
                    "totp_secret": secret,
                    "otpauth_uri": uri,
                    "error": "invalid code",
                },
                status_code=400,
            )

        _enable_admin_totp(u)
        _audit(u, "totp_enable", "")
        return RedirectResponse(
            url=_prefixed(request, "/2fa"),
            status_code=302,
        )

    @app.post("/2fa/disable", response_class=HTMLResponse)
    async def totp_disable(request: Request, code: str = Form("")):
        _require_ip_allowed(request)
        u = _require_login(request)
        enabled, secret = _get_admin_totp(u)
        if not enabled:
            return RedirectResponse(
                url=_prefixed(request, "/2fa"),
                status_code=302,
            )
        if not secret:
            raise HTTPException(status_code=400, detail="2fa misconfigured")

        if not verify_totp(secret=secret, code=code):
            uri = build_provisioning_uri(
                secret=secret,
                account=u,
                issuer="MAIL_API",
            )
            return templates.TemplateResponse(
                "totp.html",
                {
                    "request": request,
                    "user": u,
                    "prefix": _get_forwarded_prefix(request),
                    "totp_enabled": True,
                    "totp_secret": secret,
                    "otpauth_uri": uri,
                    "error": "invalid code",
                },
                status_code=400,
            )

        _disable_admin_totp(u)
        _delete_all_recovery_codes(u)
        _audit(u, "totp_disable", "")
        return RedirectResponse(
            url=_prefixed(request, "/2fa"),
            status_code=302,
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_get(request: Request):
        _require_ip_allowed(request)
        if not _has_any_admin():
            return RedirectResponse(
                url=_prefixed(request, "/bootstrap"),
                status_code=302,
            )
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "has_admin": _has_any_admin(),
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.post("/login")
    async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        code: str = Form(""),
    ):
        _require_ip_allowed(request)
        ip = _get_client_ip(request)
        allowed, wait_seconds = _login_is_allowed(ip=ip, username=username)
        if not allowed:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": f"too many attempts; retry in {wait_seconds}s",
                    "has_admin": _has_any_admin(),
                    "prefix": _get_forwarded_prefix(request),
                    "username": username,
                },
                status_code=429,
            )

        if not _authenticate(username, password):
            _record_login_failure(ip=ip, username=username)
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "invalid credentials",
                    "has_admin": _has_any_admin(),
                    "prefix": _get_forwarded_prefix(request),
                    "username": username,
                },
                status_code=401,
            )

        enabled, secret = _get_admin_totp(username)
        if enabled:
            if not secret.strip():
                return templates.TemplateResponse(
                    "login.html",
                    {
                        "request": request,
                        "error": "2fa misconfigured",
                        "has_admin": _has_any_admin(),
                        "prefix": _get_forwarded_prefix(request),
                        "username": username,
                        "totp_required": True,
                    },
                    status_code=403,
                )
            if not verify_totp(secret=secret, code=code):
                if _consume_recovery_code(username=username, code=code):
                    _audit(username, "recovery_consume", "")
                else:
                    _record_login_failure(ip=ip, username=username)
                    return templates.TemplateResponse(
                        "login.html",
                        {
                            "request": request,
                            "error": "invalid 2fa code",
                            "has_admin": _has_any_admin(),
                            "prefix": _get_forwarded_prefix(request),
                            "username": username,
                            "totp_required": True,
                        },
                        status_code=401,
                    )

        _clear_login_failures(ip=ip, username=username)
        s = get_session_serializer()
        cookie = s.dumps({"u": username})
        resp = RedirectResponse(url=_prefixed(request, "/"), status_code=302)
        resp.set_cookie(
            "mail_api_session",
            cookie,
            httponly=True,
            samesite="strict",
        )
        _audit(username, "login", "")
        return resp

    @app.post("/logout")
    async def logout(request: Request):
        _require_ip_allowed(request)
        u = _get_current_user(request) or "unknown"
        resp = RedirectResponse(
            url=_prefixed(request, "/login"),
            status_code=302,
        )
        resp.delete_cookie("mail_api_session")
        _audit(u, "logout", "")
        return resp

    @app.get("/bootstrap", response_class=HTMLResponse)
    async def bootstrap_get(request: Request):
        _require_ip_allowed(request)
        if _has_any_admin():
            return RedirectResponse(
                url=_prefixed(request, "/login"),
                status_code=302,
            )
        return templates.TemplateResponse(
            "bootstrap.html",
            {
                "request": request,
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.post("/bootstrap")
    async def bootstrap_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        _require_ip_allowed(request)
        if _has_any_admin():
            raise HTTPException(
                status_code=409,
                detail="already initialized",
            )
        if len(username.strip()) < 3 or len(password) < 10:
            return templates.TemplateResponse(
                "bootstrap.html",
                {
                    "request": request,
                    "error": "username or password too short",
                    "prefix": _get_forwarded_prefix(request),
                },
                status_code=400,
            )
        _create_admin(username.strip(), password)
        _audit(username.strip(), "bootstrap", "created initial admin")
        return RedirectResponse(
            url=_prefixed(request, "/login"),
            status_code=302,
        )

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        keys = [
            "webhook_secret",
            "timestamp_skew_seconds",
            "allowed_sender_domain",
            "default_from_localpart",
            "allow_from_override",
            "sendmail_path",
            "receiver_bind_host",
            "trusted_proxy_cidrs",
            "admin_bind_host",
        ]
        vals = {k: get_setting(k) for k in keys}
        defaults = {k: DEFAULTS.get(k, "") for k in keys}
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": u,
                "values": vals,
                "defaults": defaults,
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.post("/settings")
    async def settings_post(
        request: Request,
        webhook_secret: str = Form(""),
        timestamp_skew_seconds: str = Form("300"),
        allowed_sender_domain: str = Form(""),
        default_from_localpart: str = Form("no-reply"),
        allow_from_override: str = Form(""),
        sendmail_path: str = Form("/usr/sbin/sendmail"),
        receiver_bind_host: str = Form("0.0.0.0"),
        admin_bind_host: str = Form("0.0.0.0"),
        trusted_proxy_cidrs: str = Form(""),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)

        set_setting("webhook_secret", webhook_secret.strip())
        set_setting(
            "timestamp_skew_seconds",
            timestamp_skew_seconds.strip() or "300",
        )
        set_setting(
            "allowed_sender_domain",
            allowed_sender_domain.strip(),
        )
        set_setting(
            "default_from_localpart",
            default_from_localpart.strip() or "no-reply",
        )
        truthy = {"1", "true", "on", "yes"}
        allow_override_value = allow_from_override.strip().lower()
        allow_override = (
            "1"
            if allow_override_value in truthy
            else "0"
        )
        set_setting("allow_from_override", allow_override)
        set_setting(
            "sendmail_path",
            sendmail_path.strip() or "/usr/sbin/sendmail",
        )
        set_setting(
            "receiver_bind_host",
            receiver_bind_host.strip() or "0.0.0.0",
        )
        set_setting(
            "admin_bind_host",
            admin_bind_host.strip() or "0.0.0.0",
        )
        set_setting("trusted_proxy_cidrs", trusted_proxy_cidrs.strip())

        _audit(u, "update_settings", "")
        return RedirectResponse(
            url=_prefixed(request, "/settings"),
            status_code=302,
        )

    @app.get("/ip-rules", response_class=HTMLResponse)
    async def ip_rules_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        return templates.TemplateResponse(
            "ip_rules.html",
            {
                "request": request,
                "user": u,
                "rules": list_rules(),
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.get("/admins", response_class=HTMLResponse)
    async def admins_get(request: Request):
        _require_ip_allowed(request)
        u = _require_login(request)
        return templates.TemplateResponse(
            "admins.html",
            {
                "request": request,
                "user": u,
                "admins": _list_admins(),
                "prefix": _get_forwarded_prefix(request),
            },
        )

    @app.post("/admins/create")
    async def admins_create(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        if len(username.strip()) < 3 or len(password) < 10:
            return RedirectResponse(
                url=_prefixed(request, "/admins"),
                status_code=302,
            )
        try:
            _create_admin(username.strip(), password)
        except sqlite3.IntegrityError:
            return RedirectResponse(
                url=_prefixed(request, "/admins"),
                status_code=302,
            )
        _audit(u, "create_admin", username.strip())
        return RedirectResponse(
            url=_prefixed(request, "/admins"),
            status_code=302,
        )

    @app.post("/admins/disable")
    async def admins_disable(request: Request, username: str = Form(...)):
        _require_ip_allowed(request)
        u = _require_login(request)
        _set_admin_active(username.strip(), False)
        _audit(u, "disable_admin", username.strip())
        return RedirectResponse(
            url=_prefixed(request, "/admins"),
            status_code=302,
        )

    @app.post("/admins/enable")
    async def admins_enable(request: Request, username: str = Form(...)):
        _require_ip_allowed(request)
        u = _require_login(request)
        _set_admin_active(username.strip(), True)
        _audit(u, "enable_admin", username.strip())
        return RedirectResponse(
            url=_prefixed(request, "/admins"),
            status_code=302,
        )

    @app.post("/ip-rules/add")
    async def ip_rules_add(
        request: Request,
        action: str = Form(...),
        cidr: str = Form(...),
    ):
        _require_ip_allowed(request)
        u = _require_login(request)
        try:
            add_rule(action, cidr)
        except ValueError:
            return RedirectResponse(
                url=_prefixed(request, "/ip-rules"),
                status_code=302,
            )
        _audit(u, "add_ip_rule", f"{action}:{cidr}")
        return RedirectResponse(
            url=_prefixed(request, "/ip-rules"),
            status_code=302,
        )

    @app.post("/ip-rules/delete")
    async def ip_rules_delete(request: Request, rule_id: int = Form(...)):
        _require_ip_allowed(request)
        u = _require_login(request)
        delete_rule(rule_id)
        _audit(u, "delete_ip_rule", str(rule_id))
        return RedirectResponse(
            url=_prefixed(request, "/ip-rules"),
            status_code=302,
        )

    return app
