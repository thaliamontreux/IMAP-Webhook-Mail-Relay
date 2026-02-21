from __future__ import annotations

from datetime import datetime, timezone
import os
import sqlite3
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .db import get_conn
from .ip_rules import (
    add_rule,
    delete_rule,
    ensure_default_rules,
    is_ip_allowed,
    list_rules,
)
from .security import get_session_serializer, hash_password, verify_password
from .settings import DEFAULTS, get_setting, set_setting
from .client_ip import get_real_client_ip, is_trusted_proxy_peer
from .delivery_log import iter_recent_lines, append_log_line
from .emailer import build_message
from .smtp_delivery import send_via_smtp
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

    @app.get("/healthz")
    async def healthz(request: Request):
        _require_ip_allowed(request)
        return {"ok": True}

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
        with get_conn() as conn:
            rows = conn.execute(
                (
                    "select q.id, q.created_at, q.updated_at, q.status, "
                    "q.webhook_id, q.to_addr, q.from_addr, q.subject, "
                    "q.attempts, q.next_attempt_at, q.last_error "
                    "from outbound_queue q "
                    "order by q.next_attempt_at asc, q.id asc "
                    "limit 200"
                )
            ).fetchall()
        items = [dict(r) for r in rows]
        return templates.TemplateResponse(
            "queue.html",
            {
                "request": request,
                "user": u,
                "prefix": _get_forwarded_prefix(request),
                "items": items,
            },
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
    ):
        _require_ip_allowed(request)
        if not _authenticate(username, password):
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "invalid credentials",
                    "has_admin": _has_any_admin(),
                    "prefix": _get_forwarded_prefix(request),
                },
                status_code=401,
            )

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
