from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from .ip_rules import ensure_default_rules, is_ip_allowed, list_rules
from .rate_limit import SqliteFixedWindowRateLimiter
from .webhook_ip_rules import (
    has_any_rules as webhook_has_any_rules,
    is_ip_allowed as is_webhook_ip_allowed,
    list_rules as list_webhook_rules,
)
from .security import verify_webhook_signature
from .emailer import build_message
from .client_ip import get_real_client_ip
from .outbound_queue import enqueue_email
from .webhooks import ensure_default_webhook, get_webhook_by_relay_key


def create_receiver_app() -> FastAPI:
    ensure_default_rules()
    ensure_default_webhook()
    app = FastAPI(title="MAIL_API Receiver")

    limiter = SqliteFixedWindowRateLimiter(
        scope="receiver",
        max_requests=120,
        window_seconds=60,
    )

    @app.middleware("http")
    async def _rate_limit_middleware(request: Request, call_next):
        ip = get_real_client_ip(request)
        r = limiter.check(key=ip)
        if not r.ok:
            return PlainTextResponse(
                content="rate limited",
                status_code=429,
                headers={"Retry-After": str(r.retry_after_seconds)},
            )
        return await call_next(request)

    def _content_length_too_large(request: Request, *, max_bytes: int) -> bool:
        raw = (request.headers.get("content-length") or "").strip()
        if not raw:
            return False
        try:
            n = int(raw)
        except ValueError:
            return False
        return n > max_bytes

    def _validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
        msg_type = str(payload.get("type", "")).strip()
        to_addr = str(payload.get("to", "")).strip()
        subject = str(payload.get("subject", "")).strip()
        token = str(payload.get("token", "")).strip()
        expires_at = str(payload.get("expiresAt", "")).strip()
        link = payload.get("link")
        from_localpart = str(payload.get("fromLocalPart", "")).strip()

        if msg_type not in {"email_verification", "password_reset"}:
            raise HTTPException(status_code=400, detail="invalid type")
        if not to_addr or "@" not in to_addr:
            raise HTTPException(status_code=400, detail="invalid to")
        if not subject:
            raise HTTPException(status_code=400, detail="invalid subject")
        if not token:
            raise HTTPException(status_code=400, detail="invalid token")
        if not expires_at:
            raise HTTPException(status_code=400, detail="invalid expiresAt")
        if link is not None and not isinstance(link, str):
            raise HTTPException(status_code=400, detail="invalid link")

        return {
            "msg_type": msg_type,
            "to_addr": to_addr,
            "subject": subject,
            "token": token,
            "expires_at": expires_at,
            "link": link,
            "from_localpart": from_localpart,
        }

    @app.get("/healthz")
    async def healthz(request: Request):
        client_ip = get_real_client_ip(request)
        rules = list_rules()
        if not is_ip_allowed(client_ip, rules):
            raise HTTPException(status_code=403, detail="forbidden")
        return {"ok": True}

    @app.post("/webhook/outbound-email")
    async def outbound_email(
        request: Request,
        x_relay_key: Optional[str] = Header(
            default=None,
            alias="X-Relay-Key",
        ),
        x_translife_timestamp: Optional[str] = Header(
            default=None,
            alias="X-TransLife-Timestamp",
        ),
        x_translife_signature: Optional[str] = Header(
            default=None,
            alias="X-TransLife-Signature",
        ),
    ):
        if _content_length_too_large(request, max_bytes=64 * 1024):
            raise HTTPException(status_code=413, detail="payload too large")

        client_ip = get_real_client_ip(request)
        rules = list_rules()
        if not is_ip_allowed(client_ip, rules):
            raise HTTPException(status_code=403, detail="forbidden")

        if not x_relay_key:
            raise HTTPException(status_code=401, detail="missing relay key")

        wh = get_webhook_by_relay_key(x_relay_key)
        if wh is None:
            raise HTTPException(status_code=401, detail="invalid relay key")
        if not wh.is_active:
            raise HTTPException(status_code=403, detail="webhook disabled")

        if webhook_has_any_rules(webhook_id=wh.id):
            wh_rules = list_webhook_rules(webhook_id=wh.id)
            if not is_webhook_ip_allowed(client_ip, wh_rules):
                raise HTTPException(status_code=403, detail="forbidden")

        raw_body = await request.body()
        if len(raw_body) > (64 * 1024):
            raise HTTPException(status_code=413, detail="payload too large")

        if not wh.webhook_secret.strip():
            raise HTTPException(
                status_code=503,
                detail="webhook secret not configured",
            )
        if not x_translife_timestamp or not x_translife_signature:
            raise HTTPException(status_code=401, detail="missing signature")
        ok = verify_webhook_signature(
            secret=wh.webhook_secret,
            timestamp_header=x_translife_timestamp,
            signature_header=x_translife_signature,
            raw_body=raw_body,
            max_skew_seconds=wh.timestamp_skew_seconds,
        )
        if not ok:
            raise HTTPException(status_code=401, detail="invalid signature")

        try:
            payload: dict[str, Any] = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid json")

        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="invalid json")

        v = _validate_payload(payload)
        msg_type = str(v["msg_type"])
        to_addr = str(v["to_addr"])
        subject = str(v["subject"])
        token = str(v["token"])
        expires_at = str(v["expires_at"])
        link = v["link"]
        from_localpart = str(v["from_localpart"])

        from_addr = (wh.sender_email or "").strip()
        if not from_addr or "@" not in from_addr:
            raise HTTPException(
                status_code=503,
                detail="sender email not configured",
            )

        if wh.allow_from_override and from_localpart:
            domain = from_addr.split("@", 1)[1]
            from_addr = f"{from_localpart}@{domain}"

        sender_name = wh.smtp_sender_name.strip() or None

        body_lines = [
            f"Type: {msg_type}",
            f"Token: {token}",
            f"ExpiresAt: {expires_at}",
        ]
        if isinstance(link, str) and link.strip():
            body_lines.append(f"Link: {link.strip()}")

        message_bytes = build_message(
            from_addr=from_addr,
            to_addr=to_addr,
            subject=subject,
            body_text="\n".join(body_lines) + "\n",
            from_name=sender_name,
        )

        idempotency_key = (request.headers.get("x-idempotency-key") or "").strip()
        if idempotency_key and len(idempotency_key) > 120:
            raise HTTPException(status_code=400, detail="invalid idempotency key")

        try:
            queue_id = enqueue_email(
                webhook_id=wh.id,
                idempotency_key=(idempotency_key or None),
                to_addr=to_addr,
                from_addr=from_addr,
                subject=subject,
                body_text="\n".join(body_lines) + "\n",
                message_bytes=message_bytes,
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=str(e))

        return {
            "ok": True,
            "to": to_addr,
            "subject": subject,
            "queued_id": queue_id,
            "idempotency_key": idempotency_key or None,
            "queued_at": datetime.utcnow().isoformat() + "Z",
        }

    return app
