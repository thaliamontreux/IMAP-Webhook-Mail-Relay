# MAIL_API Webhook Integration

This document describes how to call the **MAIL_API** receiver webhook to queue outbound email for delivery using the **per-webhook** configuration in the control panel.

## 1) Endpoint

- **Method:** `POST`
- **Path:** `/webhook/outbound-email`
- **Default receiver port:** `2555`

Examples:

- Direct (no reverse proxy):
  - `http://<server-ip>:2555/webhook/outbound-email`

- With the provided Nginx template (if you enabled it):
  - `http(s)://<server-name>:2500/webhook/outbound-email`

## 2) Authentication and required headers

You must provide the following headers:

- `X-Relay-Key`
  - The webhook’s relay key (unique per webhook).
  - You can copy this value from the **Control Panel → Webhooks → (your webhook)** page.

- `X-TransLife-Timestamp`
  - An ISO-8601 timestamp string.
  - Example: `2026-02-22T22:45:00Z`

- `X-TransLife-Signature`
  - Lowercase hex HMAC-SHA256 signature.
  - Computed from:

    `HMAC_SHA256(secret = webhook_secret, message = timestamp + "." + raw_body)`

  Where:
  - `webhook_secret` is the secret configured for that webhook.
  - `timestamp` is the exact header value you send in `X-TransLife-Timestamp`.
  - `raw_body` is the exact request body bytes you send.

### Signature pseudocode

```text
timestamp = X-TransLife-Timestamp
raw_body  = request body bytes
msg       = timestamp + "." + raw_body
signature = hex(hmac_sha256(webhook_secret, msg))
```

## 3) Request body (JSON)

- **Content-Type:** `application/json`
- **Max size:** 64 KB

### Supported payload schema

```json
{
  "type": "email_verification" | "password_reset",
  "to": "recipient@example.com",
  "subject": "Subject line",
  "token": "opaque-token-string",
  "expiresAt": "2026-02-22T23:15:00Z",
  "link": "https://example.com/reset?token=...",
  "fromLocalPart": "optional-local-part"
}
```

Notes:

- `type` must be one of:
  - `email_verification`
  - `password_reset`
- `to` must contain `@`.
- `subject` must be non-empty.
- `token` must be non-empty.
- `expiresAt` must be non-empty (string).
- `link` is optional. If present, it must be a string.
- `fromLocalPart` is optional.
  - It is only applied if the webhook is configured to allow From override **and** the webhook is not using `smtp_username` as the From address.

## 4) Idempotency (optional, recommended)

You may include:

- `X-Idempotency-Key: <string>`

Rules:

- Max length: 120 chars.
- Replaying the same request (same webhook + same idempotency key) will return the same `queued_id`.

## 5) How MAIL_API chooses SMTP settings and sender

MAIL_API uses **only the webhook’s SMTP profile** (not the global SMTP profile) when delivering webhook emails.

- **SMTP host/port/security/username/password** come from the webhook’s SMTP configuration.
- **From address**:
  - Defaults to `webhook.smtp_username` if it looks like an email address.
  - Otherwise falls back to the webhook’s `sender_email`.
- **Envelope-from**:
  - Defaults to the chosen From address.
  - If `smtp_envelope_from_override` is set on the webhook, it is used as the SMTP MAIL FROM.

## 6) Responses

### Success: `200 OK`

```json
{
  "ok": true,
  "to": "recipient@example.com",
  "subject": "Subject line",
  "queued_id": 123,
  "idempotency_key": "abc-123",
  "queued_at": "2026-02-22T22:45:00Z"
}
```

### Common errors

- `400 Bad Request`
  - invalid JSON
  - invalid schema/fields
  - invalid idempotency key

- `401 Unauthorized`
  - missing relay key
  - invalid relay key
  - missing signature headers
  - invalid signature

- `403 Forbidden`
  - sender IP not allowlisted (global IP rules or webhook IP rules)
  - webhook disabled

- `413 Payload Too Large`
  - request body exceeds 64 KB

- `503 Service Unavailable`
  - webhook secret not configured
  - SMTP sender identity not configured (no valid `smtp_username` email and no `sender_email`)

## 7) Example: curl

```bash
TS="2026-02-22T22:45:00Z"
BODY='{"type":"password_reset","to":"you@example.com","subject":"Reset your password","token":"abc123","expiresAt":"2026-02-22T23:15:00Z","link":"https://example.com/reset?token=abc123"}'

# SIGNATURE = hex(hmac_sha256(WEBHOOK_SECRET, TS + "." + BODY))
# How you compute it depends on your environment.

curl -i \
  -X POST "http://127.0.0.1:2555/webhook/outbound-email" \
  -H "Content-Type: application/json" \
  -H "X-Relay-Key: <YOUR_RELAY_KEY>" \
  -H "X-TransLife-Timestamp: ${TS}" \
  -H "X-TransLife-Signature: <YOUR_SIGNATURE_HEX>" \
  -H "X-Idempotency-Key: reset-you@example.com-abc123" \
  --data "${BODY}"
```

## 8) Example: Python

```python
import hmac
import hashlib
import json
import requests

url = "http://127.0.0.1:2555/webhook/outbound-email"
relay_key = "..."
webhook_secret = "..."  # keep this secure

timestamp = "2026-02-22T22:45:00Z"
payload = {
    "type": "password_reset",
    "to": "you@example.com",
    "subject": "Reset your password",
    "token": "abc123",
    "expiresAt": "2026-02-22T23:15:00Z",
    "link": "https://example.com/reset?token=abc123",
}

body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
msg = timestamp.encode("utf-8") + b"." + body
sig = hmac.new(webhook_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Relay-Key": relay_key,
    "X-TransLife-Timestamp": timestamp,
    "X-TransLife-Signature": sig,
    "X-Idempotency-Key": "reset-you@example.com-abc123",
}

resp = requests.post(url, headers=headers, data=body, timeout=15)
print(resp.status_code, resp.text)
```

Important:

- The signature is computed from the **exact bytes** of the request body.
- If your JSON library changes whitespace or ordering between signing and sending, the signature will not validate.

## 9) Operational notes

- Configure global IP allow rules (Control Panel → **IP Rules**) to allow your application’s outbound IP(s).
- Optionally configure per-webhook IP rules (Control Panel → **Webhook IP Rules**) for stricter allowlisting.
- If you are behind a reverse proxy, configure **Trusted proxy CIDRs** in the Control Panel so the real client IP is recognized.
