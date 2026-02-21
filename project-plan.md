---
name: MAIL_API
ports:
  receiver: 2555
  control_panel: 2580
---

# Goals
- Accept outbound email webhook calls from `auth-service` and relay them as outbound email using a configurable delivery backend.
- Provide administrator-friendly, protocol-specific configuration pages (SMTP submission plus optional mailbox protocols like IMAP/IMAPS/POP3/POP3S for related scenarios).
- Provide a secure control panel to configure all runtime options.
- Support multiple admin credentials (and optionally multiple API keys) for control panel access.
- Allow sending email **as any address** within a configured hostname/domain.
- Ports are **static**: receiver `2555`, control panel `2580`.

# Implementation Stack
- Python 3.11+
- FastAPI + Jinja2 templates
- SQLite for settings/queue

# Supported Protocol Scenarios (Admin Pages)
## SMTP submission (primary / required)
- The system delivers email via SMTP submission to an upstream SMTP host.
- Must support presets:
  - port `25` with `plain`
  - port `587` with `STARTTLS` (default)
  - port `465` with `SSL/TLS`
- Must support:
  - optional username/password authentication
  - SMTP timeout setting
  - optional "ignore/bypass certificate validation" toggle
  - "Test SMTP" action in the UI

## IMAP/IMAPS/POP3/POP3S (optional / future)
- Note: these protocols are generally used to *read* mailboxes, not to send mail.
- Requirement (UI/administrator experience): provide protocol-specific pages that can store credentials and run connectivity tests, for future workflows such as:
  - IMAP/IMAPS: append a copy to a mailbox folder (e.g. Sent), or mailbox automation.
  - POP3/POP3S: poll a mailbox for bounces/notifications.
- These pages must be clearly labeled as optional and separate from outbound delivery.

# Expected Webhook Contract (from auth-service)
## JSON body
- `type`: `"email_verification"` or `"password_reset"`
- `to`: recipient email
- `subject`: email subject
- `token`: raw one-time token
- `expiresAt`: ISO timestamp
- `link`: optional, only included if `PUBLIC_WEB_URL` is set upstream

## Optional signature headers
Only present if `OUTBOUND_EMAIL_WEBHOOK_SECRET` is set upstream:
- `X-TransLife-Timestamp`: ISO timestamp
- `X-TransLife-Signature`: `hex(hmac_sha256(secret, timestamp + "." + rawBody))`

# Proposed Architecture
## Processes
- **MAIL_API Receiver** (HTTP, port `2555`)
  - Endpoint: `POST /webhook/outbound-email`
  - Validates request signature (if enabled)
  - Validates payload schema
  - Renders email body (template-based)
  - Enqueues the message into an outbound queue (store-and-forward)
- **MAIL_API Delivery Worker** (background process)
  - Reserves the next queued email
  - Attempts delivery via SMTP submission
  - Retries on failures with backoff
  - Deletes queued row on success
  - Writes to a capped delivery log (max 5MB)
- **MAIL_API Control Panel** (HTTP, port `2580`)
  - Web UI for config and user management
  - Optionally exposes a local-only admin API (loopback) for automation

## Storage
- SQLite database (single file) for:
  - **Global settings** (webhook secret, allowed sender domain, templates, replay window, etc.)
  - **Admin users** (username + password hash)
  - **API keys** (optional) for programmatic control panel access
  - **Audit log** (who changed what and when)
  - **Outbound queue** (store-and-forward delivery)

# Security Model
## Webhook receiver
- If webhook secret configured:
  - Recompute signature using raw request body.
  - Constant-time compare.
  - Reject if timestamp is too old/new (replay protection; default window: 5 minutes; configurable).
- If webhook secret is not configured:
  - Receiver can optionally refuse all requests until configured (recommended default).
- Allowlist optional:
  - Source IP allowlist (configurable)
- Rate limiting:
  - Basic per-IP rate limit (configurable)

## Control panel
- Password hashing: `bcrypt` or `argon2id`.
- Session cookies:
  - `HttpOnly`, `SameSite=Strict`, `Secure` when TLS is enabled.
- CSRF protection for state-changing actions.
- Optional TLS:
  - Either run behind a reverse proxy (recommended) or bind to a cert/key configured in the panel.

# Email Submission Details (SMTP)
- Compose an RFC 5322 message with headers:
  - `From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type`
- Submit using SMTP:
  - Envelope-from (MAIL FROM) is set to the configured sender address.
  - `From:` header uses the configured sender name (optional) + sender address.
- Sender policy:
  - Control panel sets `allowed_sender_domain` (e.g. `example.com`).
  - Control panel sets whether any local-part is allowed (`*@domain`) or only allowlisted senders.

# Control Panel Configurable Options
- Webhook signature:
  - enabled/disabled
  - shared secret value
  - accepted timestamp skew window
- Public URLs:
  - `public_web_url` (if you want receiver to build links when upstream does not send `link`)
- Email templates:
  - Subject/body templates for `email_verification` and `password_reset`
  - Option to include token, expiresAt, and link
- Sender settings:
  - `allowed_sender_domain`
  - default `from` local-part (e.g. `no-reply`)
  - allow any local-part toggle
- Admin & access:
  - create/disable admin users
  - rotate session secret
  - create/revoke API keys (optional)
- Outbound delivery (SMTP):
  - host / port / security (plain, STARTTLS, SSL)
  - timeout
  - username / password
  - ignore certificates toggle
  - sender display name
  - test SMTP (send a real test message)
- Optional protocol pages (future):
  - IMAP (143) settings + test
  - IMAPS (993) settings + test
  - POP3 (110) settings + test
  - POP3S (995) settings + test
- Observability:
  - request log level
  - view queue status
  - view recent deliveries / errors
  - view delivery log (capped to 5MB)

# API Surface (Draft)
## Receiver (2555)
- `POST /webhook/outbound-email`
- `GET /healthz`

## Control panel (2580)
- `GET /login`
- `POST /login`
- `POST /logout`
- `GET /` (dashboard)
- `GET/POST /settings`
- `GET/POST /admins`
- `GET/POST /templates`
- `GET /audit`

# Deployment
- Run as a dedicated OS user (e.g. `mail_api`).
- Ensure outbound network access to the configured SMTP host/port from the worker process.
- Ensure the receiver, control panel, and delivery worker are running (e.g., via systemd).
- Bind to:
  - `0.0.0.0:2555` (receiver)
  - `127.0.0.1:2580` by default (control panel), with an option to bind to `0.0.0.0` only if explicitly enabled.

# Open Questions / Decisions Needed
- Control panel exposure: local-only (`127.0.0.1`) + reverse proxy, or direct public bind with TLS in-app?
- Should receiver accept requests when signature is not configured, or hard-fail until configured?
- Exact sender rules: allow any `local-part@domain` or require allowlist?

# Integration Guide: Sending a Message via URL (Webhook)
This section describes exactly how another program should call MAIL_API.

## 1) HTTP Endpoint
- Method: `POST`
- Path: `/webhook/outbound-email`
- Default direct URL:
  - `http://<MAIL_API_HOST>:2555/webhook/outbound-email`
- If behind Nginx on port `2500`:
  - `https://<PUBLIC_HOST>:2500/webhook/outbound-email`

## 2) Headers
### Content type
- `Content-Type: application/json`

### Optional signature headers (recommended)
If a webhook secret is configured in the control panel, the sender must include:
- `X-TransLife-Timestamp`: ISO8601 timestamp (UTC recommended), e.g. `2026-02-21T05:35:10Z`
- `X-TransLife-Signature`: hex HMAC SHA-256 of:
  - `timestamp + "." + raw_body`

Pseudo-code:
```
raw_body = JSON bytes exactly as sent
msg = timestamp + "." + raw_body
signature = hex(hmac_sha256(secret, msg))
```

## 3) JSON Body Schema
Required fields:
- `type`: `"email_verification"` or `"password_reset"`
- `to`: recipient email address
- `subject`: subject line
- `token`: one-time token string
- `expiresAt`: ISO timestamp

Optional fields:
- `link`: URL string
- `fromLocalPart`: if enabled by admin policy, allows caller to request a specific local-part

Example body:
```
{
  "type": "email_verification",
  "to": "user@example.com",
  "subject": "Verify your email",
  "token": "123456",
  "expiresAt": "2026-02-21T06:00:00Z",
  "link": "https://example.com/verify?token=123456"
}
```

## 4) Example cURL
Unsigned (only works if signature is not required):
```
curl -X POST "http://127.0.0.1:2555/webhook/outbound-email" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"email_verification\",\"to\":\"user@example.com\",\"subject\":\"Verify\",\"token\":\"123\",\"expiresAt\":\"2026-02-21T06:00:00Z\"}"
```

## 5) Success Response
On success, the receiver enqueues the message and returns JSON:
- `ok`: boolean
- `queued_id`: integer
- `queued_at`: timestamp

Example:
```
{
  "ok": true,
  "to": "user@example.com",
  "subject": "Verify your email",
  "queued_id": 42,
  "queued_at": "2026-02-21T05:35:12.345678Z"
}
```

## 6) Common Error Responses
- `401 missing signature` / `401 invalid signature`: signature required and failed
- `403 forbidden`: caller IP not allowed
- `400 invalid json` / schema validation errors
- `503 webhook secret not configured`: receiver not ready
- `503 sender domain not configured`: admin must configure sender policy
