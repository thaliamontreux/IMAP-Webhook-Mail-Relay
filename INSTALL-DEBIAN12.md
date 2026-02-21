# Debian 12 Install

This project is designed to run on Debian 12 with Python 3.11.x.

## Quick install

Run as root (or with sudo):

- `sudo bash install/debian12/install.sh`

## What the installer does

- Verifies prerequisites exist (python3 + venv + systemd; nginx only if you pass `--nginx`)
- Creates a dedicated system user `mail_api`
- Copies the app into `/opt/mail_api/app`
- Creates a virtual environment in `/opt/mail_api/venv` and installs `requirements.txt`
- Creates a data directory `/var/lib/mail_api` (SQLite DB lives here)
- Installs and enables a systemd service `mail_api.service`
- Optionally installs an Nginx site config (template) if you pass `--nginx`

## After install

- Control panel: `http://<server-ip>:2580/bootstrap`
- Receiver health: `http://<server-ip>:2555/healthz`

If you enable the provided Nginx template (`--nginx`), Nginx will listen on port `2500` and proxy to the app:

- Receiver via Nginx: `http://<server-name>:2500/` (proxies to `:2555`)
- Control panel via Nginx: `http://<server-name>:2500/admin/` (proxies to `:2580`)

## Nginx / reverse proxy

If you put Nginx in front, set the control panel setting:

- `Trusted proxy CIDRs`: include the Nginx IP, e.g. `127.0.0.1/32`

## Hardening checklist (no 2FA)

- **Terminate TLS at Nginx**
  - Use the provided `nginx-example.conf` (TLS on port `2500`) as a starting point.
  - Ensure `X-Forwarded-Proto` is set by Nginx (templates already do this).

- **Restrict admin access**
  - Prefer restricting `/admin/` at the Nginx layer (allowlist) in addition to MAIL_API IP rules.
  - Also configure MAIL_API IP rules (`IP Rules` page) to only allow your admin networks.

- **Trusted proxy CIDRs**
  - Set `Trusted proxy CIDRs` to include the Nginx IP/CIDR so the app can correctly determine the real client IP.
  - Example when proxying locally: `127.0.0.1/32`

- **Request size limits**
  - The receiver enforces a 64KB max request size.
  - Set `client_max_body_size 64k;` in Nginx for consistent behavior.

- **Persistent protections**
  - Rate limiting and login lockout are stored in SQLite (in `/var/lib/mail_api/mail_api.db` by default).

- **Idempotency**
  - Clients may include `X-Idempotency-Key` (max 120 chars). Replays with the same key will return the same queue id.
