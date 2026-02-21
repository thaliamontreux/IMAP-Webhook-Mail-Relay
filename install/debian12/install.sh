#!/usr/bin/env bash
set -euo pipefail

APP_USER="mail_api"
APP_DIR="/opt/mail_api"
APP_CODE_DIR="$APP_DIR/app"
VENV_DIR="$APP_DIR/venv"
DATA_DIR="/var/lib/mail_api"
SYSTEMD_UNIT_SRC="$(dirname "$0")/mail_api.service"
SYSTEMD_UNIT_DST="/etc/systemd/system/mail_api.service"

WITH_NGINX="0"

usage() {
  cat <<EOF
Usage: install.sh [--nginx]

Options:
  --nginx   Install an Nginx site template into /etc/nginx/sites-available/mail_api
EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--nginx" ]]; then
  WITH_NGINX="1"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root (or with sudo)" >&2
  exit 1
fi

echo "==> Checking prerequisites"
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.11+ first." >&2
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "ERROR: python3 venv module not available. Install python3-venv." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemctl not found. This installer requires systemd." >&2
  exit 1
fi

if [[ "$WITH_NGINX" == "1" ]]; then
  if ! command -v nginx >/dev/null 2>&1; then
    echo "ERROR: nginx not found but --nginx was provided." >&2
    exit 1
  fi
fi

if ! command -v /usr/sbin/sendmail >/dev/null 2>&1; then
  echo "WARNING: /usr/sbin/sendmail not found. Install/configure postfix on this host." >&2
fi

echo "==> Creating user $APP_USER (if needed)"
if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

echo "==> Creating directories"
mkdir -p "$APP_CODE_DIR" "$DATA_DIR"
chown -R "$APP_USER:$APP_USER" "$DATA_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Copying application code to $APP_CODE_DIR"
rm -rf "$APP_CODE_DIR"/*
cp -a "$REPO_ROOT/mail_api" "$APP_CODE_DIR/"
cp -a "$REPO_ROOT/requirements.txt" "$APP_CODE_DIR/"

if [[ -f "$REPO_ROOT/nginx-example.conf" ]]; then
  cp -a "$REPO_ROOT/nginx-example.conf" "$APP_CODE_DIR/" || true
fi

chown -R root:root "$APP_DIR"
chown -R "$APP_USER:$APP_USER" "$APP_CODE_DIR"

echo "==> Creating virtualenv and installing Python dependencies"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_CODE_DIR/requirements.txt"

echo "==> Installing systemd unit"
cp -a "$SYSTEMD_UNIT_SRC" "$SYSTEMD_UNIT_DST"
systemctl daemon-reload
systemctl enable mail_api.service
systemctl restart mail_api.service

if [[ "$WITH_NGINX" == "1" ]]; then
  echo "==> Installing Nginx site template"
  NGINX_AVAIL="/etc/nginx/sites-available/mail_api.conf"
  NGINX_ENABLED="/etc/nginx/sites-enabled/mail_api.conf"

  echo "NOTE: This installer will NOT modify or remove any existing Nginx configs (e.g. /etc/nginx/sites-enabled/Transrelay.conf)."

  if [[ -e "$NGINX_AVAIL" ]]; then
    echo "WARNING: $NGINX_AVAIL already exists. Not overwriting." >&2
    echo "         A new template will be written to ${NGINX_AVAIL}.new" >&2
    cp -a "$SCRIPT_DIR/nginx-mail-api.conf.template" "${NGINX_AVAIL}.new"
  else
    cp -a "$SCRIPT_DIR/nginx-mail-api.conf.template" "$NGINX_AVAIL"
  fi

  if [[ -e "$NGINX_ENABLED" ]]; then
    echo "NOTE: $NGINX_ENABLED already exists. Not changing Nginx enablement." >&2
  else
    ln -s "$NGINX_AVAIL" "$NGINX_ENABLED"
  fi

  nginx -t
  systemctl reload nginx

  echo "NOTE: Update server_name values in $NGINX_AVAIL and add TLS if needed."
  echo "NOTE: In MAIL_API control panel, set Trusted proxy CIDRs to include your Nginx IP (e.g. 127.0.0.1/32)."
fi

echo "==> Done"
echo "Control panel: http://<server-ip>:2580/bootstrap"
echo "Receiver:       http://<server-ip>:2555/webhook/outbound-email"
