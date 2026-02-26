#!/usr/bin/env bash
set -euo pipefail

# Ubuntu HAProxy installer for Translife cluster
# - Installs haproxy + cluster scanner
# - Generates HAProxy config from discovered backends in 10.0.50.0/24
# - Reloads HAProxy automatically via systemd timer

ENV_FILE="/etc/translife-haproxy.env"
STATE_DIR="/var/lib/translife-haproxy"
BACKENDS_CFG="/etc/haproxy/translife-backends.cfg"
CLUSTER_BIN="/usr/local/sbin/translife-cluster"

usage() {
  cat <<EOF
Usage: install.sh

This installer configures HAProxy on Ubuntu to load-balance a Translife cluster.

Defaults (editable in $ENV_FILE after install):
  TRANS_BIND_IP=192.168.250.201
  TRANS_BACKEND_NET=10.0.50.0/24
  TRANS_BACKEND_PORT=2555
  TRANS_FRONTEND_PORTS=2555
  TRANS_HEALTH_PATH=/healthz
  TRANS_SCAN_INTERVAL_SECONDS=20

EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root (or with sudo)" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: apt-get not found (this script targets Ubuntu/Debian)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "==> Installing packages"
apt-get update
apt-get install -y haproxy python3

mkdir -p "$STATE_DIR"
chmod 0750 "$STATE_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> Writing default environment file to $ENV_FILE"
  cat >"$ENV_FILE" <<'EOF'
# Translife HAProxy + cluster discovery configuration
TRANS_BIND_IP=192.168.250.201
TRANS_BACKEND_NET=10.0.50.0/24
TRANS_BACKEND_PORT=2555
TRANS_FRONTEND_PORTS=2555
TRANS_HEALTH_PATH=/healthz
TRANS_SCAN_TIMEOUT_SECONDS=1.0
TRANS_SCAN_CONCURRENCY=128
TRANS_SCAN_INTERVAL_SECONDS=20
TRANS_STATS_BIND=127.0.0.1
TRANS_STATS_PORT=8404
TRANS_STATS_USER=admin
TRANS_STATS_PASS=change-me
EOF
  chmod 0640 "$ENV_FILE"
fi

echo "==> Installing cluster scanner to $CLUSTER_BIN"
install -m 0755 "$(dirname "$0")/translife_cluster.py" "$CLUSTER_BIN"

echo "==> Installing systemd units"
install -m 0644 "$(dirname "$0")/translife-cluster.service" /etc/systemd/system/translife-cluster.service
install -m 0644 "$(dirname "$0")/translife-cluster.timer" /etc/systemd/system/translife-cluster.timer

systemctl daemon-reload

echo "==> Writing HAProxy main configuration"
cat >/etc/haproxy/haproxy.cfg <<'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client  60s
    timeout server  60s

# Generated backends and frontends are written to:
#   /etc/haproxy/translife-backends.cfg
# The cluster service updates that file and reloads HAProxy.

EOF

# Ensure file exists so haproxy can start even before first scan
if [[ ! -f "$BACKENDS_CFG" ]]; then
  cat >"$BACKENDS_CFG" <<'EOF'
# Placeholder generated file. The translife-cluster service will replace this.
frontend fe_translife_placeholder
    bind 127.0.0.1:65535
    default_backend be_translife_placeholder

backend be_translife_placeholder
    http-request return status 503 content-type text/plain lf-string "no backends discovered"
EOF
fi

# Append include line after placeholder defaults
printf "\n# Include generated configuration\n" >>/etc/haproxy/haproxy.cfg
printf "include /etc/haproxy/translife-backends.cfg\n" >>/etc/haproxy/haproxy.cfg

echo "==> Enabling services"
systemctl enable haproxy
systemctl restart haproxy

systemctl enable translife-cluster.timer
systemctl start translife-cluster.timer

echo "==> Running one discovery pass"
"$CLUSTER_BIN" --once || true

echo "==> Done"
echo "- Edit: $ENV_FILE"
echo "- HAProxy config: /etc/haproxy/haproxy.cfg"
echo "- Generated config: /etc/haproxy/translife-backends.cfg"
echo "- Cluster state: $STATE_DIR/hosts.json"
echo "- Check status: systemctl status haproxy translife-cluster.timer"
