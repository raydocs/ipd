#!/bin/sh
# Install the probe agent on a machine the operator already controls.
# Usage: curl -fsSL <url-you-host>/install-agent.sh | sh -s -- --hub http://127.0.0.1:8787 --key <enrol-token>
# This script does not SSH anywhere. It only writes a systemd unit on the machine where it runs.
set -eu
HUB=""
KEY=""
BIN="${BIN:-/usr/local/bin/ipd}"
while [ $# -gt 0 ]; do
  case "$1" in
    --hub) HUB="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
if [ -z "$HUB" ] || [ -z "$KEY" ]; then
  echo "need --hub and --key" >&2
  exit 2
fi
if [ ! -x "$BIN" ]; then
  echo "put the ipd binary at $BIN first (see install.sh)" >&2
  exit 2
fi
install -d -m 0755 /etc/ipd
umask 077
cat > /etc/ipd/agent.env <<EOF
IPD_SERVER=$HUB
IPD_ENROLL_TOKEN=$KEY
EOF
cat > /etc/systemd/system/ipd-agent.service <<'EOF'
[Unit]
Description=ipd probe agent
After=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/ipd/agent.env
ExecStart=/usr/local/bin/ipd agent
Restart=on-failure
MemoryMax=64M
CPUQuota=50%
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
EOF
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now ipd-agent.service
fi
echo "agent unit written for $HUB"
