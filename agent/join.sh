#!/bin/bash
# Zarrin node installer. The panel serves this with the node's own token
# filled in; run it as root on the node:  curl -fsSL <link> | sudo bash
set -euo pipefail

PANEL_URL="__PANEL_URL__"
NODE_TOKEN="__NODE_TOKEN__"
NODE_IP="__NODE_IP__"
DIR=/opt/zarrin-agent

say() { printf '\033[1;33m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "Run as root."; exit 1; }

say "Zarrin agent for $NODE_IP"
if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker"
  curl -fsSL https://get.docker.com | sh
fi

# VPN clients are forwarded by the kernel; service ports are kept out of the
# ephemeral range (often widened to 1024-65000 on VPN servers), or a busy
# Xray can take them and the service fails to bind.
cat > /etc/sysctl.d/90-zarrin.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.ip_local_reserved_ports=1194,1701,51820-51829,62050-62059
SYSCTL
sysctl -q -p /etc/sysctl.d/90-zarrin.conf
# L2TP's PPP sessions and the IPsec policy match for its firewall rule.
printf '%s\n' ppp_generic ppp_async xt_policy > /etc/modules-load.d/zarrin.conf
for m in ppp_generic ppp_async xt_policy; do modprobe "$m" 2>/dev/null || true; done
[ -c /dev/ppp ] || mknod /dev/ppp c 108 0

say "Downloading the agent from the panel"
mkdir -p "$DIR/data"
curl -fsS -H "Authorization: Bearer $NODE_TOKEN" "$PANEL_URL/agent/v1/bundle" -o /tmp/zarrin-agent.tgz
tar xzf /tmp/zarrin-agent.tgz -C "$DIR"
rm -f /tmp/zarrin-agent.tgz
cd "$DIR"
( umask 077; cat > .env <<ENV
PANEL_URL=$PANEL_URL
NODE_TOKEN=$NODE_TOKEN
PUBLIC_IP=$NODE_IP
ENV
)

# Coming from the pg-ikev2 agent: keep its Let's Encrypt account and certificate.
if [ -d /opt/pg-ikev2/data ]; then
  for d in acme certs; do
    if [ -d "/opt/pg-ikev2/data/$d" ] && [ ! -e "$DIR/data/$d" ]; then
      cp -a "/opt/pg-ikev2/data/$d" "$DIR/data/$d"
      rm -rf "$DIR/data/$d/self"
    fi
  done
fi

say "Building the agent image (a few minutes the first time)"
docker compose build -q

# Switch over with the shortest gap: the old agent stops only once the new
# image is ready.
if [ -f /opt/pg-ikev2/docker-compose.yml ] && docker ps --format '{{.Names}}' | grep -qx pg-ikev2; then
  say "Stopping the old pg-ikev2 agent"
  (cd /opt/pg-ikev2 && docker compose down)
  [ -f /opt/pg-ikev2/data/pending.json ] && cp /opt/pg-ikev2/data/pending.json "$DIR/data/legacy-pending.json"
  # Keep it from coming back on reboot; the directory stays as a backup.
  mv /opt/pg-ikev2/docker-compose.yml /opt/pg-ikev2/docker-compose.yml.replaced-by-zarrin
fi

say "Starting"
docker compose up -d
sleep 8
docker logs --tail 15 zarrin-agent 2>&1 || true
echo
say "Done. This node now shows up in the Zarrin panel."
