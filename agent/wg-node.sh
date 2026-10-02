#!/bin/bash
# A second PasarGuard node on this server that runs only PasarGuard's own
# WireGuard core. A PasarGuard node runs one core, and the main node
# (/opt/pg-node) runs Xray, so WireGuard needs a node of its own; PasarGuard
# then handles WireGuard users, peer IPs, traffic and limits natively.
#
# Kept apart from /opt/pg-node (own directory, data, ports and container
# name), so `pg-node update` and Zarrin updates never touch each other.
#
#   wg-node.sh <public ip> [service port] [api port]
# Prints the node's certificate and API key as JSON for registering it.
set -euo pipefail

IP=${1:?usage: wg-node.sh <public ip> [service port] [api port]}
PORT=${2:-62052}
API_PORT=${3:-62053}
DIR=/opt/pg-node-wg
DATA=/var/lib/pg-node-wg

mkdir -p "$DIR" "$DATA/certs"
chmod 700 "$DATA/certs"
if [ ! -s "$DATA/certs/ssl_cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=$IP" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$IP" \
    -keyout "$DATA/certs/ssl_key.pem" -out "$DATA/certs/ssl_cert.pem" 2>/dev/null
  chmod 600 "$DATA/certs/ssl_key.pem"
fi

if [ ! -f "$DIR/.env" ]; then
  ( umask 077; cat > "$DIR/.env" <<ENV
SERVICE_PORT=$PORT
API_PORT=$API_PORT
NODE_HOST=0.0.0.0
SERVICE_PROTOCOL=grpc
SSL_CERT_FILE=$DATA/certs/ssl_cert.pem
SSL_KEY_FILE=$DATA/certs/ssl_key.pem
API_KEY=$(cat /proc/sys/kernel/random/uuid)
ENV
  )
fi

cat > "$DIR/docker-compose.yml" <<YML
# PasarGuard node for the WireGuard core, managed by Zarrin.
services:
  node-wg:
    container_name: node-wg
    image: pasarguard/node:latest
    restart: always
    network_mode: host
    cap_add: [NET_ADMIN]
    env_file: .env
    volumes:
      - $DATA:$DATA
    logging:
      options: {max-size: "20m", max-file: "3"}
YML

cd "$DIR"
docker compose pull -q
docker compose up -d >/dev/null 2>&1

python3 - "$DATA/certs/ssl_cert.pem" "$DIR/.env" "$PORT" "$API_PORT" <<'PY'
import json, sys
cert, env, port, api_port = sys.argv[1:5]
key = next(l.split("=", 1)[1].strip() for l in open(env) if l.startswith("API_KEY="))
print(json.dumps({"server_ca": open(cert).read(), "api_key": key, "port": int(port), "api_port": int(api_port)}))
PY
