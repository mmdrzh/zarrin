#!/bin/bash
# Installs the Zarrin panel next to an existing PasarGuard panel.
#
#   git clone git@github.com:mmdrzh/zarrin.git /opt/zarrin
#   sudo /opt/zarrin/install.sh
#
# Settings can be given as environment variables to skip the questions:
#   ZARRIN_DOMAIN, ZARRIN_PORT, ZARRIN_ADMIN, ACME_EMAIL, PASARGUARD_HOST_DIR
set -euo pipefail

DIR=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
cd "$DIR"
say() { printf '\033[1;33m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*"; exit 1; }
[ "$(id -u)" = 0 ] || die "Run as root (sudo)."
command -v docker >/dev/null || die "Docker is not installed (PasarGuard should have installed it)."

PG_DIR=${PASARGUARD_HOST_DIR:-/opt/pasarguard}
[ -f "$PG_DIR/.env" ] || die "PasarGuard not found in $PG_DIR (set PASARGUARD_HOST_DIR)."
# A key missing from PasarGuard's .env (a default install has no SUBSCRIPTION_PATH
# or SSL keys) must read as empty, not stop the script under pipefail.
pg_env() { { grep -E "^\s*$1\s*=" "$PG_DIR/.env" || true; } | head -1 | cut -d= -f2- | sed -e 's/^ *//' -e 's/ *$//' -e 's/^"//' -e 's/"$//'; }

# ---------------------------------------------------------------- PasarGuard
DB_URL=$(pg_env SQLALCHEMY_DATABASE_URL)
case "$DB_URL" in postgresql*) ;; *) die "Zarrin needs PasarGuard on PostgreSQL/TimescaleDB (found: ${DB_URL%%:*})." ;; esac
DB_USER=$(pg_env DB_USER); DB_PASSWORD=$(pg_env DB_PASSWORD); DB_NAME=$(pg_env DB_NAME)
if [ -z "$DB_USER" ] || [ -z "$DB_PASSWORD" ]; then
  # postgresql+asyncpg://user:pass@host:port/db
  rest=${DB_URL#*://}; creds=${rest%%@*}; DB_USER=${creds%%:*}; DB_PASSWORD=${creds#*:}; DB_NAME=${rest##*/}
fi
DBC=$(docker ps --filter "label=com.docker.compose.project.working_dir=$PG_DIR" --format '{{.Names}} {{.Image}}' | awk '/timescale|postgres/{print $1; exit}')
[ -n "$DBC" ] || die "PasarGuard's database container is not running."
DB_PORT=$(docker port "$DBC" 5432/tcp 2>/dev/null | { grep -oE '127\.0\.0\.1:[0-9]+' || true; } | head -1 | cut -d: -f2)
[ -n "$DB_PORT" ] || die "PasarGuard's database is not published on 127.0.0.1 (needed by Zarrin)."
PG_PORT=$(pg_env UVICORN_PORT); PG_PORT=${PG_PORT:-8000}
SUB_PATH=$(pg_env SUBSCRIPTION_PATH); SUB_PATH=${SUB_PATH:-sub}
SCHEME=https; [ -z "$(pg_env UVICORN_SSL_CERTFILE)" ] && SCHEME=http

# ------------------------------------------------------------------ questions
ask() {  # ask VAR "question" default
  local var=$1 q=$2 def=${3:-}
  if [ -z "${!var:-}" ]; then
    if [ -t 0 ] || [ -e /dev/tty ]; then
      read -r -p "$q${def:+ [$def]}: " val </dev/tty || true
      printf -v "$var" '%s' "${val:-$def}"
    else
      printf -v "$var" '%s' "$def"
    fi
  fi
}

if [ -f .env ]; then
  say "Existing .env found; keeping its settings (delete it to start over)."
else
  RAND_PORT=$(shuf -i 20000-59999 -n 1)
  ask ZARRIN_DOMAIN "Panel domain (an A record pointing to this server)" ""
  [ -n "$ZARRIN_DOMAIN" ] || die "A domain is required."
  ask ZARRIN_PORT "Panel port" "$RAND_PORT"
  ask ACME_EMAIL "E-mail for Let's Encrypt (optional)" ""
  ROLE_PW=$(openssl rand -hex 24)
  LEGACY_LINES=""
  if [ -f /opt/pg-ikev2-bridge/.env ]; then
    tls_cert=$(grep -E '^TLS_CERT=' /opt/pg-ikev2-bridge/.env | cut -d= -f2- | sed 's#^/certs#/pasarguard-data/certs#')
    tls_key=$(grep -E '^TLS_KEY=' /opt/pg-ikev2-bridge/.env | cut -d= -f2- | sed 's#^/certs#/pasarguard-data/certs#')
    legacy_port=$(grep -E '^LISTEN_PORT=' /opt/pg-ikev2-bridge/.env | cut -d= -f2-); legacy_port=${legacy_port:-62060}
    LEGACY_LINES="LEGACY_PORT=$legacy_port
LEGACY_TLS_CERT=$tls_cert
LEGACY_TLS_KEY=$tls_key"
  fi
  umask 077
  cat > .env <<ENV
# Zarrin panel settings. Secrets: keep this file private (chmod 600).
ZARRIN_DOMAIN=$ZARRIN_DOMAIN
ZARRIN_PORT=$ZARRIN_PORT
ZARRIN_SECRET=$(openssl rand -hex 32)
ACME_EMAIL=$ACME_EMAIL

PG_DSN=postgresql://zarrin:$ROLE_PW@127.0.0.1:$DB_PORT/$DB_NAME
PG_OWNER_DSN=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1:$DB_PORT/$DB_NAME
PASARGUARD_API=$SCHEME://127.0.0.1:$PG_PORT
PASARGUARD_SUB_URL=$SCHEME://127.0.0.1:$PG_PORT/$SUB_PATH
PASARGUARD_HOST_DIR=$PG_DIR
PASARGUARD_HOST_DATA=/var/lib/pasarguard
$LEGACY_LINES
ENV
  umask 022
fi
chmod 600 .env
mkdir -p data && chmod 700 data
set -a; . ./.env; set +a

# ---------------------------------------------------------------------- build
say "Building the Zarrin image (a few minutes the first time)"
docker compose build -q

say "Creating the least-privilege database role"
docker compose run --rm --no-deps zarrin python -m zarrin.cli grant

if [ -f /opt/pg-ikev2-bridge/.env ] && [ ! -f data/.legacy-imported ]; then
  say "Taking over the nodes of the pg-ikev2 bridge"
  docker compose run --rm --no-deps -v /opt/pg-ikev2-bridge:/legacy:ro zarrin python -m zarrin.cli import-legacy /legacy/.env
  touch data/.legacy-imported
fi

ADMIN_OUT=""
if [ ! -f data/.admin-created ]; then
  ask ZARRIN_ADMIN "Admin username" "admin"
  ADMIN_OUT=$(docker compose run --rm --no-deps zarrin python -m zarrin.cli admin "$ZARRIN_ADMIN")
  touch data/.admin-created
fi

if [ -f /opt/pg-ikev2-bridge/docker-compose.yml ] && docker ps --format '{{.Names}}' | grep -qx pg-ikev2-bridge; then
  say "Stopping the pg-ikev2 bridge (Zarrin serves its API on the same port)"
  (cd /opt/pg-ikev2-bridge && docker compose down)
  mv /opt/pg-ikev2-bridge/docker-compose.yml /opt/pg-ikev2-bridge/docker-compose.yml.replaced-by-zarrin
fi

say "Starting"
docker compose up -d
ln -sf "$DIR/zarrin.sh" /usr/local/bin/zarrin
chmod +x "$DIR/zarrin.sh" "$DIR/panel/subpage/install.sh"
"$DIR/zarrin.sh" install-units

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$ZARRIN_PORT/tcp" >/dev/null && say "ufw: opened $ZARRIN_PORT/tcp"
fi
if [ -f /etc/tala-fw.conf ] && ! grep -q "$ZARRIN_PORT" /etc/tala-fw.conf; then
  sed -i "s/^PANEL_TCP=\"\(.*\)\"/PANEL_TCP=\"\1 $ZARRIN_PORT\"/" /etc/tala-fw.conf && systemctl restart tala-fw || true
fi

echo
say "Zarrin is up: https://$ZARRIN_DOMAIN:$ZARRIN_PORT"
if [ -n "$ADMIN_OUT" ]; then
  echo "$ADMIN_OUT" | grep -E '^(USERNAME|PASSWORD)='
  echo "Save this password now; it is not shown again. Turn on 2FA after the first login."
fi
echo "The certificate is requested from Let's Encrypt in the background (port 80 must be reachable)."
