#!/bin/bash
# Zarrin host command (installed as /usr/local/bin/zarrin).
#
#   zarrin status            containers and panel address
#   zarrin logs [N]          last N log lines (default 100), then follow
#   zarrin restart           restart the panel
#   zarrin update            git pull + rebuild + restart (PasarGuard untouched)
#   zarrin admin <user>      create an admin or reset its password (turns 2FA off)
#   zarrin subpage [--remove]  add/remove the IKEv2 card in PasarGuard's subscription page
#   zarrin restore-run       run a restore requested from the panel (used by systemd)
set -euo pipefail

DIR=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
cd "$DIR"
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"

env_get() { grep -E "^$1=" "$DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//'; }
compose() { docker compose -f "$DIR/docker-compose.yml" "$@"; }

cmd_status() {
  compose ps
  echo
  echo "Panel: https://$(env_get ZARRIN_DOMAIN):$(env_get ZARRIN_PORT)"
}

cmd_update() {
  echo "==> git pull"
  # As the checkout's owner, whose deploy key can reach the private repository.
  sudo -u "$(stat -c %U "$DIR/.git")" git -C "$DIR" pull --ff-only
  echo "==> building"
  compose build -q
  compose up -d
  install_units
  echo "==> done"
}

cmd_admin() {
  [ -n "${1:-}" ] || { echo "usage: zarrin admin <username>"; exit 1; }
  compose exec -T zarrin python -m zarrin.cli admin "$1"
}

install_units() {
  cat > /etc/systemd/system/zarrin-restore.path <<UNIT
[Unit]
Description=Zarrin: watch for restore requests from the panel

[Path]
PathExists=$DIR/data/restore/request.json

[Install]
WantedBy=multi-user.target
UNIT
  cat > /etc/systemd/system/zarrin-restore.service <<UNIT
[Unit]
Description=Zarrin: restore a backup requested from the panel

[Service]
Type=oneshot
ExecStart=$DIR/zarrin.sh restore-run
UNIT
  systemctl daemon-reload
  systemctl enable --now zarrin-restore.path >/dev/null 2>&1
}

# ------------------------------------------------------------------ restore

STATUS="$DIR/data/restore/status.json"
LOGS=()
status() {  # status <state> [message]
  local state=$1; shift || true
  [ $# -gt 0 ] && LOGS+=("$(date '+%H:%M:%S') $*")
  printf '%s\n' "${LOGS[@]}" | python3 -c '
import json, sys, time
print(json.dumps({"state": sys.argv[1], "at": int(time.time()), "log": sys.stdin.read().splitlines()}, ensure_ascii=False))
' "$state" > "$STATUS.tmp" && mv "$STATUS.tmp" "$STATUS"
}

cmd_restore_run() {
  local req="$DIR/data/restore/request.json"
  [ -f "$req" ] || exit 0
  local work="$DIR/data/restore/work"
  mv "$req" "$DIR/data/restore/request.running.json"
  req="$DIR/data/restore/request.running.json"
  trap 'status failed "خطا: ریستور متوقف شد (جزئیات: journalctl -u zarrin-restore)"; compose_pg up -d >/dev/null 2>&1 || true; rm -rf "$work"' ERR

  local file pg zr
  file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' "$req")
  pg=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["pasarguard"]))' "$req")
  zr=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["zarrin"]))' "$req")
  case "$file" in *..*|/*) status failed "مسیر فایل نامعتبر"; exit 1;; esac
  local archive="$DIR/data/$file"
  status running "شروع ریستور از $(basename "$archive")"

  rm -rf "$work"; mkdir -p "$work"
  tar -xzf "$archive" -C "$work" manifest.json $( [ "$pg" = 1 ] && echo pasarguard.dump ) $( [ "$zr" = 1 ] && echo zarrin.db )
  local ts; ts=$(date +%Y%m%d%H%M%S)

  if [ "$pg" = 1 ]; then restore_pasarguard "$work/pasarguard.dump" "$ts"; fi
  if [ "$zr" = 1 ]; then
    status running "ریستور اطلاعات زرین..."
    compose stop zarrin
    cp -a "$DIR/data/zarrin.db" "$DIR/data/zarrin.db.before-restore-$ts" 2>/dev/null || true
    rm -f "$DIR/data/zarrin.db-wal" "$DIR/data/zarrin.db-shm"
    install -m 600 "$work/zarrin.db" "$DIR/data/zarrin.db"
    compose start zarrin
  fi
  rm -rf "$work"
  rm -f "$req"
  trap - ERR
  status done "ریستور با موفقیت انجام شد ✅"
}

PG_DIR=""
compose_pg() { docker compose --project-directory "$PG_DIR" -f "$PG_DIR/docker-compose.yml" "$@"; }

restore_pasarguard() {
  local dump=$1 ts=$2
  PG_DIR=$(env_get PASARGUARD_HOST_DIR); PG_DIR=${PG_DIR:-/opt/pasarguard}
  local db_user db_name dbc
  db_user=$(grep -E '^DB_USER' "$PG_DIR/.env" | head -1 | cut -d= -f2- | tr -d ' "')
  db_name=$(grep -E '^DB_NAME' "$PG_DIR/.env" | head -1 | cut -d= -f2- | tr -d ' "')
  dbc=$(docker ps --filter "label=com.docker.compose.project.working_dir=$PG_DIR" --format '{{.Names}} {{.Image}}' | awk '/timescale|postgres/{print $1; exit}')
  [ -n "$dbc" ] && [ -n "$db_user" ] && [ -n "$db_name" ] || { status failed "دیتابیس پاسارگاد پیدا نشد"; exit 1; }
  local psql=(docker exec -i "$dbc" psql -v ON_ERROR_STOP=1 -U "$db_user" -qAt)
  local tmp=zarrin_restore_tmp

  status running "بکاپ ایمنی از دیتابیس فعلی..."
  mkdir -p "$DIR/data/backups"
  docker exec "$dbc" pg_dump -U "$db_user" -Fc "$db_name" > "$DIR/data/backups/safety-before-restore-$ts.dump"
  chmod 600 "$DIR/data/backups/safety-before-restore-$ts.dump"

  status running "بازگردانی در یک دیتابیس موقت (پاسارگاد هنوز روشن است)..."
  docker cp "$dump" "$dbc:/tmp/zarrin-restore.dump"
  "${psql[@]}" -d postgres -c "DROP DATABASE IF EXISTS $tmp" -c "CREATE DATABASE $tmp OWNER \"$db_user\""
  local has_ts
  has_ts=$("${psql[@]}" -d postgres -c "SELECT count(*) FROM pg_available_extensions WHERE name='timescaledb'")
  if [ "$has_ts" = 1 ]; then
    "${psql[@]}" -d "$tmp" -c "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()" >/dev/null
  fi
  docker exec "$dbc" pg_restore -U "$db_user" -d "$tmp" --no-owner --no-privileges -j 4 /tmp/zarrin-restore.dump \
    > "$DIR/data/restore/pg_restore.log" 2>&1 || true
  [ "$has_ts" = 1 ] && "${psql[@]}" -d "$tmp" -c "SELECT timescaledb_post_restore()" >/dev/null
  docker exec "$dbc" rm -f /tmp/zarrin-restore.dump
  local users
  users=$("${psql[@]}" -d "$tmp" -c "SELECT count(*) FROM users" 2>/dev/null || echo "")
  if ! [[ "$users" =~ ^[0-9]+$ ]]; then
    status failed "بکاپ درست بازگردانی نشد (جدول users نیست). دیتابیس فعلی دست نخورد. لاگ: data/restore/pg_restore.log"
    "${psql[@]}" -d postgres -c "DROP DATABASE IF EXISTS $tmp" || true
    exit 1
  fi
  status running "بکاپ سالم است: $users کاربر. جایگزینی دیتابیس (پنل پاسارگاد چند لحظه خاموش می‌شود)..."

  local services
  services=$(compose_pg config --services | grep -vE 'timescale|postgres|^db$|pgadmin' | tr '\n' ' ')
  compose_pg stop $services
  local old="${db_name}_before_restore_$ts"
  "${psql[@]}" -d postgres \
    -c "ALTER DATABASE \"$db_name\" ALLOW_CONNECTIONS false" \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$db_name' AND pid <> pg_backend_pid()" \
    -c "ALTER DATABASE \"$db_name\" RENAME TO \"$old\"" \
    -c "ALTER DATABASE $tmp RENAME TO \"$db_name\"" >/dev/null
  compose_pg start $services
  status running "دسترسی زرین روی دیتابیس جدید..."
  sleep 3
  compose exec -T zarrin python -m zarrin.cli grant >/dev/null || true
  compose restart zarrin >/dev/null
  # Keep only the newest pre-restore copy.
  "${psql[@]}" -d postgres -c "SELECT datname FROM pg_database WHERE datname LIKE '${db_name}_before_restore_%' ORDER BY datname DESC OFFSET 1" |
    while read -r name; do [ -n "$name" ] && "${psql[@]}" -d postgres -c "DROP DATABASE \"$name\"" || true; done
  status running "دیتابیس قبلی با نام $old نگه داشته شد."
}

cmd_subpage() {
  "$DIR/panel/subpage/install.sh" "$@"
}

case "${1:-status}" in
  status) cmd_status ;;
  logs) compose logs --tail "${2:-100}" -f ;;
  restart) compose restart ;;
  update) cmd_update ;;
  admin) shift; cmd_admin "$@" ;;
  subpage) shift; cmd_subpage "$@" ;;
  restore-run) cmd_restore_run ;;
  install-units) install_units ;;
  *) sed -n '2,11p' "$0"; exit 1 ;;
esac
