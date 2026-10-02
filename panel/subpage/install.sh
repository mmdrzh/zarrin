#!/bin/sh
# Adds (or refreshes) the IKEv2 card in PasarGuard's subscription page template.
# Usage: install.sh [template]   |   install.sh --remove [template]
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
MODE=add; [ "$1" = "--remove" ] && { MODE=remove; shift; }
T=${1:-/var/lib/pasarguard/templates/subscription/index.html}
# The shared VPN domain and the L2TP key come from Zarrin's settings.
SERVER=$(docker exec zarrin python -m zarrin.cli get ikev2_domain 2>/dev/null || true)
PSK=$(docker exec zarrin python -m zarrin.cli get l2tp_psk 2>/dev/null || true)
if [ "$MODE" = add ] && { [ -z "$SERVER" ] || [ -z "$PSK" ]; }; then
  echo "Zarrin is not running or the VPN domain / L2TP key is not set"; exit 1
fi
cp "$T" "$T.bak-ikev2-$(date +%Y%m%d-%H%M%S)"
# Keep the five newest copies of the template.
ls -t "$T".bak-ikev2-* 2>/dev/null | tail -n +6 | xargs -r rm -f
python3 - "$T" "$DIR/ikev2-card.html" "$MODE" "$DIR/ikev2-head.html" "$SERVER" "$PSK" <<'PY'
import re, sys
path, card, mode, head, server, psk = sys.argv[1:7]
fill = lambda text: text.replace("__VPN_SERVER__", server).replace("__L2TP_PSK__", psk)
s = open(path, encoding="utf-8").read()
s = re.sub(r"<!-- pg-ikev2 start.*?<!-- pg-ikev2 end -->\n?", "", s, flags=re.S)
s = re.sub(r"<!-- pg-ikev2-head start.*?<!-- pg-ikev2-head end -->\n?", "", s, flags=re.S)
if mode == "add":
    snippet = fill(open(card, encoding="utf-8").read())
    # Above the page's own app, so it is the first thing a customer sees.
    i = s.find('<div id="root">')
    if i < 0:
        i = s.lower().rfind("</body>")
    s = s[:i] + snippet + s[i:] if i >= 0 else s + snippet
    # The app's IKEv2 login right after <head>, so it is found in the first few KB.
    h = re.search(r"<head[^>]*>", s, re.I)
    if h:
        s = s[:h.end()] + "\n" + fill(open(head, encoding="utf-8").read()) + s[h.end():]
open(path, "w", encoding="utf-8").write(s)
PY
# Render the new template for a real user before keeping it: a broken
# template would take every customer's subscription page down.
C=$(docker ps --format '{{.Names}}' | grep -m1 -E '^pasarguard-pasarguard-1$' || true)
if [ -n "$C" ] && ! docker exec -i -w /code "$C" python - "$(basename "$(dirname "$T")")/$(basename "$T")" <<'PY' >/dev/null 2>&1
import asyncio, sys
from sqlalchemy import select
from app.db.base import GetDB
from app.db.models import User
from app.db.crud.user import get_user
from app.models.user import SubscriptionUserResponse
from app.templates import render_template
async def m():
    async with GetDB() as db:
        name = (await db.execute(select(User.username).limit(1))).scalar_one()
        u = SubscriptionUserResponse.model_validate(await get_user(db, name))
        out = render_template(sys.argv[1], {"user": u, "links": [], "apps_data": [], "user_data": {}})
        assert len(out) > 1000
asyncio.run(m())
PY
then
  cp "$(ls -t "$T".bak-ikev2-* | head -1)" "$T"
  echo "IKEv2 card: the new template failed to render; previous one restored ($T)"; exit 1
fi
echo "IKEv2 card: $MODE done ($T)"
