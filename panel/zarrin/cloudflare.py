"""Cloudflare API, through any number of scoped API Tokens (one per account).

Each saved token is checked when it is added and remembers which zones it
can see, so the right token is picked for a domain (the panel's own
certificate, the shared VPN domain's records). Global API Keys are refused:
they control a whole account, and they would sit on this server and in every
backup, while Zarrin only needs to edit DNS.
"""

import re
import secrets
import time

import httpx

from .store import store

API = "https://api.cloudflare.com/client/v4"
ZONES_TTL = 600


class CloudflareError(Exception):
    pass


def is_global_key(secret: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{37}", secret or ""))


def _error(r: httpx.Response) -> str:
    try:
        errors = r.json().get("errors") or []
        return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or f"HTTP {r.status_code}"
    except ValueError:
        return f"HTTP {r.status_code}"


async def tokens() -> list[dict]:
    """[{id, label, token, zones, checked_at}]; an older single token setting
    is moved into the list the first time."""
    items = await store.get("cloudflare_tokens") or []
    legacy = (await store.get("cloudflare_token") or "").strip()
    if legacy:
        if not is_global_key(legacy) and not any(t["token"] == legacy for t in items):
            items.append({"id": secrets.token_hex(4), "label": "Cloudflare", "token": legacy, "zones": [], "checked_at": 0})
        await store.set("cloudflare_tokens", items)
        await store.set("cloudflare_token", "")
    return items


async def inspect(token: str) -> list[str]:
    """Verifies a token and returns the zones it can see."""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.get(f"{API}/user/tokens/verify", headers=headers)
        if r.status_code != 200 or not r.json().get("success"):
            raise CloudflareError(_error(r))
        zones, page = [], 1
        while True:
            r = await http.get(f"{API}/zones", headers=headers, params={"per_page": 50, "page": page})
            if r.status_code != 200 or not r.json().get("success"):
                raise CloudflareError(_error(r))
            data = r.json()
            zones += [z["name"] for z in data["result"]]
            if page >= (data.get("result_info") or {}).get("total_pages", 1):
                break
            page += 1
    return sorted(zones)


async def add(label: str, token: str) -> dict:
    token = token.strip()
    if is_global_key(token):
        raise CloudflareError("این Global API Key است. لطفاً یک API Token با قالب «Edit zone DNS» بسازید.")
    items = await tokens()
    if any(t["token"] == token for t in items):
        raise CloudflareError("این توکن قبلاً ثبت شده")
    zones = await inspect(token)
    item = {"id": secrets.token_hex(4), "label": label.strip()[:64] or "Cloudflare", "token": token,
            "zones": zones, "checked_at": int(time.time())}
    items.append(item)
    await store.set("cloudflare_tokens", items)
    return item


async def remove(token_id: str) -> None:
    await store.set("cloudflare_tokens", [t for t in await tokens() if t["id"] != token_id])


async def refresh() -> list[dict]:
    """Re-checks every token; returns them with ok/error."""
    items = await tokens()
    out = []
    for t in items:
        try:
            t["zones"] = await inspect(t["token"])
            t["checked_at"] = int(time.time())
            out.append({**t, "ok": True})
        except (CloudflareError, httpx.HTTPError) as exc:
            out.append({**t, "ok": False, "error": str(exc)})
    await store.set("cloudflare_tokens", items)
    return out


def zone_of(domain: str, zones: list[str]) -> str | None:
    domain = domain.lower().rstrip(".")
    matches = [z for z in zones if domain == z or domain.endswith("." + z)]
    return max(matches, key=len) if matches else None


async def token_for(domain: str) -> str | None:
    items = await tokens()
    stale = [t for t in items if time.time() - (t.get("checked_at") or 0) > ZONES_TTL]
    if stale and not any(zone_of(domain, t["zones"]) for t in items):
        await refresh()
        items = await tokens()
    for t in items:
        if zone_of(domain, t["zones"]):
            return t["token"]
    return None


async def lego_env(domain: str) -> dict:
    """Environment for `lego --dns cloudflare` for this domain, or {}."""
    token = await token_for(domain)
    return {"CF_DNS_API_TOKEN": token} if token else {}


def public(t: dict) -> dict:
    tok = t["token"]
    return {"id": t["id"], "label": t["label"], "token": tok[:4] + "…" + tok[-4:], "zones": t.get("zones", []),
            "checked_at": t.get("checked_at")}
