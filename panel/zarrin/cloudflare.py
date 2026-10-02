"""Cloudflare API: credential check now; DNS records for nodes later.

A scoped API Token (Zone → DNS → Edit) is what Zarrin asks for. A Global API
Key also works (it then needs the account e-mail too) but is discouraged: it
controls the whole Cloudflare account, and it would sit on this server and in
every backup.
"""

import re

import httpx

from .store import store

API = "https://api.cloudflare.com/client/v4"


def kind_of(secret: str) -> str:
    if re.fullmatch(r"[0-9a-f]{37}", secret or ""):
        return "global_key"
    return "token" if secret else ""


async def auth_headers() -> dict:
    secret = (await store.get("cloudflare_token") or "").strip()
    if kind_of(secret) == "global_key":
        email = (await store.get("cloudflare_email") or "").strip()
        return {"X-Auth-Email": email, "X-Auth-Key": secret}
    return {"Authorization": f"Bearer {secret}"} if secret else {}


async def lego_env() -> dict:
    """Environment for `lego --dns cloudflare`, or {} when not configured."""
    secret = (await store.get("cloudflare_token") or "").strip()
    if not secret:
        return {}
    if kind_of(secret) == "global_key":
        email = (await store.get("cloudflare_email") or "").strip()
        return {"CF_API_EMAIL": email, "CF_API_KEY": secret} if email else {}
    return {"CF_DNS_API_TOKEN": secret}


async def check() -> dict:
    """What the saved credential is and which zones it can see."""
    secret = (await store.get("cloudflare_token") or "").strip()
    kind = kind_of(secret)
    if not kind:
        return {"ok": False, "kind": "", "error": "توکن کلودفلر ثبت نشده"}
    headers = await auth_headers()
    if kind == "global_key" and not headers.get("X-Auth-Email"):
        return {"ok": False, "kind": kind, "error": "برای Global API Key ایمیل حساب کلودفلر هم لازم است"}
    async with httpx.AsyncClient(timeout=20) as http:
        if kind == "token":
            r = await http.get(f"{API}/user/tokens/verify", headers=headers)
            if r.status_code != 200 or not r.json().get("success"):
                return {"ok": False, "kind": kind, "error": _error(r)}
        r = await http.get(f"{API}/zones", headers=headers, params={"per_page": 50})
        if r.status_code != 200 or not r.json().get("success"):
            return {"ok": False, "kind": kind, "error": _error(r)}
        zones = [z["name"] for z in r.json()["result"]]
    return {"ok": True, "kind": kind, "zones": zones}


def _error(r: httpx.Response) -> str:
    try:
        errors = r.json().get("errors") or []
        return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errors) or f"HTTP {r.status_code}"
    except ValueError:
        return f"HTTP {r.status_code}"
