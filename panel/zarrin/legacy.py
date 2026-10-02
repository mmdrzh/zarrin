"""The old pg-ikev2 bridge API, so nodes still running the pg-ikev2 agent keep
working until they are moved to the Zarrin agent, plus the Tifusi app's
/sub/<hex token> endpoint (served on both ports)."""

import base64
import binascii

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from . import config
from .api_agent import CHAIN_FILE, agent_cert, agent_peers, node_from_request, record_usage
from .pg import password_for, pg
from .runtime import runtime
from .store import store

sub_router = APIRouter()


def app_trust_anchor() -> str | None:
    """PEM the Tifusi app pins for IKEv2: ISRG Root X1 and the root it signed.

    The app pins the issuer of the first non-CA certificate it is given, or of
    the first one when all are CAs. Handing it [cert issued by the root, root]
    makes it pin the root instead of an intermediate that differs per node."""
    if not CHAIN_FILE.exists():
        return None
    certs = x509.load_pem_x509_certificates(CHAIN_FILE.read_bytes())
    root = next((c for c in certs if c.issuer == c.subject), None)
    child = next((c for c in certs if root is not None and c.issuer == root.subject and c is not root), None)
    if root is None or child is None:
        return None
    return (child.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)).decode()


@sub_router.get("/sub/{secret}")
@sub_router.get("/sub/{secret}/app.json")
async def app_sub(secret: str, request: Request):
    """Tifusi VPN's app.json for a PasarGuard user: IKEv2 plus the panel's own links.

    The path carries the PasarGuard subscription token hex-encoded. The token is
    checked by asking PasarGuard for that subscription; nothing is served unless
    PasarGuard accepts it."""
    if not (16 <= len(secret) <= 400) or any(c not in "0123456789abcdef" for c in secret):
        raise HTTPException(404)
    try:
        token = binascii.unhexlify(secret).decode()
    except (binascii.Error, UnicodeDecodeError):
        raise HTTPException(404)
    if not all(c.isalnum() or c in "._-" for c in token) or not config.PASARGUARD_SUB_URL:
        raise HTTPException(404)
    async with httpx.AsyncClient(verify=False, timeout=20) as http:
        r = await http.get(f"{config.PASARGUARD_SUB_URL}/{token}",
                           headers={"User-Agent": "v2rayNG/1.9.0", "Accept": "*/*"})
    if r.status_code != 200:
        raise HTTPException(404)
    body, userinfo = r.text, r.headers.get("Subscription-Userinfo", "")
    if not request.url.path.endswith("/app.json"):
        return PlainTextResponse(body, headers={"Subscription-Userinfo": userinfo})
    # PasarGuard's token starts with base64url("<version>,<user id>,<issued>").
    try:
        head = token.split(".")[0]
        user_id = int(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)).decode().split(",")[1])
    except (ValueError, IndexError, binascii.Error, UnicodeDecodeError):
        raise HTTPException(404)
    u = await pg.user_by_id(user_id)
    if u is None:
        raise HTTPException(404)
    text = body.strip()
    if "://" not in text:
        try:
            text = base64.b64decode(text + "=" * (-len(text) % 4)).decode()
        except (binascii.Error, UnicodeDecodeError):
            pass
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    ikev2 = []
    pw = password_for(u["uuid"])
    domain = await store.get("ikev2_domain")
    if pw and domain:
        cfg = {"server": domain, "remote_id": domain, "username": u["username"], "password": pw, "remark": "IKEv2"}
        anchor = app_trust_anchor()
        if anchor:
            cfg["certificate"] = anchor
        ikev2.append(cfg)
    return JSONResponse({
        "username": u["username"],
        "status": u["status"],
        "expire": int(u["expire"].timestamp()) if u["expire"] else None,
        "used_traffic": u["used_traffic"] or 0,
        "data_limit": u["data_limit"] or None,
        "ikev2": ikev2,
        "vless": [ln for ln in lines if ln.lower().startswith("vless://")],
        "hysteria2": [ln for ln in lines if ln.lower().startswith(("hysteria2://", "hy2://"))],
    })


def legacy_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/v1/users")
    async def users(request: Request):
        await node_from_request(request)
        _, body, etag = await runtime.users()
        if request.headers.get("If-None-Match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return Response(content=body, media_type="application/json", headers={"ETag": etag})

    @app.post("/v1/usage")
    async def usage(request: Request):
        node = await node_from_request(request)
        data = await request.json()
        return await record_usage(node, "legacy-" + str(data["batch_id"]), data.get("items", {}))

    app.add_api_route("/v1/peers", agent_peers, methods=["GET"])
    app.add_api_route("/v1/cert", agent_cert, methods=["POST"])

    @app.get("/health")
    async def health():
        ok = await pg.ping()
        return PlainTextResponse("ok" if ok else "db down", status_code=200 if ok else 503)

    app.include_router(sub_router)
    return app
