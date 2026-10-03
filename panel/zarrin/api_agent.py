"""What node agents talk to, and the one-line node installer.

Every node has its own token (only its SHA-256 is stored), and a token works
only from the node's own IP address.
"""

import io
import json
import logging
import tarfile
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from . import config
from . import ovpn
from .auth import client_ip, new_token, sha256
from .pg import pg
from .runtime import runtime
from .store import store

log = logging.getLogger("zarrin.agent")
router = APIRouter()

CHAIN_FILE = config.DATA / "chain.pem"
DEFAULT_POOLS = {"ikev2": "10.66.0.0/16", "l2tp": "10.67.0.0/16"}


async def node_from_request(request: Request) -> dict:
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    node = await store.fetchone("SELECT * FROM nodes WHERE token_hash = ?", sha256(token)) if token else None
    if node is None:
        raise HTTPException(401)
    if client_ip(request) != node["ip"]:
        log.warning("token of node %s (%s) used from %s", node["id"], node["ip"], client_ip(request))
        raise HTTPException(403)
    now = int(time.time())
    if not node["last_seen"] or now - node["last_seen"] >= 10:
        await store.execute("UPDATE nodes SET last_seen = ? WHERE id = ?", now, node["id"])
    return node


async def pg_node_id(node: dict) -> int | None:
    """The PasarGuard node this node's traffic is recorded under, matched by IP
    the first time and remembered."""
    if node["pg_node_id"] is not None:
        return node["pg_node_id"]
    for n in await pg.nodes():
        if n["address"] == node["ip"]:
            await store.execute("UPDATE nodes SET pg_node_id = ? WHERE id = ?", n["id"], node["id"])
            return n["id"]
    return None


async def record_usage(node: dict, batch_id: str, items: dict) -> dict:
    key = f"{node['id']}:{batch_id}"
    if await store.batch_seen(key):
        return {"ok": True, "duplicate": True}
    clean = {}
    for user, value in (items or {}).items():
        up, down = int(value[0]), int(value[1])
        if up < 0 or down < 0 or up + down > 10 ** 13:
            continue
        if up + down > 0:
            clean[str(user)] = (up, down)
    if clean:
        users, total = await pg.record_usage(await pg_node_id(node), clean)
        log.info("node %s: recorded %d users, %.1f MB", node["name"], users, total / 1e6)
    await store.mark_batch(key)
    return {"ok": True, "users": len(clean)}


async def node_config(node: dict) -> dict:
    settings = await store.all_settings()
    own = json.loads(node["settings"] or "{}")
    peers = [r["ip"] for r in await store.fetchall("SELECT ip FROM nodes WHERE id != ?", node["id"])]
    ikev2 = own.get("ikev2", {})
    l2tp = own.get("l2tp", {})
    openvpn = own.get("openvpn", {})
    udp_port, tcp_port = await ovpn.ports()
    udp_alt, tcp_alt = await ovpn.alt_ports()
    keys = await ovpn.pki()
    return {
        "node": {"id": node["id"], "name": node["name"], "ip": node["ip"]},
        "dns": settings["dns"],
        "acme_email": config.ACME_EMAIL,
        "peers": peers,
        "ikev2": {
            "enabled": ikev2.get("enabled", True),
            "server_id": settings["ikev2_domain"] or node["ip"],
            "pool": ikev2.get("pool", DEFAULT_POOLS["ikev2"]),
        },
        "l2tp": {
            # Off until turned on per node in the panel.
            "enabled": bool(l2tp.get("enabled", False)) and bool(settings["l2tp_psk"]),
            "pool": l2tp.get("pool", DEFAULT_POOLS["l2tp"]),
            "psk": settings["l2tp_psk"],
        },
        "openvpn": {
            "enabled": bool(openvpn.get("enabled", False)) and bool(udp_port or tcp_port),
            "udp_port": udp_port, "tcp_port": tcp_port, "udp_alt": udp_alt, "tcp_alt": tcp_alt,
            "pool_udp": ovpn.POOL_UDP, "pool_tcp": ovpn.POOL_TCP,
            "ca": keys["ca"], "cert": keys["cert"], "key": keys["key"], "tls_crypt": keys["tls_crypt"],
        },
    }


# --------------------------------------------------------------- agent API

@router.get("/agent/v1/config")
async def agent_config(request: Request):
    node = await node_from_request(request)
    return await node_config(node)


@router.get("/agent/v1/users")
async def agent_users(request: Request):
    await node_from_request(request)
    _, body, etag = await runtime.users()
    if request.headers.get("If-None-Match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(content=b'{"users":' + body + b"}", media_type="application/json", headers={"ETag": etag})


@router.post("/agent/v1/report")
async def agent_report(request: Request):
    """Every ~15s: who is online, pending usage, health. The reply carries any
    commands (kick a user) queued for this node."""
    node = await node_from_request(request)
    data = await request.json()
    result = {"ok": True}
    batch = data.get("batch")
    if batch and batch.get("id"):
        result["batch"] = await record_usage(node, batch["id"], batch.get("items", {}))
    sessions = []
    for s in data.get("online", [])[:20000]:
        sessions.append({
            "proto": str(s.get("proto", ""))[:16],
            "user": str(s.get("user", ""))[:128],
            "remote": str(s.get("remote", ""))[:64],
            "since": int(s.get("since") or 0),
            "up": int(s.get("up") or 0),
            "down": int(s.get("down") or 0),
            "id": str(s.get("id", ""))[:64],
        })
    runtime.set_online(node["id"], sessions, data.get("status"))
    await store.execute(
        "UPDATE nodes SET last_seen = ?, agent_version = ?, status = ? WHERE id = ?",
        int(time.time()), str(data.get("version", ""))[:32], json.dumps(data.get("status") or {}),
        node["id"],
    )
    result["commands"] = runtime.take_commands(node["id"])
    return result


@router.post("/agent/v1/cert")
async def agent_cert(request: Request):
    """A node's IKEv2 certificate chain, handed to the Tifusi app (it pins the issuer)."""
    await node_from_request(request)
    chain = (await request.body()).decode(errors="replace").strip()
    if "BEGIN CERTIFICATE" not in chain or len(chain) > 64 * 1024:
        raise HTTPException(400)
    CHAIN_FILE.write_text(chain + "\n")
    return {"ok": True}


@router.get("/agent/v1/peers")
async def agent_peers(request: Request):
    node = await node_from_request(request)
    rows = await store.fetchall("SELECT ip FROM nodes WHERE id != ?", node["id"])
    return sorted(r["ip"] for r in rows)


def agent_bundle() -> bytes:
    src = config.REPO / "agent"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(src.rglob("*")):
            if "__pycache__" in path.parts or path.suffix == ".pyc" or not path.is_file():
                continue
            tar.add(path, arcname=str(path.relative_to(src)))
    return buf.getvalue()


@router.get("/agent/v1/bundle")
async def agent_bundle_route(request: Request):
    await node_from_request(request)
    return Response(content=agent_bundle(), media_type="application/gzip")


# ------------------------------------------------------------ node install

def panel_url() -> str:
    return f"https://{config.DOMAIN}:{config.PORT}"


def join_command(token: str) -> str:
    return f"curl -fsSL {panel_url()}/join/{token} | sudo bash"


@router.get("/join/{token}", response_class=PlainTextResponse)
async def join(token: str, request: Request):
    """The script a new (or reinstalled) node runs. Fetching it registers the
    node under the address it came from and mints that node's own token."""
    row = await store.fetchone("SELECT * FROM join_tokens WHERE token_hash = ?", sha256(token))
    if row is None or row["expires_at"] < time.time():
        return PlainTextResponse("echo 'Zarrin: this install link is invalid or expired'; exit 1\n", status_code=404)
    ip = client_ip(request)
    node_token = new_token()
    if row["node_id"]:
        node = await store.fetchone("SELECT * FROM nodes WHERE id = ?", row["node_id"])
        if node is None:
            return PlainTextResponse("echo 'Zarrin: node was deleted'; exit 1\n", status_code=404)
        if node["ip"] != ip:
            return PlainTextResponse(f"echo 'Zarrin: this link is for {node['ip']}, not {ip}'; exit 1\n", status_code=403)
        await store.execute("UPDATE nodes SET token_hash = ?, legacy = 0 WHERE id = ?", sha256(node_token), node["id"])
        node_id = node["id"]
    else:
        existing = await store.fetchone("SELECT * FROM nodes WHERE ip = ?", ip)
        if existing:
            await store.execute("UPDATE nodes SET token_hash = ?, legacy = 0 WHERE id = ?", sha256(node_token), existing["id"])
            node_id = existing["id"]
        else:
            node_id = await store.execute(
                "INSERT INTO nodes (name, ip, token_hash, created_at) VALUES (?, ?, ?, ?)",
                row["name"], ip, sha256(node_token), int(time.time()),
            )
        await store.execute("UPDATE join_tokens SET node_id = ? WHERE token_hash = ?", node_id, row["token_hash"])
    await store.audit(None, ip, "node.join", f"node {node_id}")
    template = (config.REPO / "agent" / "join.sh").read_text()
    script = (template.replace("__PANEL_URL__", panel_url())
              .replace("__NODE_TOKEN__", node_token)
              .replace("__NODE_IP__", ip))
    return PlainTextResponse(script, media_type="text/x-shellscript")


async def create_join_token(name: str, node_id: int | None = None, hours: int = 24) -> str:
    token = new_token(24)
    now = int(time.time())
    await store.execute(
        "INSERT INTO join_tokens (token_hash, name, created_at, expires_at, node_id) VALUES (?, ?, ?, ?, ?)",
        sha256(token), name, now, now + hours * 3600, node_id,
    )
    return token
