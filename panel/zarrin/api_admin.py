"""The admin panel's JSON API (/api/...)."""

import json
import time

import pyotp
import segno
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import backup, certs, cloudflare, config, telegram
from .api_agent import create_join_token, join_command
from .auth import (authenticate, clear_session_cookie, client_ip, current_admin, hash_password, issue_session,
                   set_session_cookie, totp_ok, totp_uri, verify_password)
from .pg import password_for, pg
from .runtime import runtime
from .store import SECRET_KEYS, store

router = APIRouter(prefix="/api")
Admin = Depends(current_admin)


def _ts(value) -> int | None:
    return int(value.timestamp()) if value else None


# ------------------------------------------------------------------- auth

class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    code: str | None = Field(default=None, max_length=12)


@router.post("/auth/login")
async def login(body: LoginIn, request: Request):
    ip = client_ip(request)
    admin, reason = await authenticate(body.username.strip(), body.password, body.code, ip)
    if admin is None:
        if reason != "totp_required":
            await store.audit(body.username[:64], ip, "login.failed", reason)
        status = {"totp_required": 401, "too_many_attempts": 429}.get(reason, 401)
        return JSONResponse({"error": reason}, status_code=status)
    await store.audit(admin["username"], ip, "login")
    response = JSONResponse({"ok": True, "username": admin["username"]})
    set_session_cookie(response, issue_session(admin))
    return response


@router.post("/auth/logout")
async def logout():
    response = JSONResponse({"ok": True})
    clear_session_cookie(response)
    return response


@router.get("/auth/me")
async def me(admin=Admin):
    return {"username": admin["username"], "totp": bool(admin["totp_secret"]), "version": config.VERSION,
            "domain": config.DOMAIN}


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=10, max_length=256)


@router.post("/auth/password")
async def change_password(body: PasswordIn, request: Request, admin=Admin):
    if not verify_password(admin["pw_hash"], body.current):
        raise HTTPException(400, "رمز فعلی اشتباه است")
    await store.execute("UPDATE admins SET pw_hash = ?, token_version = token_version + 1 WHERE id = ?",
                        hash_password(body.new), admin["id"])
    await store.audit(admin["username"], client_ip(request), "password.change")
    fresh = await store.fetchone("SELECT * FROM admins WHERE id = ?", admin["id"])
    response = JSONResponse({"ok": True})
    set_session_cookie(response, issue_session(fresh))
    return response


@router.post("/auth/totp/setup")
async def totp_setup(admin=Admin):
    secret = pyotp.random_base32()
    await store.set(f"totp_pending:{admin['id']}", {"secret": secret, "at": int(time.time())})
    uri = totp_uri(secret, admin["username"])
    return {"secret": secret, "uri": uri, "qr": segno.make(uri, error="m").svg_inline(scale=5, border=2)}


class CodeIn(BaseModel):
    code: str = Field(max_length=12)
    password: str | None = Field(default=None, max_length=256)


@router.post("/auth/totp/enable")
async def totp_enable(body: CodeIn, request: Request, admin=Admin):
    pending = await store.get(f"totp_pending:{admin['id']}")
    if not pending or time.time() - pending["at"] > 900:
        raise HTTPException(400, "دوباره شروع کنید")
    if not totp_ok(pending["secret"], body.code):
        raise HTTPException(400, "کد اشتباه است")
    await store.execute("UPDATE admins SET totp_secret = ? WHERE id = ?", pending["secret"], admin["id"])
    await store.execute("DELETE FROM kv WHERE k = ?", f"totp_pending:{admin['id']}")
    await store.audit(admin["username"], client_ip(request), "totp.enable")
    return {"ok": True}


@router.post("/auth/totp/disable")
async def totp_disable(body: CodeIn, request: Request, admin=Admin):
    if not body.password or not verify_password(admin["pw_hash"], body.password) or not totp_ok(admin["totp_secret"], body.code):
        raise HTTPException(400, "رمز یا کد اشتباه است")
    await store.execute("UPDATE admins SET totp_secret = NULL WHERE id = ?", admin["id"])
    await store.audit(admin["username"], client_ip(request), "totp.disable")
    return {"ok": True}


# -------------------------------------------------------------- dashboard

async def _nodes_view() -> list[dict]:
    rows = await store.fetchall("SELECT * FROM nodes ORDER BY id")
    sessions = runtime.online_sessions()
    try:
        pg_nodes = {n["id"]: dict(n) for n in await pg.nodes()}
    except Exception:
        pg_nodes = {}
    out = []
    for n in rows:
        mine = [s for s in sessions if s["node_id"] == n["id"]]
        status = json.loads(n["status"] or "{}")
        pgn = pg_nodes.get(n["pg_node_id"]) if n["pg_node_id"] else None
        out.append({
            "id": n["id"], "name": n["name"], "ip": n["ip"], "legacy": bool(n["legacy"]),
            "live": runtime.node_live(n["id"]) or bool(n["last_seen"] and time.time() - n["last_seen"] < 60),
            "last_seen": n["last_seen"], "agent_version": n["agent_version"], "status": status,
            "settings": json.loads(n["settings"] or "{}"), "online": len(mine),
            "online_by_proto": _count_by(mine, "proto"),
            "pg_node": {"id": pgn["id"], "name": pgn["name"], "status": pgn["status"]} if pgn else None,
            "created_at": n["created_at"],
        })
    return out


def _count_by(items: list[dict], key: str) -> dict:
    out: dict = {}
    for item in items:
        out[item[key]] = out.get(item[key], 0) + 1
    return out


@router.get("/dashboard")
async def dashboard(admin=Admin):
    sessions = runtime.online_sessions()
    try:
        counts = await pg.user_counts()
        db_ok = True
    except Exception:
        counts, db_ok = {}, False
    return {
        "nodes": await _nodes_view(),
        "online_total": len(sessions),
        "online_users": len({s["user"] for s in sessions}),
        "online_by_proto": _count_by(sessions, "proto"),
        "users": counts,
        "db_ok": db_ok,
        "cert": certs.info(),
        "last_backup": await store.get("last_backup"),
        "last_backup_telegram": await store.get("last_backup_telegram"),
        "version": config.VERSION,
    }


# ------------------------------------------------------------------ nodes

@router.get("/nodes")
async def nodes(admin=Admin):
    return await _nodes_view()


class JoinIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


@router.post("/nodes/join")
async def node_join(body: JoinIn, request: Request, admin=Admin):
    token = await create_join_token(body.name.strip())
    await store.audit(admin["username"], client_ip(request), "node.join_link", body.name)
    return {"command": join_command(token), "expires_in_hours": 24}


@router.post("/nodes/{node_id}/reinstall")
async def node_reinstall(node_id: int, request: Request, admin=Admin):
    node = await store.fetchone("SELECT * FROM nodes WHERE id = ?", node_id)
    if node is None:
        raise HTTPException(404)
    token = await create_join_token(node["name"], node_id=node_id)
    await store.audit(admin["username"], client_ip(request), "node.reinstall_link", node["name"])
    return {"command": join_command(token), "expires_in_hours": 24}


class NodePatch(BaseModel):
    name: str | None = Field(default=None, max_length=64)
    pg_node_id: int | None = None
    clear_pg_node: bool = False
    settings: dict | None = None


@router.patch("/nodes/{node_id}")
async def node_patch(node_id: int, body: NodePatch, request: Request, admin=Admin):
    node = await store.fetchone("SELECT * FROM nodes WHERE id = ?", node_id)
    if node is None:
        raise HTTPException(404)
    if body.name:
        await store.execute("UPDATE nodes SET name = ? WHERE id = ?", body.name.strip(), node_id)
    if body.pg_node_id is not None or body.clear_pg_node:
        await store.execute("UPDATE nodes SET pg_node_id = ? WHERE id = ?", None if body.clear_pg_node else body.pg_node_id, node_id)
    if body.settings is not None:
        merged = {**json.loads(node["settings"] or "{}"), **body.settings}
        await store.execute("UPDATE nodes SET settings = ? WHERE id = ?", json.dumps(merged), node_id)
    await store.audit(admin["username"], client_ip(request), "node.update", f"{node['name']}: {body.model_dump_json()}")
    return {"ok": True}


@router.delete("/nodes/{node_id}")
async def node_delete(node_id: int, request: Request, admin=Admin):
    node = await store.fetchone("SELECT * FROM nodes WHERE id = ?", node_id)
    if node is None:
        raise HTTPException(404)
    await store.execute("DELETE FROM nodes WHERE id = ?", node_id)
    runtime.online.pop(node_id, None)
    await store.audit(admin["username"], client_ip(request), "node.delete", f"{node['name']} {node['ip']}")
    return {"ok": True, "uninstall": "cd /opt/zarrin-agent && docker compose down && cd / && rm -rf /opt/zarrin-agent"}


@router.get("/pasarguard/nodes")
async def pasarguard_nodes(admin=Admin):
    return [dict(n) for n in await pg.nodes()]


@router.get("/pasarguard/outbounds")
async def pasarguard_outbounds(admin=Admin):
    return [{k: v for k, v in o.items() if k != "config"} for o in await pg.outbounds()]


# ----------------------------------------------------------------- online

@router.get("/online")
async def online(admin=Admin):
    names = {n["id"]: n["name"] for n in await store.fetchall("SELECT id, name FROM nodes")}
    sessions = runtime.online_sessions()
    for s in sessions:
        s["node"] = names.get(s["node_id"], "?")
    sessions.sort(key=lambda s: (s["user"], s["node_id"]))
    blocked = {u: t for u, t in (await store.get("blocked") or {}).items() if t > time.time()}
    return {"sessions": sessions, "blocked": blocked}


class KickIn(BaseModel):
    user: str = Field(min_length=1, max_length=128)
    node_id: int | None = None
    block_minutes: int = Field(default=0, ge=0, le=60 * 24 * 30)


@router.post("/online/kick")
async def kick(body: KickIn, request: Request, admin=Admin):
    if body.block_minutes:
        blocked = {u: t for u, t in (await store.get("blocked") or {}).items() if t > time.time()}
        blocked[body.user] = int(time.time()) + body.block_minutes * 60
        await store.set("blocked", blocked)
        runtime.invalidate_users()
    ids = [body.node_id] if body.node_id else [n["id"] for n in await store.fetchall("SELECT id FROM nodes")]
    runtime.queue(ids, {"type": "kick", "user": body.user})
    await store.audit(admin["username"], client_ip(request), "user.kick",
                      f"{body.user} node={body.node_id or 'all'} block={body.block_minutes}m")
    return {"ok": True}


@router.delete("/online/blocked/{user}")
async def unblock(user: str, request: Request, admin=Admin):
    blocked = await store.get("blocked") or {}
    blocked.pop(user, None)
    await store.set("blocked", blocked)
    runtime.invalidate_users()
    await store.audit(admin["username"], client_ip(request), "user.unblock", user)
    return {"ok": True}


# ------------------------------------------------------------------ users

def _user_view(r, allowed: set[str], sessions: list[dict]) -> dict:
    return {
        "id": r["id"], "username": r["username"], "status": r["status"], "expire": _ts(r["expire"]),
        "data_limit": r["data_limit"], "used_traffic": r["used_traffic"], "online_at": _ts(r["online_at"]),
        "password": password_for(r["uuid"]), "allowed": r["username"] in allowed,
        "sessions": [s for s in sessions if s["user"] == r["username"]],
    }


@router.get("/users")
async def users(q: str = "", admin=Admin):
    q = q.strip()
    if len(q) < 2:
        return []
    allowed, _, _ = await runtime.users()
    sessions = runtime.online_sessions()
    return [_user_view(r, set(allowed), sessions) for r in await pg.search_users(q)]


@router.get("/connection-info")
async def connection_info(admin=Admin):
    """What a user needs besides username and password, for the user page."""
    return {"server": await store.get("ikev2_domain"), "l2tp_psk": await store.get("l2tp_psk")}


# --------------------------------------------------------------- settings

EDITABLE = {"ikev2_domain", "dns", "l2tp_psk", "telegram_bot_token", "telegram_chat_id", "telegram_proxy",
            "backup_interval_hours", "backup_keep", "pasarguard_api_key"}


def _mask(value: str) -> str:
    if not value:
        return ""
    return value[:4] + "…" + value[-4:] if len(value) > 12 else "••••"


@router.get("/settings")
async def get_settings(admin=Admin):
    s = await store.all_settings()
    out = {k: s.get(k) for k in EDITABLE}
    for k in SECRET_KEYS:
        out[k] = _mask(out.get(k) or "")
    out["cert"] = certs.info()
    return out


@router.put("/settings")
async def put_settings(body: dict, request: Request, admin=Admin):
    changed = []
    for key, value in body.items():
        if key not in EDITABLE:
            continue
        if key in SECRET_KEYS and isinstance(value, str) and "…" in value:
            continue  # the masked value came back unchanged
        if key in ("backup_interval_hours",):
            value = max(0.0, min(168.0, float(value or 0)))
        elif key == "backup_keep":
            value = max(1, min(500, int(value or 24)))
        elif key == "l2tp_psk":
            value = str(value or "").strip()
            if not (8 <= len(value) <= 64) or not value.isascii() or '"' in value or " " in value:
                raise HTTPException(400, "کلید L2TP باید ۸ تا ۶۴ کاراکتر انگلیسی بدون فاصله باشد")
        else:
            value = str(value or "").strip()[:4096]
        if await store.get(key) == value:
            continue
        await store.set(key, value)
        changed.append(key)
    await store.audit(admin["username"], client_ip(request), "settings.update", ",".join(changed))
    if {"ikev2_domain", "l2tp_psk"} & set(changed):
        request_subpage_refresh()
    return {"ok": True, "changed": changed}


SUBPAGE_DIR = config.DATA / "subpage"


def request_subpage_refresh() -> None:
    """Asks the host (zarrin-subpage.path) to re-apply the card, which bakes in
    the VPN domain and the L2TP key."""
    SUBPAGE_DIR.mkdir(parents=True, exist_ok=True)
    (SUBPAGE_DIR / "request").write_text(str(int(time.time())))


@router.post("/subpage/apply")
async def subpage_apply(request: Request, admin=Admin):
    request_subpage_refresh()
    await store.audit(admin["username"], client_ip(request), "subpage.apply")
    return {"ok": True}


@router.get("/subpage/status")
async def subpage_status(admin=Admin):
    f = SUBPAGE_DIR / "status.json"
    pending = (SUBPAGE_DIR / "request").exists() or (SUBPAGE_DIR / "request.running").exists()
    try:
        return {**json.loads(f.read_text()), "pending": pending}
    except (OSError, ValueError):
        return {"ok": None, "pending": pending}


@router.post("/settings/telegram/test")
async def telegram_test(admin=Admin):
    try:
        await telegram.send_message(f"✅ Zarrin ({config.DOMAIN}): اتصال ربات برقرار است.")
    except telegram.TelegramError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"خطا: {exc}")
    return {"ok": True}


@router.get("/cloudflare/tokens")
async def cf_tokens(admin=Admin):
    return [cloudflare.public(t) for t in await cloudflare.tokens()]


class CfTokenIn(BaseModel):
    label: str = Field(default="", max_length=64)
    token: str = Field(min_length=20, max_length=200)


@router.post("/cloudflare/tokens")
async def cf_token_add(body: CfTokenIn, request: Request, admin=Admin):
    try:
        item = await cloudflare.add(body.label, body.token)
    except cloudflare.CloudflareError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"خطا در ارتباط با کلودفلر: {exc}")
    await store.audit(admin["username"], client_ip(request), "cloudflare.add", f"{item['label']}: {', '.join(item['zones'])}")
    return cloudflare.public(item)


@router.delete("/cloudflare/tokens/{token_id}")
async def cf_token_delete(token_id: str, request: Request, admin=Admin):
    await cloudflare.remove(token_id)
    await store.audit(admin["username"], client_ip(request), "cloudflare.remove", token_id)
    return {"ok": True}


@router.post("/cloudflare/check")
async def cf_check(admin=Admin):
    return [{**cloudflare.public(t), "ok": t["ok"], "error": t.get("error")} for t in await cloudflare.refresh()]


@router.post("/settings/pasarguard/test")
async def pasarguard_test(admin=Admin):
    key = (await store.get("pasarguard_api_key") or "").strip()
    if not key:
        return {"ok": False, "error": "API Key ثبت نشده"}
    import httpx
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as http:
            r = await http.get(f"{config.PASARGUARD_API}/api/admin", headers={"X-Api-Key": key})
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if r.status_code != 200:
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    data = r.json()
    return {"ok": True, "admin": data.get("username"), "role": (data.get("role") or {}).get("name")}


@router.post("/certs/issue")
async def cert_issue(request: Request, admin=Admin):
    ok, msg = await certs.issue()
    await store.audit(admin["username"], client_ip(request), "cert.issue", msg[:200])
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "cert": certs.info()}


# ---------------------------------------------------------------- backups

@router.get("/backups")
async def backups(admin=Admin):
    return {
        "items": backup.list_backups(),
        "last": await store.get("last_backup"),
        "last_telegram": await store.get("last_backup_telegram"),
        "restore": backup.restore_status(),
    }


class BackupIn(BaseModel):
    telegram: bool = True


@router.post("/backups")
async def backup_create(body: BackupIn, request: Request, admin=Admin):
    await store.audit(admin["username"], client_ip(request), "backup.create")
    try:
        if body.telegram:
            return await backup.backup_and_send("manual")
        path = await backup.create_backup("manual")
        return {"name": path.name, "size": path.stat().st_size, "telegram": None}
    except Exception as exc:
        raise HTTPException(500, str(exc)[-500:])


@router.get("/backups/{name}/download")
async def backup_download(name: str, request: Request, admin=Admin):
    try:
        path = backup.backup_path(name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    await store.audit(admin["username"], client_ip(request), "backup.download", name)
    return FileResponse(path, filename=name, media_type="application/gzip")


@router.delete("/backups/{name}")
async def backup_delete(name: str, request: Request, admin=Admin):
    try:
        backup.backup_path(name).unlink()
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    await store.audit(admin["username"], client_ip(request), "backup.delete", name)
    return {"ok": True}


@router.post("/restore/upload")
async def restore_upload(request: Request, files: list[UploadFile] = File(...), admin=Admin):
    """One .tar.gz, or every .partNN piece of one (as sent to Telegram)."""
    if not files:
        raise HTTPException(400)
    files = sorted(files, key=lambda f: f.filename or "")
    config.RESTORE_DIR.mkdir(parents=True, exist_ok=True)
    dest = config.RESTORE_DIR / f"upload-{int(time.time())}.tar.gz"
    size = 0
    with dest.open("wb") as out:
        for f in files:
            while chunk := await f.read(1024 * 1024):
                size += len(chunk)
                if size > 4 * 1024 ** 3:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(413, "فایل خیلی بزرگ است")
                out.write(chunk)
    dest.chmod(0o600)
    try:
        import tarfile
        with tarfile.open(dest, "r:gz") as tar:
            manifest = json.load(tar.extractfile("manifest.json"))
    except Exception:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "فایل بکاپ زرین معتبر نیست (اگر چند تکه است، همه‌ی تکه‌ها را با هم انتخاب کنید)")
    await store.audit(admin["username"], client_ip(request), "restore.upload", f"{dest.name} {size}")
    return {"upload": dest.name, "manifest": manifest}


class RestoreIn(BaseModel):
    source: str = Field(pattern="^(backup|upload)$")
    name: str = Field(max_length=128)
    pasarguard: bool = True
    zarrin: bool = False
    files: bool = False
    env: bool = False
    confirm: str


@router.post("/restore")
async def restore(body: RestoreIn, request: Request, admin=Admin):
    if body.confirm != "RESTORE":
        raise HTTPException(400, "برای تأیید RESTORE را بنویسید")
    if not (body.pasarguard or body.zarrin or body.files or body.env):
        raise HTTPException(400, "چیزی برای ریستور انتخاب نشده")
    if body.source == "backup":
        try:
            path = backup.backup_path(body.name)
        except (ValueError, FileNotFoundError):
            raise HTTPException(404)
    else:
        if not body.name.startswith("upload-") or "/" in body.name:
            raise HTTPException(400)
        path = config.RESTORE_DIR / body.name
        if not path.exists():
            raise HTTPException(404)
    try:
        backup.request_restore(path, {"pasarguard": body.pasarguard, "zarrin": body.zarrin, "files": body.files,
                                      "env": body.env},
                               admin["username"])
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(400, str(exc))
    await store.audit(admin["username"], client_ip(request), "restore.request",
                      f"{body.source}:{body.name} pg={body.pasarguard} zarrin={body.zarrin} files={body.files} env={body.env}")
    return {"ok": True}


@router.get("/restore/status")
async def restore_status(admin=Admin):
    return backup.restore_status()


# ------------------------------------------------------------------ audit

@router.get("/audit")
async def audit(admin=Admin):
    return await store.fetchall("SELECT * FROM audit ORDER BY id DESC LIMIT 300")
