"""Backups: PasarGuard's database, its settings and templates, and Zarrin's own
data, in one .tar.gz that can be sent to Telegram and restored from the panel.

A restore stops PasarGuard, which this container cannot do on its own (it has
no Docker socket on purpose). It writes a request file instead; a systemd
path unit on the host notices it and runs `zarrin restore-run`, which reports
progress back in restore/status.json.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import tarfile
import time
from datetime import datetime
from pathlib import Path

from . import config, telegram
from .store import store

log = logging.getLogger("zarrin.backup")

NAME_RE = re.compile(r"^zarrin-backup-\d{8}-\d{6}\.tar\.gz$")
_lock = asyncio.Lock()


def _dsn_for_libpq(dsn: str) -> str:
    return dsn.replace("postgresql+asyncpg://", "postgresql://")


async def _run(*cmd: str, env: dict | None = None) -> None:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                env={**os.environ, **(env or {})})
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {(err or out).decode(errors='replace')[-800:]}")


def _sqlite_copy(dest: Path) -> None:
    src = sqlite3.connect(config.DB_FILE)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()


def list_backups() -> list[dict]:
    config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(config.BACKUP_DIR.glob("zarrin-backup-*.tar.gz"), reverse=True):
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "created": int(st.st_mtime)})
    return out


def backup_path(name: str) -> Path:
    if not NAME_RE.match(name):
        raise ValueError("bad backup name")
    path = config.BACKUP_DIR / name
    if not path.exists():
        raise FileNotFoundError(name)
    return path


async def create_backup(reason: str = "manual") -> Path:
    async with _lock:
        config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(config.BACKUP_DIR, 0o700)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        work = config.BACKUP_DIR / f".work-{stamp}"
        work.mkdir()
        try:
            contents = []
            if config.PG_OWNER_DSN:
                await _run("pg_dump", "--format=custom", "--compress=6", "--file", str(work / "pasarguard.dump"),
                           "--dbname", _dsn_for_libpq(config.PG_OWNER_DSN))
                contents.append("pasarguard.dump")
            await asyncio.to_thread(_sqlite_copy, work / "zarrin.db")
            contents.append("zarrin.db")
            for src, dest in ((config.PASARGUARD_DIR / ".env", "pasarguard/.env"),
                              (config.PASARGUARD_DIR / "docker-compose.yml", "pasarguard/docker-compose.yml"),
                              (config.REPO / ".env", "zarrin/.env")):
                if src.exists():
                    (work / dest).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, work / dest)
                    contents.append(dest)
            for sub in ("templates", "certs"):
                src = config.PASARGUARD_DATA / sub
                if src.exists():
                    shutil.copytree(src, work / "pasarguard-data" / sub, symlinks=True)
                    contents.append(f"pasarguard-data/{sub}")
            manifest = {
                "format": 1,
                "zarrin_version": config.VERSION,
                "created": int(time.time()),
                "host": socket.gethostname(),
                "domain": config.DOMAIN,
                "reason": reason,
                "contents": contents,
            }
            (work / "manifest.json").write_text(json.dumps(manifest, indent=2))
            final = config.BACKUP_DIR / f"zarrin-backup-{stamp}.tar.gz"
            tmp = final.with_suffix(".partial")

            def pack():
                with tarfile.open(tmp, "w:gz", compresslevel=6) as tar:
                    for item in sorted(work.iterdir()):
                        tar.add(item, arcname=item.name)

            await asyncio.to_thread(pack)
            os.chmod(tmp, 0o600)
            tmp.rename(final)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        await prune()
        await store.set("last_backup", {"at": int(time.time()), "name": final.name, "size": final.stat().st_size})
        log.info("backup %s (%.1f MB, %s)", final.name, final.stat().st_size / 1e6, reason)
        return final


async def prune() -> None:
    keep = max(1, int(await store.get("backup_keep") or 24))
    for item in list_backups()[keep:]:
        (config.BACKUP_DIR / item["name"]).unlink(missing_ok=True)


async def backup_and_send(reason: str) -> dict:
    path = await create_backup(reason)
    size_mb = path.stat().st_size / 1e6
    caption = (f"🟡 Zarrin backup\n🖥 {config.DOMAIN or socket.gethostname()}\n"
               f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n📁 {path.name} ({size_mb:.1f} MB)")
    result = {"name": path.name, "size": path.stat().st_size, "telegram": None}
    try:
        parts = await telegram.send_file(path, caption)
        result["telegram"] = f"sent in {parts} part(s)"
    except telegram.TelegramError as exc:
        result["telegram"] = str(exc)
    await store.set("last_backup_telegram", {"at": int(time.time()), "result": result["telegram"]})
    return result


async def scheduler() -> None:
    """Every `backup_interval_hours` (0 = off), backup and send to Telegram."""
    await asyncio.sleep(60)
    while True:
        try:
            hours = float(await store.get("backup_interval_hours") or 0)
            token = await store.get("telegram_bot_token")
            last = (await store.get("last_backup_scheduled") or {}).get("at", 0)
            if hours > 0 and token and time.time() - last >= hours * 3600 - 30:
                await store.set("last_backup_scheduled", {"at": int(time.time())})
                await backup_and_send("scheduled")
        except Exception:
            log.exception("scheduled backup failed")
        await asyncio.sleep(60)


# ----------------------------------------------------------------- restore

def restore_status() -> dict:
    status = config.RESTORE_DIR / "status.json"
    if status.exists():
        try:
            return json.loads(status.read_text())
        except ValueError:
            pass
    return {"state": "idle"}


def request_restore(path: Path, parts: dict, admin: str) -> None:
    """Hands the restore to the host (see module docstring)."""
    config.RESTORE_DIR.mkdir(parents=True, exist_ok=True)
    state = restore_status().get("state")
    if state in ("requested", "running"):
        raise RuntimeError("یک ریستور دیگر در حال اجراست")
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        if "manifest.json" not in names:
            raise ValueError("این فایل بکاپ زرین نیست (manifest.json ندارد)")
        if parts.get("pasarguard") and "pasarguard.dump" not in names:
            raise ValueError("این بکاپ دیتابیس پاسارگاد ندارد")
    request = {"file": str(path.relative_to(config.DATA)), "pasarguard": bool(parts.get("pasarguard")),
               "zarrin": bool(parts.get("zarrin")), "admin": admin, "at": int(time.time())}
    (config.RESTORE_DIR / "status.json").write_text(json.dumps({"state": "requested", "at": int(time.time()),
                                                                 "log": ["درخواست ثبت شد؛ منتظر سرویس میزبان..."]}))
    tmp = config.RESTORE_DIR / "request.json.tmp"
    tmp.write_text(json.dumps(request))
    tmp.rename(config.RESTORE_DIR / "request.json")
