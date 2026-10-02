"""Zarrin's own state, in SQLite: admins, nodes, settings, audit log.

PasarGuard's database stays the source of truth for users; nothing about a
user is copied here except what PasarGuard has no place for (WireGuard keys).
"""

import asyncio
import json
import time
from typing import Any

import aiosqlite

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    totp_secret TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    pg_node_id INTEGER,
    token_hash TEXT NOT NULL UNIQUE,
    legacy INTEGER NOT NULL DEFAULT 0,
    settings TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    agent_version TEXT,
    status TEXT
);
CREATE TABLE IF NOT EXISTS join_tokens (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    node_id INTEGER
);
CREATE TABLE IF NOT EXISTS seen_batches (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    admin TEXT,
    ip TEXT,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS wg_peers (
    user_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    uuid TEXT,
    created_at INTEGER NOT NULL
);
"""

# Defaults for settings an admin can change in the panel.
DEFAULTS: dict[str, Any] = {
    "ikev2_domain": "",
    "dns": "8.8.8.8,1.1.1.1",
    "l2tp_psk": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "telegram_proxy": "",
    "backup_interval_hours": 1,
    "backup_keep": 24,
    "cloudflare_token": "",  # older single-token setting, moved into cloudflare_tokens
    "cloudflare_tokens": [],
    "pasarguard_api_key": "",
    "blocked": {},  # username -> unix time the temporary block ends
}

# Settings whose value is never sent back to the browser in full.
SECRET_KEYS = {"telegram_bot_token", "pasarguard_api_key"}


class Store:
    def __init__(self) -> None:
        self.db: aiosqlite.Connection | None = None
        self.lock = asyncio.Lock()

    async def open(self) -> None:
        config.DATA.mkdir(parents=True, exist_ok=True)
        self.db = await aiosqlite.connect(config.DB_FILE)
        self.db.row_factory = aiosqlite.Row
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA foreign_keys=ON")
        await self.db.executescript(SCHEMA)
        await self.db.commit()
        config.DB_FILE.chmod(0o600)

    async def close(self) -> None:
        if self.db:
            await self.db.close()

    async def fetchall(self, sql: str, *args) -> list[dict]:
        async with self.db.execute(sql, args) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def fetchone(self, sql: str, *args) -> dict | None:
        async with self.db.execute(sql, args) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def execute(self, sql: str, *args) -> int:
        async with self.lock:
            cur = await self.db.execute(sql, args)
            await self.db.commit()
            return cur.lastrowid

    # ------------------------------------------------------------ settings

    async def get(self, key: str) -> Any:
        row = await self.fetchone("SELECT v FROM kv WHERE k = ?", key)
        return json.loads(row["v"]) if row else DEFAULTS.get(key)

    async def set(self, key: str, value: Any) -> None:
        await self.execute(
            "INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            key, json.dumps(value),
        )

    async def all_settings(self) -> dict[str, Any]:
        out = dict(DEFAULTS)
        for row in await self.fetchall("SELECT k, v FROM kv"):
            out[row["k"]] = json.loads(row["v"])
        return out

    # --------------------------------------------------------------- audit

    async def audit(self, admin: str | None, ip: str | None, action: str, detail: str = "") -> None:
        await self.execute(
            "INSERT INTO audit (at, admin, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
            int(time.time()), admin, ip, action, detail[:2000],
        )

    # ------------------------------------------------------------- batches

    async def batch_seen(self, batch_id: str) -> bool:
        return await self.fetchone("SELECT 1 FROM seen_batches WHERE id = ?", batch_id) is not None

    async def mark_batch(self, batch_id: str) -> None:
        now = int(time.time())
        await self.execute("INSERT OR IGNORE INTO seen_batches (id, at) VALUES (?, ?)", batch_id, now)

    async def prune(self) -> None:
        now = int(time.time())
        await self.execute("DELETE FROM seen_batches WHERE at < ?", now - 3 * 86400)
        await self.execute("DELETE FROM audit WHERE at < ?", now - 90 * 86400)
        await self.execute("DELETE FROM join_tokens WHERE expires_at < ?", now - 86400)


store = Store()
