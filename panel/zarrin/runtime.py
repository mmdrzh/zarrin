"""In-memory state shared by the agent API and the admin API: who is online
on which node, commands waiting for a node, and the allowed-users cache."""

import asyncio
import hashlib
import json
import time

from .pg import password_for, pg
from .store import store

ONLINE_STALE_SECONDS = 60
USERS_CACHE_SECONDS = 2.0


class Runtime:
    def __init__(self) -> None:
        # node id -> {"at": unix time, "sessions": [...], "status": {...}}
        self.online: dict[int, dict] = {}
        # node id -> pending commands, handed out with the next report reply
        self.commands: dict[int, list[dict]] = {}
        self._users: dict[str, str] = {}
        self._users_body = b"{}"
        self._users_etag = ""
        self._users_at = 0.0
        self._users_lock = asyncio.Lock()

    # --------------------------------------------------------------- users

    async def users(self) -> tuple[dict[str, str], bytes, str]:
        """{username: password} of everyone allowed to connect right now."""
        async with self._users_lock:
            if time.monotonic() - self._users_at > USERS_CACHE_SECONDS:
                blocked = await store.get("blocked") or {}
                now = time.time()
                users = {}
                for r in await pg.allowed_users():
                    if blocked.get(r["username"], 0) > now:
                        continue
                    pw = password_for(r["uuid"])
                    if pw:
                        users[r["username"]] = pw
                body = json.dumps(users, separators=(",", ":"), sort_keys=True).encode()
                if body != self._users_body:
                    self._users = users
                    self._users_body = body
                    self._users_etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
                self._users_at = time.monotonic()
            return self._users, self._users_body, self._users_etag

    def invalidate_users(self) -> None:
        self._users_at = 0.0

    # -------------------------------------------------------------- online

    def set_online(self, node_id: int, sessions: list[dict], status: dict | None) -> None:
        self.online[node_id] = {"at": time.time(), "sessions": sessions, "status": status or {}}

    def online_sessions(self) -> list[dict]:
        now = time.time()
        out = []
        for node_id, entry in self.online.items():
            if now - entry["at"] > ONLINE_STALE_SECONDS:
                continue
            for s in entry["sessions"]:
                out.append({**s, "node_id": node_id})
        return out

    def node_live(self, node_id: int) -> bool:
        entry = self.online.get(node_id)
        return bool(entry and time.time() - entry["at"] <= ONLINE_STALE_SECONDS)

    # ------------------------------------------------------------ commands

    def queue(self, node_ids: list[int], command: dict) -> None:
        for node_id in node_ids:
            self.commands.setdefault(node_id, []).append(command)

    def take_commands(self, node_id: int) -> list[dict]:
        return self.commands.pop(node_id, [])


runtime = Runtime()
