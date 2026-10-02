"""Per-user traffic since the last report, from cumulative per-session
counters, sent to the panel in batches that survive restarts.

One batch at a time, retried with the same id until the panel accepts it, so
a lost reply never counts traffic twice.
"""

import json
import logging
import threading
import uuid
from pathlib import Path

log = logging.getLogger("zarrin.usage")

PENDING_FILE = Path("/data/pending.json")


class Usage:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.last: dict[str, tuple[int, int]] = {}  # counter key -> (up, down) at the previous read
        self.pending: dict[str, list[int]] = {}
        self.batch: dict | None = None
        if PENDING_FILE.exists():
            try:
                saved = json.loads(PENDING_FILE.read_text())
                self.batch = saved.get("batch")
                self.pending = saved.get("pending", {})
            except Exception:
                log.exception("ignoring unreadable %s", PENDING_FILE)

    def _add(self, user: str, key: str, up: int, down: int) -> None:
        prev_up, prev_down = self.last.get(key, (0, 0))
        du = up - prev_up if up >= prev_up else up
        dd = down - prev_down if down >= prev_down else down
        if du > 0 or dd > 0:
            acc = self.pending.setdefault(user, [0, 0])
            acc[0] += du
            acc[1] += dd

    def read(self, sessions: list[dict]) -> None:
        with self.lock:
            seen = {}
            for s in sessions:
                for key, (up, down) in s["counters"].items():
                    self._add(s["user"], key, up, down)
                    seen[key] = (up, down)
            self.last = seen

    def closed(self, events: list[tuple[str, str, int, int]]) -> None:
        with self.lock:
            for user, key, up, down in events:
                self._add(user, key, up, down)
                self.last.pop(key, None)

    def save(self) -> None:
        tmp = PENDING_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"batch": self.batch, "pending": self.pending}))
        tmp.replace(PENDING_FILE)

    def next_batch(self) -> dict | None:
        with self.lock:
            if self.batch is None and self.pending:
                self.batch = {"id": uuid.uuid4().hex, "items": self.pending}
                self.pending = {}
            self.save()
            return self.batch

    def accepted(self, batch: dict) -> None:
        with self.lock:
            if self.batch and self.batch["id"] == batch["id"]:
                self.batch = None
            self.save()
        total = sum(u + d for u, d in batch["items"].values())
        if total:
            log.info("usage: reported %d users, %.1f MB", len(batch["items"]), total / 1e6)

    def migrate_legacy(self, path: Path) -> None:
        """Takes over traffic the old pg-ikev2 agent had not reported yet."""
        if not path.exists():
            return
        try:
            saved = json.loads(path.read_text())
        except ValueError:
            return
        with self.lock:
            for source in ((saved.get("batch") or {}).get("items") or {}, saved.get("pending") or {}):
                for user, (up, down) in source.items():
                    acc = self.pending.setdefault(user, [0, 0])
                    acc[0] += int(up)
                    acc[1] += int(down)
            self.save()
        path.rename(path.with_suffix(".migrated"))
        log.info("took over unreported traffic from the pg-ikev2 agent")
