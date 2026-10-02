"""Everything Zarrin reads from or writes to PasarGuard's database.

All of it is in this one file so a PasarGuard schema change has one place to
fix. The runtime role (see GRANT_SQL) can read and update only the columns
used here.
"""

import json
import logging
from datetime import datetime, timezone

import asyncpg

from . import config

log = logging.getLogger("zarrin.pg")

ROLE = "zarrin"

GRANT_SQL = """
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
    CREATE ROLE {role} LOGIN;
  END IF;
END $$;
ALTER ROLE {role} PASSWORD '{password}';
GRANT CONNECT ON DATABASE {db} TO {role};
GRANT USAGE ON SCHEMA public TO {role};
GRANT SELECT (id, username, status, expire, data_limit, used_traffic, admin_id, proxy_settings,
              online_at, created_at, note, sub_revoked_at) ON users TO {role};
GRANT UPDATE (used_traffic, online_at) ON users TO {role};
GRANT SELECT (id, username, used_traffic) ON admins TO {role};
GRANT UPDATE (used_traffic) ON admins TO {role};
GRANT SELECT (id, name, address, status, usage_coefficient, core_config_id) ON nodes TO {role};
GRANT SELECT (id, name, config) ON core_configs TO {role};
GRANT SELECT, INSERT, UPDATE ON node_user_usages, node_usages TO {role};
GRANT USAGE ON SEQUENCE node_user_usages_id_seq, node_usages_id_seq TO {role};
"""

ALLOWED_USERS_SQL = """
SELECT id, username, proxy_settings->'vless'->>'id' AS uuid FROM users
WHERE status IN ('active', 'on_hold')
  AND (expire IS NULL OR expire > now())
  AND (data_limit IS NULL OR data_limit = 0 OR used_traffic < data_limit)
"""

USER_COLUMNS = """id, username, status::text AS status, expire, data_limit, used_traffic, online_at,
                  created_at, admin_id, proxy_settings->'vless'->>'id' AS uuid"""


def password_for(uuid: str | None) -> str | None:
    """Six digits derived from the user's VLESS UUID. Every account has one,
    nothing is stored, and revoking the subscription (a new UUID) changes it.
    The subscription page template computes the same digits in Jinja:
    digit i = int(hex[5i:5i+5], 16) % 10, over the UUID without dashes."""
    if not uuid:
        return None
    h = uuid.replace("-", "").lower()
    if len(h) < 30:
        return None
    return "".join(str(int(h[i * 5:i * 5 + 5], 16) % 10) for i in range(6))


def time_bucket(now: datetime) -> datetime:
    # Same 10-minute bucket as PasarGuard's record_usages job;
    # node_user_usages is unique on (created_at, user_id, node_id).
    return now.replace(minute=(now.minute // 10) * 10, second=0, microsecond=0)


class PasarGuardDB:
    def __init__(self) -> None:
        self.pool: asyncpg.Pool | None = None

    async def open(self) -> None:
        self.pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=5, statement_cache_size=0)

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()

    async def ping(self) -> bool:
        try:
            return await self.pool.fetchval("SELECT 1") == 1
        except Exception:
            return False

    # ---------------------------------------------------------------- users

    async def allowed_users(self) -> list[asyncpg.Record]:
        return await self.pool.fetch(ALLOWED_USERS_SQL)

    async def user_by_id(self, user_id: int) -> asyncpg.Record | None:
        return await self.pool.fetchrow(f"SELECT {USER_COLUMNS} FROM users WHERE id = $1", user_id)

    async def user_by_name(self, username: str) -> asyncpg.Record | None:
        return await self.pool.fetchrow(f"SELECT {USER_COLUMNS} FROM users WHERE username = $1", username)

    async def search_users(self, query: str, limit: int = 30) -> list[asyncpg.Record]:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return await self.pool.fetch(
            f"SELECT {USER_COLUMNS} FROM users WHERE username ILIKE $1 ORDER BY username LIMIT $2", pattern, limit
        )

    async def user_counts(self) -> dict[str, int]:
        rows = await self.pool.fetch("SELECT status::text AS status, count(*) AS n FROM users GROUP BY 1")
        return {r["status"]: r["n"] for r in rows}

    # -------------------------------------------------------------- traffic

    async def record_usage(self, pg_node_id: int | None, items: dict[str, tuple[int, int]]) -> tuple[int, int]:
        """Adds per-user [uplink, downlink] bytes the same way PasarGuard's own
        record_usages job does: users, admins, node_user_usages, node_usages.
        Returns (users recorded, bytes after the node's coefficient)."""
        now = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn, conn.transaction():
            coeff = 1.0
            if pg_node_id is not None:
                value = await conn.fetchval("SELECT usage_coefficient FROM nodes WHERE id = $1", pg_node_id)
                coeff = float(value if value is not None else 1.0)
            rows = await conn.fetch("SELECT id, username, admin_id FROM users WHERE username = ANY($1::text[])", list(items))
            per_user: list[tuple[int, int]] = []
            per_admin: dict[int, int] = {}
            for r in rows:
                up, down = items[r["username"]]
                value = int((up + down) * coeff)
                if value <= 0:
                    continue
                per_user.append((r["id"], value))
                if r["admin_id"]:
                    per_admin[r["admin_id"]] = per_admin.get(r["admin_id"], 0) + value
            if per_user:
                # Ordered by id, as the panel does, to keep lock order consistent.
                per_user.sort()
                uids = [u for u, _ in per_user]
                values = [v for _, v in per_user]
                await conn.execute(
                    """UPDATE users SET used_traffic = users.used_traffic + s.v, online_at = $3
                       FROM unnest($1::bigint[], $2::bigint[]) AS s(id, v) WHERE users.id = s.id""",
                    uids, values, now,
                )
                if per_admin:
                    aids = sorted(per_admin)
                    await conn.execute(
                        """UPDATE admins SET used_traffic = admins.used_traffic + s.v
                           FROM unnest($1::bigint[], $2::bigint[]) AS s(id, v) WHERE admins.id = s.id""",
                        aids, [per_admin[a] for a in aids],
                    )
                await conn.execute(
                    """INSERT INTO node_user_usages (created_at, user_id, node_id, used_traffic)
                       SELECT $3, s.id, $4, s.v FROM unnest($1::bigint[], $2::bigint[]) AS s(id, v)
                       ON CONFLICT (created_at, user_id, node_id)
                       DO UPDATE SET used_traffic = node_user_usages.used_traffic + EXCLUDED.used_traffic""",
                    uids, values, time_bucket(now), pg_node_id,
                )
            total_up = sum(u for u, _ in items.values())
            total_down = sum(d for _, d in items.values())
            await conn.execute(
                """INSERT INTO node_usages (created_at, node_id, uplink, downlink) VALUES ($1, $2, $3, $4)
                   ON CONFLICT (created_at, node_id)
                   DO UPDATE SET uplink = node_usages.uplink + EXCLUDED.uplink,
                                 downlink = node_usages.downlink + EXCLUDED.downlink""",
                time_bucket(now), pg_node_id, total_up, total_down,
            )
        return len(per_user), sum(v for _, v in per_user)

    # ----------------------------------------------------------- nodes/core

    async def nodes(self) -> list[asyncpg.Record]:
        return await self.pool.fetch("SELECT id, name, address, status::text AS status, usage_coefficient FROM nodes ORDER BY id")

    async def outbounds(self) -> list[dict]:
        """Outbounds of every core config, for routing VPN traffic through them."""
        out = []
        for row in await self.pool.fetch("SELECT id, name, config FROM core_configs ORDER BY id"):
            cfg = row["config"]
            if isinstance(cfg, str):
                cfg = json.loads(cfg)
            for ob in cfg.get("outbounds", []) or []:
                if ob.get("tag"):
                    out.append({"core_id": row["id"], "core": row["name"], "tag": ob["tag"],
                                "protocol": ob.get("protocol", ""), "config": ob})
        return out


pg = PasarGuardDB()
