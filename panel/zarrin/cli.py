"""Maintenance commands, run inside the container by the host's `zarrin` script.

  python -m zarrin.cli admin <username>       create the admin or reset its password (prints it; clears 2FA)
  python -m zarrin.cli grant                  create/refresh the least-privilege PostgreSQL role
  python -m zarrin.cli import-legacy <env>    take over nodes from an old pg-ikev2 bridge .env
  python -m zarrin.cli set <key> <json value> change a setting
  python -m zarrin.cli get <key>              print a setting
  python -m zarrin.cli card-values            JSON the subscription page card is filled with
"""

import asyncio
import json
import secrets
import shutil
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import asyncpg

from . import config
from .auth import hash_password, sha256
from .pg import GRANT_SQL, ROLE
from .store import store


async def cmd_admin(username: str) -> None:
    await store.open()
    password = secrets.token_urlsafe(12)
    row = await store.fetchone("SELECT id FROM admins WHERE username = ?", username)
    if row:
        await store.execute("UPDATE admins SET pw_hash = ?, totp_secret = NULL, token_version = token_version + 1 "
                            "WHERE id = ?", hash_password(password), row["id"])
        await store.audit("cli", None, "admin.reset", username)
        print(f"password of {username} reset (2FA turned off)")
    else:
        await store.execute("INSERT INTO admins (username, pw_hash, created_at) VALUES (?, ?, ?)",
                            username, hash_password(password), int(time.time()))
        await store.audit("cli", None, "admin.create", username)
        print(f"admin {username} created")
    print(f"USERNAME={username}")
    print(f"PASSWORD={password}")
    await store.close()


async def cmd_grant() -> None:
    if not config.PG_OWNER_DSN:
        sys.exit("PG_OWNER_DSN is not set")
    runtime = urlparse(config.PG_DSN.replace("postgresql+asyncpg", "postgresql"))
    if runtime.username != ROLE:
        sys.exit(f"PG_DSN must use the role {ROLE}")
    db = runtime.path.lstrip("/")
    password = runtime.password.replace("'", "''")
    conn = await asyncpg.connect(config.PG_OWNER_DSN.replace("postgresql+asyncpg", "postgresql"))
    try:
        await conn.execute(GRANT_SQL.format(role=ROLE, password=password, db=db))
    finally:
        await conn.close()
    print(f"role {ROLE} ready")


async def cmd_import_legacy(env_path: str) -> None:
    env = {}
    for line in Path(env_path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    await store.open()
    imported = 0
    for entry in filter(None, (e.strip() for e in env.get("NODE_TOKENS", "").split(","))):
        token, pg_node_id, ip = entry.split(":")
        if await store.fetchone("SELECT 1 FROM nodes WHERE ip = ?", ip):
            print(f"{ip}: already known, skipped")
            continue
        await store.execute(
            "INSERT INTO nodes (name, ip, pg_node_id, token_hash, legacy, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            f"node-{pg_node_id}", ip, int(pg_node_id), sha256(token), int(time.time()),
        )
        imported += 1
        print(f"{ip}: imported (PasarGuard node {pg_node_id})")
    if env.get("IKEV2_SERVER_ID") and not await store.get("ikev2_domain"):
        await store.set("ikev2_domain", env["IKEV2_SERVER_ID"])
        print(f"IKEv2 domain: {env['IKEV2_SERVER_ID']}")
    chain = Path(env_path).parent / "state" / "chain.pem"
    if chain.exists():
        shutil.copy(chain, config.DATA / "chain.pem")
    await store.audit("cli", None, "legacy.import", f"{imported} nodes")
    await store.close()


async def cmd_set(key: str, value: str) -> None:
    await store.open()
    await store.set(key, json.loads(value))
    await store.close()
    print(f"{key} updated")


async def cmd_get(key: str) -> None:
    await store.open()
    value = await store.get(key)
    await store.close()
    print(value if isinstance(value, str) else json.dumps(value))


async def cmd_card_values() -> None:
    from . import ovpn
    await store.open()
    server = await store.get("ikev2_domain") or ""
    udp, tcp = await ovpn.ports()
    print(json.dumps({
        "server": server,
        "psk": await store.get("l2tp_psk") or "",
        "ovpn_udp": await ovpn.profile("udp", server) if udp else "",
        "ovpn_tcp": await ovpn.profile("tcp", server) if tcp else "",
        "ovpn_auto": await ovpn.profile("auto", server) if udp or tcp else "",
    }))
    await store.close()


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "admin":
        asyncio.run(cmd_admin(args[1]))
    elif args == ["grant"]:
        asyncio.run(cmd_grant())
    elif len(args) == 2 and args[0] == "import-legacy":
        asyncio.run(cmd_import_legacy(args[1]))
    elif args == ["card-values"]:
        asyncio.run(cmd_card_values())
    elif len(args) == 2 and args[0] == "get":
        asyncio.run(cmd_get(args[1]))
    elif len(args) == 3 and args[0] == "set":
        asyncio.run(cmd_set(args[1], args[2]))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
