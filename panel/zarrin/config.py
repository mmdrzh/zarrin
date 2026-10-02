"""Settings that come from the environment (/opt/zarrin/.env).

Everything an admin changes at runtime (Telegram token, Cloudflare token,
protocol options, ...) lives in the database instead, see store.Settings.
"""

import os
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise SystemExit(f"missing environment variable {name}")
    return value


VERSION = "0.1.0"

DOMAIN = _env("ZARRIN_DOMAIN", "")
PORT = int(_env("ZARRIN_PORT", "56246"))
SECRET = _env("ZARRIN_SECRET")
DATA = Path(_env("ZARRIN_DATA", "/data"))
# The repository checkout, mounted read-only: the node agent bundle comes from here.
REPO = Path(_env("ZARRIN_REPO", "/repo"))
ACME_EMAIL = _env("ACME_EMAIL", "")

# PasarGuard. PG_DSN is a least-privilege role used for everything at runtime;
# PG_OWNER_DSN (the panel's own database user) is used only for backups.
PG_DSN = _env("PG_DSN")
PG_OWNER_DSN = _env("PG_OWNER_DSN", "")
PASARGUARD_API = _env("PASARGUARD_API", "https://127.0.0.1:443").rstrip("/")
PASARGUARD_SUB_URL = _env("PASARGUARD_SUB_URL", "").rstrip("/")
PASARGUARD_DIR = Path(_env("PASARGUARD_DIR", "/pasarguard"))
PASARGUARD_DATA = Path(_env("PASARGUARD_DATA_DIR", "/pasarguard-data"))

# The port the old pg-ikev2 bridge served on. Kept for nodes not yet moved to
# the Zarrin agent and for the Tifusi app's /sub links. 0 turns it off.
LEGACY_PORT = int(_env("LEGACY_PORT", "0"))
LEGACY_TLS_CERT = _env("LEGACY_TLS_CERT", "")
LEGACY_TLS_KEY = _env("LEGACY_TLS_KEY", "")

CERT_DIR = DATA / "certs"
BACKUP_DIR = DATA / "backups"
RESTORE_DIR = DATA / "restore"
DB_FILE = DATA / "zarrin.db"
WEB_DIR = Path(_env("ZARRIN_WEB", "/app/web"))
