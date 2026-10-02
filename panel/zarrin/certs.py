"""The panel's own TLS certificate for ZARRIN_DOMAIN, from Let's Encrypt.

HTTP-01 on port 80 (lego's built-in server, bound only while issuing), or
DNS-01 through Cloudflare once a token is saved. Until a certificate exists a
self-signed one is used so the panel still starts. A renewed certificate is
loaded into the running server's SSL context without a restart.
"""

import asyncio
import logging
import os
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import config
from .store import store

log = logging.getLogger("zarrin.certs")

FULLCHAIN = config.CERT_DIR / "fullchain.pem"
PRIVKEY = config.CERT_DIR / "privkey.pem"
ACME_DIR = config.CERT_DIR / "acme"
contexts: list[ssl.SSLContext] = []


def _self_signed() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, config.DOMAIN or "zarrin")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(config.DOMAIN or "zarrin")]), critical=False)
            .sign(key, hashes.SHA256()))
    config.CERT_DIR.mkdir(parents=True, exist_ok=True)
    PRIVKEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    os.chmod(PRIVKEY, 0o600)
    FULLCHAIN.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def days_left() -> float:
    if not FULLCHAIN.exists():
        return -1
    cert = x509.load_pem_x509_certificate(FULLCHAIN.read_bytes())
    return (cert.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / 86400


def is_self_signed() -> bool:
    if not FULLCHAIN.exists():
        return True
    cert = x509.load_pem_x509_certificate(FULLCHAIN.read_bytes())
    return cert.issuer == cert.subject


def info() -> dict:
    return {"domain": config.DOMAIN, "days_left": round(days_left(), 1), "self_signed": is_self_signed()}


async def issue() -> tuple[bool, str]:
    """Gets a certificate from Let's Encrypt. Returns (ok, message)."""
    if not config.DOMAIN:
        return False, "no domain"
    cf_token = (await store.get("cloudflare_token") or "").strip()
    cmd = ["lego", "run", "--path", str(ACME_DIR), "--accept-tos", "--key-type", "EC256", "--domains", config.DOMAIN]
    env = dict(os.environ)
    if cf_token:
        cmd += ["--dns", "cloudflare"]
        env["CF_DNS_API_TOKEN"] = cf_token
    else:
        cmd += ["--http", "--http.address", ":80"]
    if config.ACME_EMAIL:
        cmd += ["--email", config.ACME_EMAIL]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                                                env=env)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        proc.kill()
        return False, "timeout"
    crt = ACME_DIR / "certificates" / f"{config.DOMAIN}.crt"
    key = ACME_DIR / "certificates" / f"{config.DOMAIN}.key"
    if proc.returncode != 0 or not crt.exists():
        msg = out.decode(errors="replace").strip()[-600:]
        log.error("Let's Encrypt for %s failed: %s", config.DOMAIN, msg)
        return False, msg
    PRIVKEY.write_bytes(key.read_bytes())
    os.chmod(PRIVKEY, 0o600)
    FULLCHAIN.write_bytes(crt.read_bytes())
    reload_contexts()
    log.info("certificate for %s installed (%.0f days)", config.DOMAIN, days_left())
    return True, "ok"


def ensure_present() -> None:
    """Before the server starts: something to serve, even if self-signed."""
    if not FULLCHAIN.exists() or not PRIVKEY.exists():
        _self_signed()


def reload_contexts() -> None:
    for ctx in contexts:
        ctx.load_cert_chain(str(FULLCHAIN), str(PRIVKEY))


async def renewer() -> None:
    await asyncio.sleep(5)
    while True:
        try:
            if is_self_signed() or days_left() < 30:
                await issue()
        except Exception:
            log.exception("certificate renewal")
        # Retry sooner while still on the self-signed fallback.
        await asyncio.sleep(1800 if is_self_signed() else 12 * 3600)
