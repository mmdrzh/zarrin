"""A publicly trusted certificate for the node's server name (the shared VPN
domain) from Let's Encrypt, so clients never have to install a CA.

HTTP-01 on port 80. Every node behind the same name answers challenges it
does not hold itself by asking its peers, since Let's Encrypt may resolve the
name to any of them.
"""

import ipaddress
import logging
import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from cryptography import x509

from .panel import panel

log = logging.getLogger("zarrin.acme")

DATA = Path("/data")
ACME_DIR = DATA / "acme"
CERT_DIR = DATA / "certs"
WEBROOT = DATA / "webroot"
PREFIX = "/.well-known/acme-challenge/"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def serve_challenges() -> None:
    """Port 80: ACME HTTP-01 tokens from WEBROOT, else from a peer node."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            token = self.path[len(PREFIX):] if self.path.startswith(PREFIX) else ""
            body = None
            if re.fullmatch(r"[A-Za-z0-9_-]{10,200}", token):
                local = WEBROOT / ".well-known" / "acme-challenge" / token
                if local.exists():
                    body = local.read_bytes()
                elif not self.headers.get("X-Zarrin-Peer") and not self.headers.get("X-PG-Peer"):
                    try:
                        peers = panel.peers()
                    except (requests.RequestException, ValueError):
                        peers = []
                    for peer in peers:
                        try:
                            r = requests.get(f"http://{peer}{PREFIX}{token}",
                                             headers={"X-Zarrin-Peer": "1", "X-PG-Peer": "1"}, timeout=4)
                            if r.status_code == 200:
                                body = r.content
                                break
                        except requests.RequestException:
                            pass
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if body is not None:
                self.wfile.write(body)

        def log_message(self, *args):
            pass

    WEBROOT.mkdir(parents=True, exist_ok=True)
    try:
        server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    except OSError as exc:
        log.error("cannot listen on port 80 for Let's Encrypt: %s", exc)
        return
    threading.Thread(target=server.serve_forever, daemon=True).start()


def ensure(server_id: str, email: str = "") -> bool:
    """Gets or renews the certificate when it has under 30 days left (3 for an
    IP) and publishes it to CERT_DIR. Returns True when it changed."""
    crt = ACME_DIR / "certificates" / f"{server_id}.crt"
    key = ACME_DIR / "certificates" / f"{server_id}.key"
    if crt.exists():
        cert = x509.load_pem_x509_certificate(crt.read_bytes())
        if cert.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=3 if is_ip(server_id) else 30):
            return publish(crt, key)
    cmd = ["lego", "run", "--path", str(ACME_DIR), "--accept-tos", "--key-type", "RSA2048", "--domains", server_id,
           "--http", "--http.webroot", str(WEBROOT)]
    if email:
        cmd += ["--email", email]
    if is_ip(server_id):
        cmd += ["--profile", "shortlived"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if out.returncode != 0 or not crt.exists():
        log.error("Let's Encrypt failed for %s: %s", server_id, (out.stderr or out.stdout).strip()[-500:])
        return False
    log.info("Let's Encrypt certificate for %s issued", server_id)
    return publish(crt, key)


def publish(crt: Path, key: Path) -> bool:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    full, priv = CERT_DIR / "fullchain.pem", CERT_DIR / "privkey.pem"
    if full.exists() and full.read_bytes() == crt.read_bytes() and priv.exists():
        return False
    priv.write_bytes(key.read_bytes())
    priv.chmod(0o600)
    full.write_bytes(crt.read_bytes())
    return True


def current(server_id: str) -> tuple[bytes, bytes] | None:
    """(fullchain, key) published for server_id, if any."""
    full, priv = CERT_DIR / "fullchain.pem", CERT_DIR / "privkey.pem"
    if not (full.exists() and priv.exists()):
        return None
    leaf = x509.load_pem_x509_certificate(full.read_bytes())
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in names.get_values_for_type(x509.DNSName)] + \
               [str(v) for v in names.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    if server_id not in sans:
        return None
    return full.read_bytes(), priv.read_bytes()
