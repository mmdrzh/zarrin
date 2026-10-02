"""IKEv2 (EAP-MSCHAPv2 username/password) on the shared charon.

Proposals and settings are the ones proven on Iranian mobile networks:
modp4096 first (Android asks for it first), modp1024 fallbacks for Windows'
native client, fragmentation and send_cert=always for iOS.
"""

import ipaddress
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import acme
from .charon import charon, text

log = logging.getLogger("zarrin.ikev2")

CONN = "zarrin-ikev2"
SECRET_PREFIX = "zr-"
SELF_DIR = Path("/data/ikev2-self")
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


def self_signed(server_id: str) -> tuple[bytes, bytes]:
    """A private CA and an RSA leaf for server_id, kept across restarts. Only
    for setups without a real domain: clients then have to import ca.pem."""
    SELF_DIR.mkdir(parents=True, exist_ok=True)
    leaf_path, key_path, ca_path = SELF_DIR / "leaf.pem", SELF_DIR / "leaf.key", SELF_DIR / "ca.pem"
    if leaf_path.exists():
        leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
        if server_id in str(leaf.subject) and leaf.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=30):
            return leaf_path.read_bytes() + ca_path.read_bytes(), key_path.read_bytes()
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Zarrin IKEv2 CA {server_id}")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = x509.IPAddress(ipaddress.ip_address(server_id)) if acme.is_ip(server_id) else x509.DNSName(server_id)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_id)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                                  x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    ca_path.write_bytes(ca.public_bytes(pem))
    leaf_path.write_bytes(leaf.public_bytes(pem))
    key_path.write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    log.info("generated a self-signed certificate for %s", server_id)
    return leaf.public_bytes(pem) + ca.public_bytes(pem), key_path.read_bytes()


class IKEv2:
    name = "ikev2"

    def __init__(self) -> None:
        self.enabled = False
        self.server_id = ""
        self.pool = ""
        self.dns = ""
        self.allowed: dict[str, str] = {}
        self.closed_events: list[tuple[str, str, int, int]] = []  # (user, counter key, in, out)
        self.lock = threading.Lock()
        charon.listeners.append(self._on_event)

    @property
    def running(self) -> bool:
        return self.enabled and charon.running

    @property
    def proc(self):
        return charon.proc if self.enabled else None

    def start(self, cfg: dict, dns: str) -> None:
        self.server_id, self.pool, self.dns = cfg["server_id"], cfg["pool"], dns
        self.enabled = True
        self.install_certificate()
        charon.set_section(self.name, self.connection(), self.pools())
        if charon.running:
            charon.reload_creds()
            charon.reload_conns()
        else:
            charon.start()
        self.apply_users(self.allowed)

    def stop(self) -> None:
        if not self.enabled:
            return
        for sa in self._sas():
            charon.terminate(sa["uniqueid"].decode())
        self.enabled = False
        charon.set_secrets(SECRET_PREFIX, {})
        charon.drop_section(self.name)
        charon.reload_conns()

    def needs_restart(self, cfg: dict, dns: str) -> bool:
        return (cfg["server_id"], cfg["pool"], dns) != (self.server_id, self.pool, self.dns)

    def reload_certificate(self) -> None:
        self.install_certificate()
        charon.reload_creds()
        charon.reload_conns()
        log.info("certificate reloaded")

    def install_certificate(self) -> None:
        pair = acme.current(self.server_id)
        chain, key = pair if pair else self_signed(self.server_id)
        charon.install_certificate(chain, key)

    def chain(self) -> bytes | None:
        return charon.chain() if self.running else None

    def connection(self) -> str:
        return f"""  {CONN} {{
    version = 2
    unique = never
    send_cert = always
    fragmentation = yes
    dpd_delay = 300s
    proposals = aes256-sha256-modp4096,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256gcm16-prfsha384-ecp384,aes256-sha256-modp1024,aes128-sha256-modp1024,aes256-sha1-modp1024,default
    local_addrs = %any
    remote_addrs = %any
    pools = zr-pool
    local {{
      auth = pubkey
      certs = zr-server.pem
      id = {self.server_id}
    }}
    remote {{
      auth = eap-mschapv2
      eap_id = %any
    }}
    children {{
      net {{
        local_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha256-modp1024,aes128-sha256-modp1024,aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,default
      }}
    }}
  }}
"""

    def pools(self) -> str:
        dns = ",".join(d.strip() for d in self.dns.split(",") if d.strip()) or "8.8.8.8"
        return f"""  zr-pool {{
    addrs = {self.pool}
    dns = {dns}
  }}
"""

    # ---------------------------------------------------------------- users

    def apply_users(self, users: dict[str, str]) -> list[str]:
        """Loads EAP secrets for the allowed users. Users whose password
        changed (subscription revoked) or who are gone are hung up."""
        previous = self.allowed
        self.allowed = {u: pw for u, pw in users.items() if USERNAME_OK.match(u) and pw}
        if not self.enabled:
            return []
        charon.set_secrets(SECRET_PREFIX, {
            SECRET_PREFIX + name: {"type": "EAP", "data": pw, "owners": [name]} for name, pw in self.allowed.items()
        })
        changed = [u for u, pw in self.allowed.items() if u in previous and previous[u] != pw]
        removed = [u for u in previous if u not in self.allowed]
        if len(previous) != len(self.allowed) or changed:
            log.info("users: %d allowed (+%d, -%d)", len(self.allowed),
                     len([u for u in self.allowed if u not in previous]), len(removed))
        for user in changed + removed:
            self.kick(user)
        return changed

    def _sas(self) -> list[dict]:
        return [sa for sa in charon.list_sas() if sa["conn"] == CONN and sa.get("remote-eap-id")]

    def kick(self, user: str) -> int:
        if not self.running:
            return 0
        n = 0
        for sa in self._sas():
            if sa["remote-eap-id"].decode() == user:
                charon.terminate(sa["uniqueid"].decode())
                n += 1
        if n:
            log.info("disconnected %s (%d session(s))", user, n)
        return n

    # -------------------------------------------------------------- sessions

    def sessions(self) -> list[dict]:
        """Open sessions with cumulative counters per CHILD_SA. bytes-in on the
        server is the client's upload."""
        if not self.running:
            return []
        out = []
        now = time.time()
        for sa in self._sas():
            user = sa["remote-eap-id"].decode()
            counters = {}
            for child in (sa.get("child-sas") or {}).values():
                counters["ikev2:" + child["uniqueid"].decode()] = (int(child.get("bytes-in", b"0")),
                                                                   int(child.get("bytes-out", b"0")))
            out.append({
                "proto": "ikev2", "user": user, "id": "ike-" + sa["uniqueid"].decode(),
                "remote": (sa.get("remote-host") or b"").decode(),
                "since": int(now - int(sa.get("established", b"0") or 0)),
                "counters": counters,
            })
        return out

    def drain_closed(self) -> list[tuple[str, str, int, int]]:
        with self.lock:
            out, self.closed_events = self.closed_events, []
        return out

    def _on_event(self, label: bytes, event: dict) -> None:
        """Final counters of each CHILD_SA as it closes (child-updown without
        up=yes, or the old SA of a child-rekey), so traffic between the last
        read and the disconnect is not lost."""
        if label == b"child-updown" and event.get("up") == b"yes":
            return
        with self.lock:
            for name, sa in event.items():
                if not isinstance(sa, dict) or text(name) != CONN:
                    continue
                user = (sa.get("remote-eap-id") or b"").decode()
                for child in (sa.get("child-sas") or {}).values():
                    child = child.get("old", child)
                    if user:
                        self.closed_events.append((user, "ikev2:" + child["uniqueid"].decode(),
                                                   int(child.get("bytes-in", b"0")),
                                                   int(child.get("bytes-out", b"0"))))
