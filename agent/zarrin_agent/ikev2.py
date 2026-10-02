"""IKEv2 (EAP-MSCHAPv2 username/password) with strongSwan 5.9's charon,
driven over VICI.

Proposals and settings are the ones proven on Iranian mobile networks:
modp4096 first (Android asks for it first), modp1024 fallbacks for Windows'
native client, fragmentation and send_cert=always for iOS.
"""

import ipaddress
import logging
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import vici
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import acme

log = logging.getLogger("zarrin.ikev2")

SWANCTL = Path("/etc/swanctl")
CHARON = "/usr/libexec/ipsec/charon"
VICI_SOCKET = "/var/run/charon.vici"
CONN = "zarrin-ikev2"
SECRET_PREFIX = "zr-"
SELF_DIR = Path("/data/ikev2-self")
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?", re.S)


def session() -> vici.Session:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(VICI_SOCKET)
    return vici.Session(sock)


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
        self.proc: subprocess.Popen | None = None
        self.server_id = ""
        self.pool = ""
        self.dns = ""
        self.allowed: dict[str, str] = {}
        self.loaded: dict[str, str] = {}
        self.closed_events: list[tuple[str, str, int, int]] = []  # (user, child id, in, out)
        self.lock = threading.Lock()
        self.listener: threading.Thread | None = None
        self.stopping = threading.Event()

    # ------------------------------------------------------------ lifecycle

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, cfg: dict, dns: str) -> None:
        self.server_id, self.pool, self.dns = cfg["server_id"], cfg["pool"], dns
        self.install_certificate()
        self.write_conf()
        for stale in ("/var/run/charon.pid", "/var/run/charon.ctl", VICI_SOCKET):
            Path(stale).unlink(missing_ok=True)
        self.proc = subprocess.Popen([CHARON])
        for _ in range(100):
            if Path(VICI_SOCKET).exists():
                try:
                    session().version()
                    break
                except Exception:
                    pass
            time.sleep(0.2)
        # Connections, pools, certificate and key. User secrets go over VICI
        # afterwards; swanctl --load-creds would unload them, so it runs only here.
        out = subprocess.run(["swanctl", "--load-all", "--noprompt"], capture_output=True, text=True)
        log.info("swanctl --load-all: %s", out.stdout.strip().replace("\n", "; ") or out.stderr.strip())
        self.loaded = {}
        self.stopping.clear()
        self.listener = threading.Thread(target=self._listen, daemon=True)
        self.listener.start()
        if self.allowed:
            self.apply_users(self.allowed)

    def stop(self) -> None:
        self.stopping.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def needs_restart(self, cfg: dict, dns: str) -> bool:
        return (cfg["server_id"], cfg["pool"], dns) != (self.server_id, self.pool, self.dns)

    def reload_certificate(self) -> None:
        """--load-creds swaps the certificate but drops every user secret
        loaded over VICI, so they are loaded again at once."""
        self.install_certificate()
        subprocess.run(["swanctl", "--load-creds", "--noprompt"], capture_output=True, text=True)
        subprocess.run(["swanctl", "--load-conns"], capture_output=True, text=True)
        self.loaded = {}
        self.apply_users(self.allowed)
        log.info("certificate reloaded")

    # ---------------------------------------------------------- certificate

    def install_certificate(self) -> None:
        """The leaf goes to x509/ and every certificate above it to x509ca/, so
        charon sends the whole chain: a leaf alone makes iOS and Windows fail."""
        pair = acme.current(self.server_id)
        if pair:
            chain, key = pair
        else:
            chain, key = self_signed(self.server_id)
        blocks = CERT_RE.findall(chain)
        # charon sends the intermediates only when it can build the chain up to
        # a root it holds. Let's Encrypt's chain may end in a cross-signed root,
        # so the real root comes from the system store.
        top = x509.load_pem_x509_certificate(blocks[-1])
        if top.issuer != top.subject:
            for candidate in Path("/etc/ssl/certs").glob("*.pem"):
                try:
                    root = x509.load_pem_x509_certificate(candidate.read_bytes())
                except ValueError:
                    continue
                if root.subject == top.issuer:
                    blocks.append(root.public_bytes(serialization.Encoding.PEM))
                    break
        for sub in ("x509", "x509ca", "private"):
            (SWANCTL / sub).mkdir(parents=True, exist_ok=True)
            for old in (SWANCTL / sub).glob("zr-*"):
                old.unlink()
        (SWANCTL / "x509" / "zr-server.pem").write_bytes(blocks[0])
        for i, block in enumerate(blocks[1:]):
            (SWANCTL / "x509ca" / f"zr-ca{i}.pem").write_bytes(block)
        (SWANCTL / "private" / "zr-server.key").write_bytes(key)
        (SWANCTL / "private" / "zr-server.key").chmod(0o600)

    def chain(self) -> bytes | None:
        leaf = SWANCTL / "x509" / "zr-server.pem"
        if not leaf.exists():
            return None
        return leaf.read_bytes() + b"".join(p.read_bytes() for p in sorted((SWANCTL / "x509ca").glob("zr-ca*.pem")))

    def write_conf(self) -> None:
        dns = ",".join(d.strip() for d in self.dns.split(",") if d.strip()) or "8.8.8.8"
        (SWANCTL / "swanctl.conf").write_text(f"""connections {{
  {CONN} {{
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
}}
pools {{
  zr-pool {{
    addrs = {self.pool}
    dns = {dns}
  }}
}}
""")

    # ---------------------------------------------------------------- users

    def apply_users(self, users: dict[str, str]) -> list[str]:
        """Loads/unloads EAP secrets. Returns users whose password changed
        (subscription revoked): their open sessions are hung up."""
        self.allowed = {u: pw for u, pw in users.items() if USERNAME_OK.match(u) and pw}
        if not self.running:
            return []
        s = session()
        added = [u for u, pw in self.allowed.items() if self.loaded.get(u) != pw]
        removed = [u for u in self.loaded if u not in self.allowed]
        changed = [u for u in added if u in self.loaded]
        for name in added:
            s.load_shared({"id": SECRET_PREFIX + name, "type": "EAP", "data": self.allowed[name], "owners": [name]})
        for name in removed:
            s.unload_shared({"id": SECRET_PREFIX + name})
        self.loaded = dict(self.allowed)
        if added or removed:
            log.info("users: %d allowed (+%d, -%d)", len(self.allowed), len(added), len(removed))
        for user in changed + removed:
            self.kick(user)
        return changed

    def kick(self, user: str) -> int:
        if not self.running:
            return 0
        s = session()
        n = 0
        for ike in s.list_sas():
            for sa in ike.values():
                if (sa.get("remote-eap-id") or b"").decode() == user:
                    for _ in s.terminate({"ike-id": sa["uniqueid"].decode(), "force": "yes", "timeout": "-1"}):
                        pass
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
        for ike in session().list_sas():
            for sa in ike.values():
                user = (sa.get("remote-eap-id") or b"").decode()
                if not user:
                    continue
                children = []
                for child in (sa.get("child-sas") or {}).values():
                    children.append((child["uniqueid"].decode(), int(child.get("bytes-in", b"0")),
                                     int(child.get("bytes-out", b"0"))))
                out.append({
                    "proto": "ikev2", "user": user, "id": "ike-" + sa["uniqueid"].decode(),
                    "remote": (sa.get("remote-host") or b"").decode(),
                    "since": int(now - int(sa.get("established", b"0") or 0)),
                    "counters": {f"ikev2:{cid}": (up, down) for cid, up, down in children},
                })
        return out

    def drain_closed(self) -> list[tuple[str, str, int, int]]:
        with self.lock:
            out, self.closed_events = self.closed_events, []
        return out

    def _listen(self) -> None:
        """Final counters of each CHILD_SA as it closes (child-updown without
        up=yes, or the old SA of a child-rekey), so traffic between the last
        read and the disconnect is not lost."""
        while not self.stopping.is_set():
            try:
                for label, event in session().listen(["child-updown", "child-rekey"]):
                    if label == b"child-updown" and event.get("up") == b"yes":
                        continue
                    with self.lock:
                        for _, sa in event.items():
                            if not isinstance(sa, dict):
                                continue
                            user = (sa.get("remote-eap-id") or b"").decode()
                            for child in (sa.get("child-sas") or {}).values():
                                child = child.get("old", child)
                                if user:
                                    self.closed_events.append((user, "ikev2:" + child["uniqueid"].decode(),
                                                               int(child.get("bytes-in", b"0")),
                                                               int(child.get("bytes-out", b"0"))))
            except Exception as exc:
                if not self.stopping.is_set():
                    log.warning("event listener: %s; reconnecting", exc)
                    time.sleep(2)
