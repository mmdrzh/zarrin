"""strongSwan's charon (5.9), shared by every service that uses IPsec: IKEv2
and L2TP/IPsec (IKEv1). Each service contributes its own connection (and
pool) to swanctl.conf and its own secrets over VICI; charon itself runs
while at least one of them is on.

Secrets are kept here too: `swanctl --load-creds` (needed to swap the
certificate) drops every secret loaded over VICI, so they are put back.
"""

import logging
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

import vici
from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("zarrin.charon")

SWANCTL = Path("/etc/swanctl")
CHARON = "/usr/libexec/ipsec/charon"
VICI_SOCKET = "/var/run/charon.vici"
CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?", re.S)


def text(value) -> str:
    return value.decode() if isinstance(value, (bytes, bytearray)) else str(value or "")


def session() -> vici.Session:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(VICI_SOCKET)
    return vici.Session(sock)


class Charon:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.sections: dict[str, tuple[str, str]] = {}  # owner -> (connections, pools)
        self.secrets: dict[str, dict] = {}  # id -> VICI load-shared message
        self.loaded: dict[str, dict] = {}
        self.lock = threading.RLock()
        self.listeners: list[Callable[[bytes, dict], None]] = []
        # Each start gets a new generation; an event thread from an earlier
        # charon exits instead of delivering events twice.
        self.generation = 0

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    # ----------------------------------------------------------- config

    def set_section(self, owner: str, connections: str, pools: str = "") -> None:
        self.sections[owner] = (connections, pools)

    def drop_section(self, owner: str) -> None:
        self.sections.pop(owner, None)

    def write_conf(self) -> None:
        conns = "".join(c for c, _ in self.sections.values())
        pools = "".join(p for _, p in self.sections.values())
        (SWANCTL / "swanctl.conf").write_text(f"connections {{\n{conns}}}\npools {{\n{pools}}}\n")

    def reload_conns(self) -> None:
        """New/changed/removed connections and pools, keeping secrets and SAs."""
        self.write_conf()
        if self.running:
            for flag in ("--load-pools", "--load-conns"):
                out = subprocess.run(["swanctl", flag], capture_output=True, text=True)
                log.info("swanctl %s: %s", flag, (out.stdout.strip().splitlines() or [out.stderr.strip()])[-1])

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self.running:
            return
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
        # Connections, pools, certificate and key; secrets go over VICI.
        out = subprocess.run(["swanctl", "--load-all", "--noprompt"], capture_output=True, text=True)
        log.info("swanctl --load-all: %s", out.stdout.strip().replace("\n", "; ") or out.stderr.strip())
        self.loaded = {}
        self.sync_secrets()
        self.generation += 1
        threading.Thread(target=self._listen, args=(self.generation,), daemon=True).start()

    def stop(self) -> None:
        self.generation += 1
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self.loaded = {}

    # -------------------------------------------------------- certificate

    def install_certificate(self, chain: bytes, key: bytes) -> None:
        """The leaf goes to x509/ and every certificate above it to x509ca/, so
        charon sends the whole chain: a leaf alone makes iOS and Windows fail.
        charon sends intermediates only when it can build the chain up to a
        root it holds, so the real root comes from the system store when the
        chain ends in a cross-signed one."""
        blocks = CERT_RE.findall(chain)
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

    def reload_creds(self) -> None:
        """Swaps the certificate; secrets are put back right after."""
        subprocess.run(["swanctl", "--load-creds", "--noprompt"], capture_output=True, text=True)
        self.loaded = {}
        self.sync_secrets()

    def chain(self) -> bytes | None:
        leaf = SWANCTL / "x509" / "zr-server.pem"
        if not leaf.exists():
            return None
        return leaf.read_bytes() + b"".join(p.read_bytes() for p in sorted((SWANCTL / "x509ca").glob("zr-ca*.pem")))

    # ------------------------------------------------------------- secrets

    def set_secrets(self, prefix: str, secrets: dict[str, dict]) -> None:
        """Replaces every secret whose id starts with prefix."""
        with self.lock:
            for sid in [s for s in self.secrets if s.startswith(prefix)]:
                if sid not in secrets:
                    del self.secrets[sid]
            self.secrets.update(secrets)
            self.sync_secrets()

    def sync_secrets(self) -> None:
        if not self.running:
            return
        with self.lock:
            s = session()
            for sid, msg in self.secrets.items():
                if self.loaded.get(sid) != msg:
                    s.load_shared({"id": sid, **msg})
            for sid in [x for x in self.loaded if x not in self.secrets]:
                s.unload_shared({"id": sid})
            self.loaded = {k: dict(v) for k, v in self.secrets.items()}

    # ---------------------------------------------------------------- SAs

    def list_sas(self) -> list[dict]:
        if not self.running:
            return []
        out = []
        for ike in session().list_sas():
            for name, sa in ike.items():
                out.append({**sa, "conn": text(name)})
        return out

    def terminate(self, ike_id: str) -> None:
        for _ in session().terminate({"ike-id": ike_id, "force": "yes", "timeout": "-1"}):
            pass

    def _listen(self, generation: int) -> None:
        while generation == self.generation:
            try:
                for label, event in session().listen(["child-updown", "child-rekey"]):
                    if generation != self.generation:
                        return
                    for fn in self.listeners:
                        fn(label, event)
            except Exception as exc:
                if generation == self.generation:
                    log.warning("event listener: %s; reconnecting", exc)
                    time.sleep(2)


charon = Charon()
