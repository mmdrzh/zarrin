"""OpenVPN over UDP and TCP: one server process per transport, users log in
with the same username and 6-digit password as IKEv2 (no client
certificates), so every user's .ovpn file is the same.

The server certificate and tls-crypt key come from the panel and are the
same on every node, so one profile works against any node behind the shared
name. tls-crypt also encrypts the TLS handshake, which hides the usual
OpenVPN fingerprint from simple inspection and drops unauthenticated
packets before any TLS work.

Each process has a management socket: sessions and byte counters come from
`status 3`, users are hung up with `kill`. A client-disconnect script
records each session's final counters.
"""

import hashlib
import json
import logging
import re
import socket
import subprocess
from pathlib import Path

log = logging.getLogger("zarrin.openvpn")

ETC = Path("/etc/openvpn/zarrin")
RUN = Path("/run/zarrin-ovpn")
CLOSED = RUN / "closed"
USERS = ETC / "users"
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")

# via-file: line 1 username, line 2 password. Exact, fixed-string match of
# "user:password" against the users file; names are restricted to
# [A-Za-z0-9_.@-] when the file is written.
AUTH_SCRIPT = """#!/bin/sh
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
case "$u" in ''|*[!A-Za-z0-9_.@-]*) exit 1;; esac
grep -Fxq -- "$u:$p" {users}
"""

DISCONNECT_SCRIPT = """#!/bin/sh
# OpenVPN client-disconnect: final counters of this session.
f={closed}/$$.json
printf '{{"proto":"%s","user":"%s","ip":"%s","port":"%s","rx":%s,"tx":%s}}\\n' \\
  "{proto}" "$common_name" "$trusted_ip" "$trusted_port" "${{bytes_received:-0}}" "${{bytes_sent:-0}}" > $f.tmp && mv $f.tmp $f
"""


def mgmt(sock_path: Path, command: str, timeout: float = 5) -> list[str]:
    """One command on a management socket; the reply lines up to END/SUCCESS/ERROR."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock_path))
    buf = b""
    try:
        while b"\n" not in buf:  # the >INFO banner
            chunk = s.recv(4096)
            if not chunk:
                return []
            buf += chunk
        buf = b""
        s.sendall(command.encode() + b"\n")
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            text = buf.decode(errors="replace")
            if "\nEND" in text or text.startswith(("SUCCESS:", "ERROR:")) or "\nSUCCESS:" in text or "\nERROR:" in text:
                break
    finally:
        s.close()
    return [ln.rstrip("\r") for ln in buf.decode(errors="replace").splitlines()]


class OpenVPN:
    name = "openvpn"

    def __init__(self) -> None:
        self.enabled = False
        self.procs: dict[str, subprocess.Popen] = {}
        self.signature = ""
        self.cfg: dict = {}
        self.allowed: dict[str, str] = {}

    @property
    def running(self) -> bool:
        return self.enabled and bool(self.procs) and all(p.poll() is None for p in self.procs.values())

    def _signature(self, cfg: dict, dns: str) -> str:
        keys = ("udp_port", "tcp_port", "pool_udp", "pool_tcp", "ca", "cert", "key", "tls_crypt")
        return hashlib.sha256(json.dumps([cfg.get(k) for k in keys] + [dns]).encode()).hexdigest()

    # ------------------------------------------------------------ lifecycle

    def start(self, cfg: dict, dns: str) -> None:
        self.cfg, self.enabled = cfg, True
        self.signature = self._signature(cfg, dns)
        ETC.mkdir(parents=True, exist_ok=True)
        for d in (RUN, CLOSED, RUN / "tmp"):
            d.mkdir(parents=True, exist_ok=True)
            subprocess.run(["chown", "nobody:nogroup", str(d)])
        for name, text in (("ca.pem", cfg["ca"]), ("server.pem", cfg["cert"]), ("server.key", cfg["key"]),
                           ("tls-crypt.key", cfg["tls_crypt"])):
            (ETC / name).write_text(text.strip() + "\n")
            (ETC / name).chmod(0o600)
        (ETC / "auth.sh").write_text(AUTH_SCRIPT.format(users=USERS))
        (ETC / "auth.sh").chmod(0o755)
        self.write_users(self.allowed)
        dns_list = [d.strip() for d in dns.split(",") if d.strip()][:2] or ["8.8.8.8"]
        for proto, port, pool in (("udp", cfg.get("udp_port"), cfg["pool_udp"]), ("tcp", cfg.get("tcp_port"), cfg["pool_tcp"])):
            if not port:
                continue
            script = ETC / f"disconnect-{proto}.sh"
            script.write_text(DISCONNECT_SCRIPT.format(closed=CLOSED, proto=proto))
            script.chmod(0o755)
            conf = ETC / f"{proto}.conf"
            conf.write_text(self.server_conf(proto, int(port), pool, dns_list))
            (RUN / f"{proto}.sock").unlink(missing_ok=True)
            self.procs[proto] = subprocess.Popen(["openvpn", "--config", str(conf)],
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info("OpenVPN %s on port %s (%s)", proto.upper(), port, pool)

    def stop(self) -> None:
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self.procs = {}
        self.enabled = False

    def needs_restart(self, cfg: dict, dns: str) -> bool:
        return self._signature(cfg, dns) != self.signature

    def server_conf(self, proto: str, port: int, pool: str, dns: list[str]) -> str:
        net, mask = pool.split("/")
        mask = socket.inet_ntoa(int((0xFFFFFFFF << (32 - int(mask))) & 0xFFFFFFFF).to_bytes(4, "big"))
        lines = [
            # IPv4 only, like the shared name's DNS records.
            f"port {port}", f"proto {'udp4' if proto == 'udp' else 'tcp4-server'}", "dev tun", "topology subnet",
            f"server {net} {mask}",
            f"ca {ETC}/ca.pem", f"cert {ETC}/server.pem", f"key {ETC}/server.key", "dh none",
            f"tls-crypt {ETC}/tls-crypt.key", "tls-version-min 1.2",
            "data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305",
            # Username and password only; the same account may be on several devices.
            "verify-client-cert none", "username-as-common-name", "duplicate-cn",
            "script-security 2", f"auth-user-pass-verify {ETC}/auth.sh via-file", f"tmp-dir {RUN}/tmp",
            f"client-disconnect {ETC}/disconnect-{proto}.sh",
            'push "redirect-gateway def1 bypass-dhcp"', 'push "block-outside-dns"',
            *[f'push "dhcp-option DNS {d}"' for d in dns],
            "keepalive 10 60", "mssfix 1250", "max-clients 5000",
            f"management {RUN}/{proto}.sock unix",
            "user nobody", "group nogroup", "persist-key", "persist-tun",
            "verb 1", "mute 20",
        ]
        if proto == "udp":
            lines += ["explicit-exit-notify 1", "fast-io"]
        else:
            lines += ["tcp-nodelay"]
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- users

    def write_users(self, users: dict[str, str]) -> None:
        tmp = USERS.with_suffix(".tmp")
        tmp.write_text("".join(f"{u}:{pw}\n" for u, pw in sorted(users.items())))
        subprocess.run(["chown", "nobody:nogroup", str(tmp)])
        tmp.chmod(0o600)
        tmp.replace(USERS)

    def apply_users(self, users: dict[str, str]) -> list[str]:
        previous = self.allowed
        self.allowed = {u: pw for u, pw in users.items() if USERNAME_OK.match(u) and pw}
        if not self.enabled:
            return []
        if self.allowed != previous:
            self.write_users(self.allowed)
        changed = [u for u, pw in self.allowed.items() if u in previous and previous[u] != pw]
        for user in changed + [u for u in previous if u not in self.allowed]:
            self.kick(user)
        return changed

    def kick(self, user: str) -> int:
        if not USERNAME_OK.match(user):
            return 0
        n = 0
        for proto in self.procs:
            try:
                reply = mgmt(RUN / f"{proto}.sock", f"kill {user}")
                if any(ln.startswith("SUCCESS") for ln in reply):
                    n += 1
            except OSError:
                pass
        if n:
            log.info("disconnected %s (OpenVPN)", user)
        return n

    # ------------------------------------------------------------- sessions

    def sessions(self) -> list[dict]:
        """bytes received by the server is the client's upload."""
        if not self.running:
            return []
        out = []
        for proto in self.procs:
            try:
                lines = mgmt(RUN / f"{proto}.sock", "status 3")
            except OSError as exc:
                log.warning("OpenVPN %s status: %s", proto, exc)
                continue
            header = None
            for ln in lines:
                parts = ln.split("\t")
                if parts[:2] == ["HEADER", "CLIENT_LIST"]:
                    header = parts[2:]
                elif parts[0] == "CLIENT_LIST" and header:
                    row = dict(zip(header, parts[1:]))
                    user = row.get("Common Name", "")
                    if not USERNAME_OK.match(user):
                        continue  # still authenticating ("UNDEF")
                    ip, _, port = row.get("Real Address", "").rpartition(":")
                    out.append({
                        "proto": "openvpn", "user": user, "id": f"ovpn-{proto}-{row.get('Client ID', '')}",
                        "remote": ip, "since": int(row.get("Connected Since (time_t)", "0") or 0),
                        "counters": {f"ovpn-{proto}:{user}:{ip}:{port}": (int(row.get("Bytes Received", 0) or 0),
                                                                          int(row.get("Bytes Sent", 0) or 0))},
                    })
        return out

    def drain_closed(self) -> list[tuple[str, str, int, int]]:
        out = []
        for f in sorted(CLOSED.glob("*.json")):
            try:
                c = json.loads(f.read_text())
                if USERNAME_OK.match(c.get("user", "")):
                    out.append((c["user"], f"ovpn-{c['proto']}:{c['user']}:{c['ip']}:{c['port']}", int(c["rx"]), int(c["tx"])))
            except (OSError, ValueError, KeyError):
                pass
            f.unlink(missing_ok=True)
        return out
