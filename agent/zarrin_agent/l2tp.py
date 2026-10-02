"""L2TP/IPsec: IKEv1 with a pre-shared key in transport mode on the shared
charon, xl2tpd for L2TP, and pppd authenticating users with MS-CHAPv2 (the
same username and 6-digit password as IKEv2).

Each user session is one pppN interface. pppd's ip-up/ip-down scripts record
who is on which interface, and ip-down records the interface's final
counters, so traffic is counted per user like IKEv2's CHILD_SAs.
"""

import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import threading
from pathlib import Path

from .charon import charon

log = logging.getLogger("zarrin.l2tp")

CONN = "zarrin-l2tp"
PSK_ID = "zrl2tp-psk"  # must not start with IKEv2's "zr-" secret prefix
RUN = Path("/run/zarrin-l2tp")
SESSIONS = RUN / "sessions"
CLOSED = RUN / "closed"
PPP_OPTIONS = Path("/etc/ppp/options.zarrin-l2tp")
CHAP_SECRETS = Path("/etc/ppp/chap-secrets")
IP_UP = Path("/etc/ppp/zarrin-ip-up")
IP_DOWN = Path("/etc/ppp/zarrin-ip-down")
XL2TPD_CONF = Path("/etc/xl2tpd/xl2tpd.conf")
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")

IP_UP_SCRIPT = """#!/bin/sh
# pppd ip-up: $1 interface, $4 local IP, $5 client's tunnel IP, $6 ipparam (client's address)
mkdir -p {sessions}
printf '{{"iface":"%s","user":"%s","ip":"%s","remote":"%s","since":%s}}\\n' \\
  "$1" "$PEERNAME" "$5" "$6" "$(date +%s)" > {sessions}/$1.tmp && mv {sessions}/$1.tmp {sessions}/$1.json
"""

# Final counters come from the interface itself (still present while ip-down
# runs), the same source the periodic reads use, so the last delta is exact.
IP_DOWN_SCRIPT = """#!/bin/sh
# pppd ip-down: $1 interface
f={sessions}/$1.json
[ -f "$f" ] || exit 0
rx=$(cat /sys/class/net/$1/statistics/rx_bytes 2>/dev/null || echo "${{BYTES_RCVD:-0}}")
tx=$(cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo "${{BYTES_SENT:-0}}")
mkdir -p {closed}
since=$(sed -n 's/.*"since":\\([0-9]*\\).*/\\1/p' "$f")
user=$(sed -n 's/.*"user":"\\([^"]*\\)".*/\\1/p' "$f")
printf '{{"iface":"%s","user":"%s","since":%s,"rx":%s,"tx":%s}}\\n' "$1" "$user" "${{since:-0}}" "$rx" "$tx" \\
  > {closed}/$1-$$.tmp && mv {closed}/$1-$$.tmp {closed}/$1-$$.json
rm -f "$f"
"""


class L2TP:
    name = "l2tp"

    def __init__(self) -> None:
        self.enabled = False
        self.proc: subprocess.Popen | None = None
        self.pool = ""
        self.psk = ""
        self.dns = ""
        self.allowed: dict[str, str] = {}
        self.lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self.enabled and self.proc is not None and self.proc.poll() is None and charon.running

    # ------------------------------------------------------------ lifecycle

    def start(self, cfg: dict, dns: str) -> None:
        self.pool, self.psk, self.dns = cfg["pool"], cfg["psk"], dns
        self.enabled = True
        for d in (SESSIONS, CLOSED, Path("/var/run/xl2tpd")):
            d.mkdir(parents=True, exist_ok=True)
        for stale in SESSIONS.glob("*.json"):
            stale.unlink()
        self.write_config()
        self.write_secrets(self.allowed)
        charon.set_section(self.name, self.connection())
        charon.set_secrets(PSK_ID, {PSK_ID: {"type": "IKE", "data": self.psk}})
        if charon.running:
            charon.reload_conns()
        else:
            charon.start()
        Path("/var/run/xl2tpd.pid").unlink(missing_ok=True)
        self.proc = subprocess.Popen(["xl2tpd", "-D", "-c", str(XL2TPD_CONF), "-p", "/var/run/xl2tpd.pid",
                                      "-C", "/var/run/xl2tpd/l2tp-control"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("L2TP/IPsec on for %s", self.pool)

    def stop(self) -> None:
        if not self.enabled:
            return
        for s in self._session_files():
            self._hangup(s["iface"])
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        for sa in charon.list_sas():
            if sa["conn"] == CONN:
                charon.terminate(sa["uniqueid"].decode())
        self.enabled = False
        charon.set_secrets(PSK_ID, {})
        charon.drop_section(self.name)
        charon.reload_conns()

    def needs_restart(self, cfg: dict, dns: str) -> bool:
        return (cfg["pool"], cfg["psk"], dns) != (self.pool, self.psk, self.dns)

    # --------------------------------------------------------------- config

    def connection(self) -> str:
        # IKEv1 main mode with a PSK, transport mode for UDP 1701 only. The
        # modp1024/3DES fallbacks are for Windows' and older Android's
        # built-in clients.
        return f"""  {CONN} {{
    version = 1
    proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,default
    local_addrs = %any
    remote_addrs = %any
    dpd_delay = 30s
    local {{
      auth = psk
    }}
    remote {{
      auth = psk
    }}
    children {{
      l2tp {{
        mode = transport
        local_ts = dynamic[udp/1701]
        remote_ts = dynamic[udp]
        esp_proposals = aes256-sha1,aes128-sha1,aes256-sha256,aes128-sha256,3des-sha1,default
      }}
    }}
  }}
"""

    def write_config(self) -> None:
        net = ipaddress.ip_network(self.pool, strict=False)
        local, first, last = net.network_address + 1, net.network_address + 2, net.broadcast_address - 1
        XL2TPD_CONF.parent.mkdir(parents=True, exist_ok=True)
        XL2TPD_CONF.write_text(f"""[global]
port = 1701
listen-addr = 0.0.0.0

[lns default]
ip range = {first}-{last}
local ip = {local}
require chap = yes
refuse pap = yes
require authentication = yes
name = zarrin
ppp debug = no
pppoptfile = {PPP_OPTIONS}
length bit = yes
""")
        dns = [d.strip() for d in self.dns.split(",") if d.strip()][:2] or ["8.8.8.8"]
        PPP_OPTIONS.write_text("\n".join([
            "name zarrin", "auth", "require-mschap-v2", "refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap",
            "noccp", "nobsdcomp", "nodeflate", "novj", "novjccomp", "nodefaultroute",
            # 1280 survives the small-MTU mobile paths that IKEv2 also clamps for.
            "mtu 1280", "mru 1280", "lcp-echo-interval 30", "lcp-echo-failure 4",
            *[f"ms-dns {d}" for d in dns],
            f"ip-up-script {IP_UP}", f"ip-down-script {IP_DOWN}",
        ]) + "\n")
        IP_UP.write_text(IP_UP_SCRIPT.format(sessions=SESSIONS))
        IP_DOWN.write_text(IP_DOWN_SCRIPT.format(sessions=SESSIONS, closed=CLOSED))
        IP_UP.chmod(0o755)
        IP_DOWN.chmod(0o755)

    def write_secrets(self, users: dict[str, str]) -> None:
        tmp = CHAP_SECRETS.with_suffix(".tmp")
        tmp.write_text("".join(f'"{u}" zarrin "{pw}" *\n' for u, pw in sorted(users.items())))
        tmp.chmod(0o600)
        tmp.replace(CHAP_SECRETS)

    # ---------------------------------------------------------------- users

    def apply_users(self, users: dict[str, str]) -> list[str]:
        previous = self.allowed
        self.allowed = {u: pw for u, pw in users.items() if USERNAME_OK.match(u) and pw}
        if not self.enabled:
            return []
        if self.allowed != previous:
            self.write_secrets(self.allowed)
        changed = [u for u, pw in self.allowed.items() if u in previous and previous[u] != pw]
        for user in changed + [u for u in previous if u not in self.allowed]:
            self.kick(user)
        return changed

    def kick(self, user: str) -> int:
        n = 0
        for s in self._session_files():
            if s.get("user") == user:
                self._hangup(s["iface"])
                n += 1
        if n:
            log.info("disconnected %s (%d L2TP session(s))", user, n)
        return n

    def _hangup(self, iface: str) -> None:
        try:
            pid = int(Path(f"/var/run/{iface}.pid").read_text().split()[0])
            os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, IndexError):
            pass

    # ------------------------------------------------------------- sessions

    def _session_files(self) -> list[dict]:
        out = []
        for f in SESSIONS.glob("*.json"):
            try:
                out.append(json.loads(f.read_text()))
            except (OSError, ValueError):
                pass
        return out

    def sessions(self) -> list[dict]:
        """Server rx on pppN is the client's upload, tx its download."""
        if not self.running:
            return []
        out = []
        for s in self._session_files():
            stats = Path("/sys/class/net") / s["iface"] / "statistics"
            try:
                rx, tx = int((stats / "rx_bytes").read_text()), int((stats / "tx_bytes").read_text())
            except (OSError, ValueError):
                continue
            out.append({
                "proto": "l2tp", "user": s["user"], "id": f"l2tp-{s['iface']}-{s['since']}",
                "remote": s.get("remote", ""), "since": int(s["since"]),
                "counters": {f"l2tp:{s['iface']}:{s['since']}": (rx, tx)},
            })
        return out

    def drain_closed(self) -> list[tuple[str, str, int, int]]:
        out = []
        for f in sorted(CLOSED.glob("*.json")):
            try:
                c = json.loads(f.read_text())
                if c.get("user"):
                    out.append((c["user"], f"l2tp:{c['iface']}:{c['since']}", int(c["rx"]), int(c["tx"])))
            except (OSError, ValueError, KeyError):
                pass
            f.unlink(missing_ok=True)
        return out
