"""Zarrin node agent.

Runs the VPN services (IKEv2, L2TP/IPsec, OpenVPN over UDP and TCP)
in the host's network namespace, beside PasarGuard's node and never
touching it. It keeps the allowed users in step with the panel (a new user can
connect within seconds), hangs up anyone no longer allowed, and reports who is
online and how much traffic each user moved.
"""

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

import requests

from . import acme, firewall
from .charon import charon
from .ikev2 import IKEv2
from .l2tp import L2TP
from .openvpn import OpenVPN
from .panel import panel
from .usage import Usage

VERSION = "0.3.1"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("zarrin.agent")

USERS_INTERVAL = 5
STATS_INTERVAL = 10
REPORT_INTERVAL = 15
CONFIG_INTERVAL = 30
LEGACY_PENDING = Path("/data/legacy-pending.json")


def listening_ports() -> set[tuple[str, int]]:
    """(proto, port) of every listening TCP socket and bound UDP socket."""
    out = set()
    for proto, files, state in (("tcp", ("/proc/net/tcp", "/proc/net/tcp6"), "0A"), ("udp", ("/proc/net/udp", "/proc/net/udp6"), "07")):
        for f in files:
            try:
                for line in Path(f).read_text().splitlines()[1:]:
                    parts = line.split()
                    if parts[3] == state:
                        out.add((proto, int(parts[1].rsplit(":", 1)[1], 16)))
            except (OSError, IndexError, ValueError):
                pass
    return out


class Agent:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.ikev2 = IKEv2()
        self.l2tp = L2TP()
        self.openvpn = OpenVPN()
        self.services = [self.ikev2, self.l2tp, self.openvpn]
        self.usage = Usage()
        self.cfg: dict = {}
        self.users: dict[str, str] = {}
        self.users_synced = False
        self.sessions: list[dict] = []
        self.cert_reported = False
        self.warned: set[tuple[str, int]] = set()

    # -------------------------------------------------------------- config

    def apply_config(self, cfg: dict) -> None:
        """Turns each service on, off or restarts it to match the panel."""
        dns = cfg.get("dns", "8.8.8.8,1.1.1.1")
        wanted = {svc.name: (cfg.get(svc.name) or {}) for svc in self.services}
        pools = []
        for w in wanted.values():
            if w.get("enabled"):
                pools += [w[k] for k in ("pool", "pool_udp", "pool_tcp") if w.get(k)]
        firewall.ensure(pools, l2tp=bool(wanted["l2tp"].get("enabled")), redirects=self.redirects(wanted["openvpn"]))
        for svc in self.services:
            want = wanted[svc.name]
            if want.get("enabled"):
                if not svc.running:
                    if svc.enabled:
                        log.error("%s is not running; restarting", svc.name)
                        self.collect()
                        svc.stop()
                    self.start_service(svc, want, dns, cfg)
                elif svc.needs_restart(want, dns):
                    log.info("%s settings changed; restarting", svc.name)
                    self.collect()
                    svc.stop()
                    self.start_service(svc, want, dns, cfg)
            elif svc.enabled:
                log.info("%s turned off in the panel", svc.name)
                self.collect()
                svc.stop()
        if not any(svc.enabled for svc in self.services) and charon.running:
            charon.stop()
        self.cfg = cfg

    def redirects(self, ovpn: dict) -> list[tuple[str, int, int]]:
        """OpenVPN's alternative ports, minus any port something on this
        server listens on (a PasarGuard inbound must never be hijacked)."""
        if not ovpn.get("enabled"):
            return []
        listening = listening_ports()
        out = []
        for proto, main_key, alt_key in (("udp", "udp_port", "udp_alt"), ("tcp", "tcp_port", "tcp_alt")):
            main = int(ovpn.get(main_key) or 0)
            for port in ovpn.get(alt_key) or []:
                port = int(port)
                if not main or port == main:
                    continue
                if (proto, port) in listening:
                    if (proto, port) not in self.warned:
                        log.warning("OpenVPN: %s/%s is in use on this server; not redirecting it", proto, port)
                        self.warned.add((proto, port))
                    continue
                out.append((proto, port, main))
        return out

    def start_service(self, svc, want: dict, dns: str, cfg: dict) -> None:
        if svc is self.ikev2:
            self.ensure_certificate(want["server_id"], cfg.get("acme_email", ""))
            self.cert_reported = False
        svc.start(want, dns)
        if self.users_synced:
            svc.apply_users(self.users)

    def ensure_certificate(self, server_id: str, email: str) -> bool:
        if acme.is_ip(server_id) and not os.environ.get("ACME_IP"):
            return False
        try:
            return acme.ensure(server_id, email)
        except Exception:
            log.exception("Let's Encrypt; using what is on disk")
            return False

    # --------------------------------------------------------------- users

    def sync_users(self) -> None:
        users = panel.users()
        if users is None:
            return
        self.users = users
        self.users_synced = True
        for svc in self.services:
            if svc.running:
                svc.apply_users(users)

    # ---------------------------------------------------------- statistics

    def collect(self) -> None:
        sessions = []
        for svc in self.services:
            if svc.running:
                sessions += svc.sessions()
                self.usage.closed(svc.drain_closed())
        self.usage.read(sessions)
        self.sessions = sessions
        # Safety net: anyone online who is not allowed any more is hung up.
        if self.users_synced:
            for s in sessions:
                if s["user"] not in self.users:
                    for svc in self.services:
                        if svc.name == s["proto"]:
                            svc.kick(s["user"])

    def report(self) -> None:
        batch = self.usage.next_batch()
        online = []
        for s in self.sessions:
            up = sum(c[0] for c in s["counters"].values())
            down = sum(c[1] for c in s["counters"].values())
            online.append({"proto": s["proto"], "user": s["user"], "remote": s["remote"], "since": s["since"],
                           "up": up, "down": down, "id": s["id"]})
        status = {"services": {svc.name: svc.running for svc in self.services}, "load": os.getloadavg()[0]}
        reply = panel.report({"version": VERSION, "batch": batch, "online": online, "status": status})
        if batch and reply.get("batch", {}).get("ok"):
            self.usage.accepted(batch)
        for cmd in reply.get("commands", []):
            if cmd.get("type") == "kick" and cmd.get("user"):
                for svc in self.services:
                    if svc.running:
                        svc.kick(cmd["user"])

    def report_chain(self) -> None:
        chain = self.ikev2.chain() if self.ikev2.running else None
        if chain:
            try:
                panel.cert(chain)
                self.cert_reported = True
            except requests.RequestException as exc:
                log.warning("could not report the certificate chain: %s", exc)

    # ---------------------------------------------------------------- main

    def run(self) -> None:
        Path("/data").mkdir(parents=True, exist_ok=True)
        self.usage.migrate_legacy(LEGACY_PENDING)
        acme.serve_challenges()
        while not self.stop.is_set():
            try:
                self.apply_config(panel.config())
                break
            except Exception as exc:
                log.warning("waiting for the panel: %s", exc)
                self.stop.wait(5)
        next_users = next_stats = next_report = next_cfg = 0.0
        next_acme = time.monotonic() + 3600
        while not self.stop.is_set():
            now = time.monotonic()
            try:
                if now >= next_users:
                    next_users = now + USERS_INTERVAL
                    self.sync_users()
                if now >= next_stats:
                    next_stats = now + STATS_INTERVAL
                    self.collect()
                if now >= next_report:
                    next_report = now + REPORT_INTERVAL
                    self.report()
                    if not self.cert_reported:
                        self.report_chain()
                if now >= next_cfg:
                    next_cfg = now + CONFIG_INTERVAL
                    self.apply_config(panel.config())
                if now >= next_acme:
                    next_acme = now + 3600
                    ik = self.cfg.get("ikev2", {})
                    if self.ikev2.running and self.ensure_certificate(ik["server_id"], self.cfg.get("acme_email", "")):
                        self.ikev2.reload_certificate()
                        self.report_chain()
                if any(svc.enabled and not svc.running for svc in self.services):
                    next_cfg = 0  # apply_config restarts it
            except (requests.RequestException, ValueError) as exc:
                log.warning("panel: %s", exc)
            except Exception:
                log.exception("loop error")
                time.sleep(1)
            self.stop.wait(1)
        self.shutdown()

    def shutdown(self) -> None:
        try:
            self.collect()
            batch = self.usage.next_batch()
            if batch:
                reply = panel.report({"version": VERSION, "batch": batch, "online": [], "status": {}})
                if reply.get("batch", {}).get("ok"):
                    self.usage.accepted(batch)
        except Exception as exc:
            log.warning("final report failed, kept for the next start: %s", exc)
            self.usage.save()
        for svc in self.services:
            svc.stop()
        charon.stop()
        firewall.remove()


def main() -> None:
    agent = Agent()
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set())
    signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    agent.run()
    sys.exit(0)


if __name__ == "__main__":
    main()
