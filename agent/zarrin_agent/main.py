"""Zarrin node agent.

Runs the VPN services (IKEv2 today; L2TP, OpenVPN and WireGuard plug in the
same way) in the host's network namespace, beside PasarGuard's node and never
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
from .ikev2 import IKEv2
from .panel import panel
from .usage import Usage

VERSION = "0.1.0"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("zarrin.agent")

USERS_INTERVAL = 5
STATS_INTERVAL = 10
REPORT_INTERVAL = 15
CONFIG_INTERVAL = 30
LEGACY_PENDING = Path("/data/legacy-pending.json")


class Agent:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.ikev2 = IKEv2()
        self.services = [self.ikev2]
        self.usage = Usage()
        self.cfg: dict = {}
        self.users: dict[str, str] = {}
        self.users_synced = False
        self.sessions: list[dict] = []
        self.cert_reported = False

    # -------------------------------------------------------------- config

    def apply_config(self, cfg: dict) -> None:
        dns = cfg.get("dns", "8.8.8.8,1.1.1.1")
        ik = cfg["ikev2"]
        pools = [ik["pool"]] if ik["enabled"] else []
        firewall.ensure(pools)
        if ik["enabled"]:
            if not self.ikev2.running:
                self.ensure_certificate(ik["server_id"], cfg.get("acme_email", ""))
                self.ikev2.start(ik, dns)
                self.cert_reported = False
            elif self.ikev2.needs_restart(ik, dns):
                log.info("IKEv2 settings changed; restarting")
                self.collect()
                self.ikev2.stop()
                self.ensure_certificate(ik["server_id"], cfg.get("acme_email", ""))
                self.ikev2.start(ik, dns)
                self.cert_reported = False
        elif self.ikev2.running:
            log.info("IKEv2 turned off in the panel")
            self.collect()
            self.ikev2.stop()
        self.cfg = cfg

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
                for svc in self.services:
                    if svc.proc is not None and not svc.running:
                        log.error("%s exited; restarting", svc.name)
                        svc.proc = None
                        next_cfg = 0
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
        firewall.remove()


def main() -> None:
    agent = Agent()
    signal.signal(signal.SIGTERM, lambda *_: agent.stop.set())
    signal.signal(signal.SIGINT, lambda *_: agent.stop.set())
    agent.run()
    sys.exit(0)


if __name__ == "__main__":
    main()
