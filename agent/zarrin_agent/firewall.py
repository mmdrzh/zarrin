"""Forwarding, NAT and MSS clamping for the VPN client pools, in chains of our
own (ZARRIN-*), so they never collide with Docker's, pg-node's or the host
firewall's rules.

The host's FORWARD policy is DROP (Docker), so without the ACCEPT rules a
tunnel comes up but carries nothing. MSS 1250 keeps big TCP transfers from
stalling on small-MTU mobile paths that drop the ICMP needed for PMTU.
"""

import logging
import subprocess
from pathlib import Path

log = logging.getLogger("zarrin.firewall")

CHAINS = (("filter", "FORWARD", "ZARRIN-FWD"), ("nat", "POSTROUTING", "ZARRIN-NAT"), ("mangle", "FORWARD", "ZARRIN-MSS"))


def run(*cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _rules(pools: list[str], mss: str) -> dict[str, list[list[str]]]:
    body = {"ZARRIN-FWD": [], "ZARRIN-NAT": [], "ZARRIN-MSS": []}
    for pool in pools:
        body["ZARRIN-FWD"] += [["-s", pool, "-j", "ACCEPT"], ["-d", pool, "-j", "ACCEPT"]]
        body["ZARRIN-NAT"] += [["-s", pool, "!", "-d", pool, "-j", "MASQUERADE"]]
        body["ZARRIN-MSS"] += [
            ["-s", pool, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mss],
            ["-d", pool, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mss],
        ]
    return body


def ensure(pools: list[str], mss: str = "1250") -> None:
    """Idempotent: a chain is rebuilt only when it does not hold exactly the
    rules for these pools, and the jump into it is put back if something
    (a Docker restart) removed it."""
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        run("sysctl", "-w", "net.ipv4.ip_forward=1")
    body = _rules(pools, mss)
    for table, parent, chain in CHAINS:
        listing = run("iptables", "-t", table, "-S", chain)
        if listing.returncode != 0:
            run("iptables", "-t", table, "-N", chain)
            have = []
        else:
            have = [ln for ln in listing.stdout.splitlines() if ln.startswith("-A ")]
        ok = len(have) == len(body[chain]) and all(any(p in ln for ln in have) for p in pools)
        if not ok:
            run("iptables", "-t", table, "-F", chain)
            for rule in body[chain]:
                run("iptables", "-t", table, "-A", chain, *rule, check=True)
            log.info("firewall: %s rebuilt for %s", chain, ", ".join(pools) or "no pools")
        if run("iptables", "-t", table, "-C", parent, "-j", chain).returncode != 0:
            run("iptables", "-t", table, "-I", parent, "1", "-j", chain, check=True)


def remove() -> None:
    for table, parent, chain in CHAINS:
        while run("iptables", "-t", table, "-D", parent, "-j", chain).returncode == 0:
            pass
        run("iptables", "-t", table, "-F", chain)
        run("iptables", "-t", table, "-X", chain)
