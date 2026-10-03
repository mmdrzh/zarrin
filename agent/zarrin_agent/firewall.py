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

CHAINS = (("filter", "FORWARD", "ZARRIN-FWD"), ("nat", "POSTROUTING", "ZARRIN-NAT"), ("mangle", "FORWARD", "ZARRIN-MSS"),
          ("filter", "INPUT", "ZARRIN-IN"), ("nat", "PREROUTING", "ZARRIN-PRE"))
# What each chain was last built with, so a change of content (not only of
# rule count) rebuilds it.
_applied: dict[str, list[list[str]]] = {}


def run(*cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _rules(pools: list[str], mss: str, l2tp: bool, redirects: list[tuple[str, int, int]]) -> dict[str, list[list[str]]]:
    body = {"ZARRIN-FWD": [], "ZARRIN-NAT": [], "ZARRIN-MSS": [], "ZARRIN-IN": [], "ZARRIN-PRE": []}
    # Extra ports for a service (OpenVPN's alternative ports): new incoming
    # connections are redirected to the port the service listens on. Only new
    # connections pass through nat PREROUTING, so replies to this server's own
    # outgoing connections that happen to use the same port are untouched.
    for proto, port, to in redirects:
        body["ZARRIN-PRE"].append(["-p", proto, "--dport", str(port), "-m", "addrtype", "--dst-type", "LOCAL",
                                   "-j", "REDIRECT", "--to-ports", str(to)])
    if l2tp:
        # L2TP itself is unencrypted: accept it only from inside IPsec.
        body["ZARRIN-IN"] = [
            ["-p", "udp", "--dport", "1701", "-m", "policy", "--dir", "in", "--pol", "ipsec", "-j", "RETURN"],
            ["-p", "udp", "--dport", "1701", "-j", "DROP"],
        ]
    for pool in pools:
        body["ZARRIN-FWD"] += [["-s", pool, "-j", "ACCEPT"], ["-d", pool, "-j", "ACCEPT"]]
        body["ZARRIN-NAT"] += [["-s", pool, "!", "-d", pool, "-j", "MASQUERADE"]]
        body["ZARRIN-MSS"] += [
            ["-s", pool, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mss],
            ["-d", pool, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mss],
        ]
    return body


def ensure(pools: list[str], mss: str = "1250", l2tp: bool = False,
           redirects: list[tuple[str, int, int]] | None = None) -> None:
    """Idempotent: a chain is rebuilt only when it does not hold exactly the
    rules for these pools, and the jump into it is put back if something
    (a Docker restart) removed it."""
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        run("sysctl", "-w", "net.ipv4.ip_forward=1")
    body = _rules(pools, mss, l2tp, redirects or [])
    for table, parent, chain in CHAINS:
        listing = run("iptables", "-t", table, "-S", chain)
        if listing.returncode != 0:
            run("iptables", "-t", table, "-N", chain)
            have = []
        else:
            have = [ln for ln in listing.stdout.splitlines() if ln.startswith("-A ")]
        ok = len(have) == len(body[chain]) and _applied.get(chain) == body[chain]
        if not ok:
            run("iptables", "-t", table, "-F", chain)
            for rule in body[chain]:
                run("iptables", "-t", table, "-A", chain, *rule, check=True)
            _applied[chain] = body[chain]
            log.info("firewall: %s rebuilt (%d rules)", chain, len(body[chain]))
        if run("iptables", "-t", table, "-C", parent, "-j", chain).returncode != 0:
            run("iptables", "-t", table, "-I", parent, "1", "-j", chain, check=True)


def remove() -> None:
    for table, parent, chain in CHAINS:
        while run("iptables", "-t", table, "-D", parent, "-j", chain).returncode == 0:
            pass
        run("iptables", "-t", table, "-F", chain)
        run("iptables", "-t", table, "-X", chain)
