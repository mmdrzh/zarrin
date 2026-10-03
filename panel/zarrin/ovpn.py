"""OpenVPN's keys, made once and shared by every node: a private CA, the
server certificate it signs, and the tls-crypt key. Users authenticate with
username and password, so the client profile (.ovpn) is the same for all of
them; it only differs between UDP and TCP.
"""

import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .store import store

SERVER_NAME = "zarrin-openvpn"
POOL_UDP = "10.68.0.0/17"
POOL_TCP = "10.68.128.0/17"


def _pem_key(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _pem_cert(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def generate() -> dict:
    now = datetime.now(timezone.utc)
    years = timedelta(days=365 * 20)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zarrin OpenVPN CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + years)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + years)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            # digitalSignature + keyAgreement, serverAuth: what remote-cert-tls server checks.
            .add_extension(x509.KeyUsage(True, False, False, False, True, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    raw = secrets.token_bytes(256)
    hexed = raw.hex()
    tls_crypt = ("-----BEGIN OpenVPN Static key V1-----\n"
                 + "\n".join(hexed[i:i + 32] for i in range(0, len(hexed), 32))
                 + "\n-----END OpenVPN Static key V1-----\n")
    return {"ca": _pem_cert(ca), "ca_key": _pem_key(ca_key), "cert": _pem_cert(cert), "key": _pem_key(key),
            "tls_crypt": tls_crypt}


async def pki() -> dict:
    data = await store.get("ovpn_pki")
    if not data:
        data = generate()
        await store.set("ovpn_pki", data)
    return data


async def ports() -> tuple[int, int]:
    return int(await store.get("ovpn_udp_port") or 0), int(await store.get("ovpn_tcp_port") or 0)


def parse_ports(text) -> list[int]:
    out = []
    for part in str(text or "").replace(" ", "").split(","):
        if part.isdigit() and 0 < int(part) < 65536 and int(part) not in out:
            out.append(int(part))
    return out


async def alt_ports() -> tuple[list[int], list[int]]:
    return parse_ports(await store.get("ovpn_udp_alt_ports")), parse_ports(await store.get("ovpn_tcp_alt_ports"))


async def remotes(proto: str) -> list[tuple[int, str]]:
    """(port, proto) in the order a client should try them: the main port
    first, then the alternatives; "auto" is every UDP port, then every TCP one."""
    udp, tcp = await ports()
    udp_alt, tcp_alt = await alt_ports()
    out = []
    if proto in ("udp", "auto") and udp:
        out += [(p, "udp") for p in [udp] + [p for p in udp_alt if p != udp]]
    if proto in ("tcp", "auto") and tcp:
        out += [(p, "tcp-client") for p in [tcp] + [p for p in tcp_alt if p != tcp]]
    return out


async def profile(proto: str, server: str) -> str:
    """The client profile; username and password are asked by the app. Every
    port is a `remote` line, so the app moves on to the next one when a port
    is blocked (after server-poll-timeout)."""
    keys = await pki()
    targets = await remotes(proto)
    lines = ["client", "dev tun",
             *[f"remote {server} {port} {p}" for port, p in targets],
             "server-poll-timeout 5", "connect-retry 2",
             "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
             "remote-cert-tls server", f"verify-x509-name {SERVER_NAME} name",
             "auth-user-pass",
             # Tells OpenVPN Connect there is no client certificate to ask for
             # (login is username/password only); plain OpenVPN ignores it.
             "setenv CLIENT_CERT 0",
             "data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305", "tls-version-min 1.2",
             "verb 3"]
    if proto == "udp":
        lines.append("explicit-exit-notify 1")
    return ("\n".join(lines) + "\n"
            + f"<ca>\n{keys['ca'].strip()}\n</ca>\n"
            + f"<tls-crypt>\n{keys['tls_crypt'].strip()}\n</tls-crypt>\n")
