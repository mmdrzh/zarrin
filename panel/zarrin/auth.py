"""Admin login: argon2 passwords, optional TOTP, a signed session cookie.

The cookie is HttpOnly, Secure and SameSite=Strict, and every state-changing
request must also carry the X-Zarrin header, which a cross-site page cannot
add without a CORS preflight that this app never answers.
"""

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request

from . import config
from .store import store

COOKIE = "zarrin_session"
SESSION_SECONDS = 12 * 3600
_hasher = PasswordHasher()
# A real hash to verify against when the username does not exist, so the
# response time does not tell which usernames exist.
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(pw_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(pw_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# ----------------------------------------------------------- rate limiting

class RateLimiter:
    """At most `limit` failures per key within `window` seconds."""

    def __init__(self, limit: int, window: int) -> None:
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)

    def blocked(self, key: str) -> bool:
        q = self.hits[key]
        now = time.monotonic()
        while q and q[0] < now - self.window:
            q.popleft()
        return len(q) >= self.limit

    def fail(self, key: str) -> None:
        self.hits[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        self.hits.pop(key, None)


login_ip_limiter = RateLimiter(10, 15 * 60)
login_user_limiter = RateLimiter(8, 15 * 60)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


# ---------------------------------------------------------------- sessions

def issue_session(admin: dict) -> str:
    now = int(time.time())
    payload = {"sub": str(admin["id"]), "ver": admin["token_version"], "iat": now, "exp": now + SESSION_SECONDS}
    return jwt.encode(payload, config.SECRET, algorithm="HS256")


async def current_admin(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "not logged in")
    try:
        payload = jwt.decode(token, config.SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "session expired")
    admin = await store.fetchone("SELECT * FROM admins WHERE id = ?", int(payload["sub"]))
    if admin is None or admin["token_version"] != payload.get("ver"):
        raise HTTPException(401, "session revoked")
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Zarrin") != "1":
        raise HTTPException(403, "missing X-Zarrin header")
    return admin


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=True,
                        samesite="strict", path="/")


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")


# -------------------------------------------------------------------- TOTP

def totp_ok(secret: str | None, code: str | None) -> bool:
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=f"Zarrin {config.DOMAIN}".strip())


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


async def authenticate(username: str, password: str, code: str | None, ip: str) -> tuple[dict | None, str]:
    """Returns (admin, "") on success or (None, reason)."""
    if login_ip_limiter.blocked(ip) or login_user_limiter.blocked(username.lower()):
        return None, "too_many_attempts"
    admin = await store.fetchone("SELECT * FROM admins WHERE username = ?", username)
    if admin is None:
        verify_password(_DUMMY_HASH, password)
        login_ip_limiter.fail(ip)
        return None, "invalid"
    if not verify_password(admin["pw_hash"], password):
        login_ip_limiter.fail(ip)
        login_user_limiter.fail(username.lower())
        return None, "invalid"
    if admin["totp_secret"]:
        if not code:
            return None, "totp_required"
        if not totp_ok(admin["totp_secret"], code):
            login_ip_limiter.fail(ip)
            login_user_limiter.fail(username.lower())
            return None, "totp_invalid"
    login_ip_limiter.reset(ip)
    login_user_limiter.reset(username.lower())
    return admin, ""
