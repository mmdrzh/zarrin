"""The Zarrin panel's agent API, as seen from a node."""

import os

import requests

PANEL_URL = os.environ["PANEL_URL"].rstrip("/")
NODE_TOKEN = os.environ["NODE_TOKEN"]

http = requests.Session()
http.headers["Authorization"] = f"Bearer {NODE_TOKEN}"
http.headers["User-Agent"] = "zarrin-agent"


class Panel:
    def __init__(self) -> None:
        self.users_etag = ""

    def config(self) -> dict:
        r = http.get(f"{PANEL_URL}/agent/v1/config", timeout=15)
        r.raise_for_status()
        return r.json()

    def users(self) -> dict[str, str] | None:
        """{username: password}, or None when unchanged since the last call."""
        headers = {"If-None-Match": self.users_etag} if self.users_etag else {}
        r = http.get(f"{PANEL_URL}/agent/v1/users", headers=headers, timeout=15)
        if r.status_code == 304:
            return None
        r.raise_for_status()
        self.users_etag = r.headers.get("ETag", "")
        return r.json()["users"]

    def report(self, body: dict) -> dict:
        r = http.post(f"{PANEL_URL}/agent/v1/report", json=body, timeout=30)
        r.raise_for_status()
        return r.json()

    def cert(self, chain: bytes) -> None:
        http.post(f"{PANEL_URL}/agent/v1/cert", data=chain, timeout=15).raise_for_status()

    def peers(self) -> list[str]:
        r = http.get(f"{PANEL_URL}/agent/v1/peers", timeout=5)
        r.raise_for_status()
        return r.json()


panel = Panel()
