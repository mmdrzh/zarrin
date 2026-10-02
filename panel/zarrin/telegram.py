"""Sending backups (and short notices) to a Telegram chat through a bot."""

import logging
from pathlib import Path

import httpx

from .store import store

log = logging.getLogger("zarrin.telegram")

# Bots may upload files up to 50 MB; parts stay under that with room to spare.
PART_BYTES = 45 * 1000 * 1000


class TelegramError(Exception):
    pass


async def _client() -> tuple[httpx.AsyncClient, str, str]:
    token = (await store.get("telegram_bot_token") or "").strip()
    chat = str(await store.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        raise TelegramError("ربات تلگرام تنظیم نشده")
    proxy = (await store.get("telegram_proxy") or "").strip() or None
    return httpx.AsyncClient(proxy=proxy, timeout=httpx.Timeout(30, write=600, read=120)), token, chat


async def send_message(text: str) -> None:
    http, token, chat = await _client()
    async with http:
        r = await http.post(f"https://api.telegram.org/bot{token}/sendMessage",
                            data={"chat_id": chat, "text": text, "disable_web_page_preview": "true"})
    if r.status_code != 200:
        raise TelegramError(_describe(r))


async def send_file(path: Path, caption: str) -> int:
    """Sends the file, split into .partNN pieces when it is too big for one
    message. Returns the number of messages sent."""
    http, token, chat = await _client()
    size = path.stat().st_size
    parts = max(1, -(-size // PART_BYTES))
    async with http:
        with path.open("rb") as f:
            for i in range(parts):
                chunk = f.read(PART_BYTES)
                name = path.name if parts == 1 else f"{path.name}.part{i + 1:02d}"
                text = caption if parts == 1 else f"{caption}\n📦 part {i + 1}/{parts}"
                r = await http.post(
                    f"https://api.telegram.org/bot{token}/sendDocument",
                    data={"chat_id": chat, "caption": text[:1000]},
                    files={"document": (name, chunk, "application/octet-stream")},
                )
                if r.status_code != 200:
                    raise TelegramError(_describe(r))
    return parts


def _describe(r: httpx.Response) -> str:
    try:
        return f"Telegram {r.status_code}: {r.json().get('description', '')}"
    except ValueError:
        return f"Telegram {r.status_code}"
