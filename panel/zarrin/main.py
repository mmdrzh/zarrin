"""Zarrin panel: admin UI + agent API on ZARRIN_PORT, and the legacy pg-ikev2
bridge API on LEGACY_PORT, served from one process."""

import asyncio
import contextlib
import logging
import signal

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import api_admin, api_agent, backup, certs, config
from .legacy import legacy_app, sub_router
from .pg import pg
from .store import store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("zarrin")

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}


def main_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    app.include_router(api_admin.router)
    app.include_router(api_agent.router)
    app.include_router(sub_router)

    @app.get("/health")
    async def health():
        return {"ok": True, "db": await pg.ping()}

    web = config.WEB_DIR
    if (web / "assets").exists():
        app.mount("/assets", StaticFiles(directory=web / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        # Single-page app: every unknown path is the same index.html.
        if path.startswith(("api/", "agent/")):
            return JSONResponse({"detail": "not found"}, status_code=404)
        target = (web / path).resolve()
        if path and target.is_file() and web.resolve() in target.parents:
            return FileResponse(target)
        index = web / "index.html"
        if index.exists():
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return JSONResponse({"detail": "web UI not built"}, status_code=503)

    return app


class Server(uvicorn.Server):
    """Two of these share one event loop; signals are handled once, in run()."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def run() -> None:
    await store.open()
    await pg.open()
    certs.ensure_present()

    main_cfg = uvicorn.Config(main_app(), host="0.0.0.0", port=config.PORT, ssl_certfile=str(certs.FULLCHAIN),
                              ssl_keyfile=str(certs.PRIVKEY), log_level="warning", proxy_headers=False,
                              server_header=False, access_log=False)
    main_cfg.load()
    certs.contexts.append(main_cfg.ssl)
    servers = [Server(main_cfg)]
    if config.LEGACY_PORT:
        legacy_cfg = uvicorn.Config(legacy_app(), host="0.0.0.0", port=config.LEGACY_PORT,
                                    ssl_certfile=config.LEGACY_TLS_CERT or None, ssl_keyfile=config.LEGACY_TLS_KEY or None,
                                    log_level="warning", proxy_headers=False, server_header=False, access_log=False)
        legacy_cfg.load()
        servers.append(Server(legacy_cfg))

    loop = asyncio.get_running_loop()

    def stop(*_):
        for s in servers:
            s.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)

    async def housekeeping():
        while True:
            try:
                await store.prune()
                # PasarGuard's certificate (served on the legacy port) is renewed by acme.sh.
                if config.LEGACY_PORT and config.LEGACY_TLS_CERT and servers[-1].config.ssl:
                    servers[-1].config.ssl.load_cert_chain(config.LEGACY_TLS_CERT, config.LEGACY_TLS_KEY)
            except Exception:
                log.exception("housekeeping")
            await asyncio.sleep(3600)

    tasks = [asyncio.create_task(certs.renewer()), asyncio.create_task(backup.scheduler()),
             asyncio.create_task(housekeeping())]
    log.info("Zarrin %s on :%s%s", config.VERSION, config.PORT,
             f" (legacy bridge API on :{config.LEGACY_PORT})" if config.LEGACY_PORT else "")
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        for t in tasks:
            t.cancel()
        await pg.close()
        await store.close()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
