"""FastAPI app. Bearer-token auth on everything except /health and the static web UI shell."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import __author__, __version__, ai
from .collector import HostKeyMismatch
from .engine import Engine
from .runbooks import RUNBOOKS, RunbookError, Runbooks
from .servers import RegistryError, ServerRegistry

log = logging.getLogger("tileops.api")
WEB = Path(__file__).parent / "web" / "index.html"

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class SnoozeBody(BaseModel):
    minutes: int = Field(60, ge=1, le=7 * 24 * 60)


class RunBody(BaseModel):
    server: str = Field(..., max_length=64)
    service: str = Field(..., max_length=64)
    alert_id: int | None = None


class ApproveBody(BaseModel):
    pin: str = Field(..., min_length=1, max_length=64)


class ServerBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(22, ge=1, le=65535)
    user: str = Field("tileops", max_length=32)
    web_roots: list[str] = Field(default_factory=lambda: ["/var/www"], max_length=10)
    services: list[str] = Field(default_factory=list, max_length=20)
    health_urls: dict[str, str] = Field(default_factory=dict)
    process_allowlist: list[str] = Field(default_factory=list, max_length=100)


class ServerUpdate(BaseModel):
    host: str | None = Field(None, max_length=253)
    port: int | None = Field(None, ge=1, le=65535)
    user: str | None = Field(None, max_length=32)
    web_roots: list[str] | None = Field(None, max_length=10)
    services: list[str] | None = Field(None, max_length=20)
    health_urls: dict[str, str] | None = None
    process_allowlist: list[str] | None = Field(None, max_length=100)


class TrustBody(BaseModel):
    fingerprint: str = Field(..., min_length=10, max_length=128)


def create_app(engine: Engine, token: str, start_scheduler: bool = True,
               registry: ServerRegistry | None = None) -> FastAPI:
    runbooks = Runbooks(engine)
    db = engine.db
    registry = registry or ServerRegistry(engine.cfg, engine.db, engine.collector.pins)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(engine.run_forever()) if start_scheduler else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="TileOps companion", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine = engine
    app.state.runbooks = runbooks
    app.state.registry = registry

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if request.url.path == "/":
            resp.headers["Content-Security-Policy"] = CSP
        return resp

    def auth(request: Request) -> None:
        h = request.headers.get("authorization", "")
        scheme, _, got = h.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(got.strip().encode(), token.encode()):
            raise HTTPException(401, "invalid or missing bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    @app.exception_handler(RunbookError)
    async def _rb_err(_req, exc: RunbookError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.code)

    @app.exception_handler(RegistryError)
    async def _reg_err(_req, exc: RegistryError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.code)

    # ------------------------------------------------------------ public
    @app.get("/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/about")
    def about():
        return {"name": "TileOps", "version": __version__, "author": __author__,
                "description": "Agentless server security + ops monitor"}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB, media_type="text/html")

    # ------------------------------------------------------------ authed
    A = [Depends(auth)]

    @app.get("/api/status", dependencies=A)
    def status():
        return engine.overall()

    @app.get("/api/servers", dependencies=A)
    def servers():
        return engine.servers()

    def _server_out(name: str) -> dict:
        return next(s for s in engine.servers() if s["name"] == name)

    def _known(name: str):
        try:
            return engine.cfg.server(name)
        except KeyError:
            raise HTTPException(404, "unknown server")

    # ---- add / edit / remove servers from the app (phone-only users never edit YAML)
    @app.post("/api/servers", dependencies=A, status_code=201)
    def add_server(body: ServerBody):
        sc = registry.add(body.model_dump())
        return {"server": _server_out(sc.name), "setup": registry.setup_info(sc.name)}

    @app.put("/api/servers/{name}", dependencies=A)
    def update_server(name: str, body: ServerUpdate):
        registry.update(name, body.model_dump(exclude_none=True))
        return _server_out(name)

    @app.delete("/api/servers/{name}", dependencies=A)
    def delete_server(name: str):
        registry.remove(name)
        return {"ok": True, "removed": name}

    @app.get("/api/servers/{name}/setup", dependencies=A)
    def server_setup(name: str):
        return registry.setup_info(name)

    @app.get("/api/servers/{name}/hostkey", dependencies=A)
    async def server_hostkey(name: str):
        sc = _known(name)
        try:
            key = await engine.collector.fetch_host_key(sc)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"could not reach {sc.host}:{sc.port}: {type(e).__name__}: {e}")
        fp = key.get_fingerprint("sha256")
        pinned = engine.collector.pins.fingerprint(sc)
        return {"fingerprint": fp, "key_type": key.get_algorithm(), "pinned": pinned,
                "matches_pin": pinned == fp if pinned else None}

    @app.post("/api/servers/{name}/trust", dependencies=A)
    async def server_trust(name: str, body: TrustBody):
        sc = _known(name)
        try:
            key = await engine.collector.fetch_host_key(sc)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"could not reach {sc.host}:{sc.port}: {type(e).__name__}")
        fp = key.get_fingerprint("sha256")
        if not hmac.compare_digest(fp, body.fingerprint.strip()):
            raise HTTPException(409, f"the server now presents {fp}, not the fingerprint you confirmed; nothing trusted")
        engine.collector.pins.pin(sc, key)
        db.kv_set(f"hostkey_trusted:{name}", str(time.time()))
        return {"ok": True, "pinned": fp}

    @app.post("/api/servers/{name}/test", dependencies=A)
    async def server_test(name: str):
        sc = _known(name)
        try:
            info = await engine.collector.check_access(sc)
        except HostKeyMismatch as e:
            return {"ok": False, "stage": "hostkey", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            msg = f"{type(e).__name__}: {e}"
            stage = "hostkey" if "not confirmed" in msg else "auth" if "PermissionDenied" in msg else "connect"
            hint = {"hostkey": "Fetch and trust the host key first.",
                    "auth": "The server did not accept the TileOps key. Run the setup command, then test again.",
                    "connect": f"Can't reach {sc.host}:{sc.port} from the companion (firewall? wrong port?)."}[stage]
            return {"ok": False, "stage": stage, "message": hint, "error": msg[:300]}
        warn = None if info["sudo_ok"] else ("Logged in, but the sudo rules are missing: "
                                             "TileOps will run in degraded (read-only) mode.")
        return {"ok": True, "stage": "done", "user": info["user"], "sudo_ok": info["sudo_ok"],
                "ss_ok": info["ss_ok"], "systemctl": info["systemctl"], "message": warn or "All good."}

    @app.post("/api/servers/{name}/scan", dependencies=A)
    async def scan(name: str):
        try:
            engine.cfg.server(name)
        except KeyError:
            raise HTTPException(404, "unknown server")
        return await engine.scan(name)

    @app.post("/api/scan", dependencies=A)
    async def scan_all():
        return [await engine.scan(s.name) for s in engine.cfg.servers]

    @app.get("/api/alerts", dependencies=A)
    def alerts(status: str | None = "active", server: str | None = None):
        if status == "all":
            status = None
        return engine.list_alerts(status, server)

    def _alert(aid: int) -> dict:
        a = engine.get_alert(aid)
        if not a:
            raise HTTPException(404, "alert not found")
        return a

    @app.get("/api/alerts/{aid}", dependencies=A)
    def alert(aid: int):
        a = _alert(aid)
        rep = db.one("SELECT created_at, model, report FROM ai_reports WHERE alert_id=?", (aid,))
        a["ai_report"] = {**json.loads(rep["report"]), "created_at": rep["created_at"]} if rep else None
        a["runbook_options"] = [
            {"runbook": "restart-service", "server": a["server"], "service": s}
            for s in engine.cfg.server(a["server"]).services
            if s in engine.cfg.server(a["server"]).health_urls
        ] if a["server"] in [s.name for s in engine.cfg.servers] else []
        return a

    @app.post("/api/alerts/{aid}/ack", dependencies=A)
    def ack(aid: int):
        _alert(aid)
        return engine.ack(aid)

    @app.post("/api/alerts/{aid}/snooze", dependencies=A)
    def snooze(aid: int, body: SnoozeBody):
        _alert(aid)
        return engine.snooze(aid, body.minutes)

    @app.post("/api/alerts/{aid}/accept", dependencies=A)
    def accept(aid: int):
        _alert(aid)
        return engine.accept_baseline(aid)

    @app.get("/api/ai", dependencies=A)
    def ai_status():
        return {"enabled": ai.enabled(), "model": engine.cfg.ai_model if ai.enabled() else None,
                "message": None if ai.enabled() else "AI not configured"}

    @app.post("/api/alerts/{aid}/investigate", dependencies=A)
    async def investigate(aid: int):
        a = _alert(aid)
        if not ai.enabled():
            raise HTTPException(503, "AI not configured")
        try:
            report = await ai.investigate(a, engine.cfg.ai_model)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"AI investigation failed: {e}")
        now = time.time()
        db.x("INSERT OR REPLACE INTO ai_reports VALUES (?,?,?,?)",
             (aid, now, report.get("_model"), json.dumps(report)))
        db.event(a["incident_id"], "ai_report", "AI investigation report added (advisory only)",
                 {"alert_id": aid})
        return {**report, "created_at": now}

    @app.get("/api/incidents", dependencies=A)
    def incidents(limit: int = 100):
        return db.q("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (min(limit, 500),))

    @app.get("/api/incidents/{iid}", dependencies=A)
    def incident(iid: int):
        inc = db.one("SELECT * FROM incidents WHERE id=?", (iid,))
        if not inc:
            raise HTTPException(404, "incident not found")
        events = db.q("SELECT * FROM events WHERE incident_id=? ORDER BY ts, id", (iid,))
        for e in events:
            e["data"] = json.loads(e["data"]) if e["data"] else None
        inc["events"] = events
        inc["runs"] = [runbooks.get(r["id"]) for r in
                       db.q("SELECT id FROM runs WHERE incident_id=? ORDER BY id", (iid,))]
        return inc

    @app.get("/api/runbooks", dependencies=A)
    def runbook_list():
        return [{"id": k, **v} for k, v in RUNBOOKS.items()]

    @app.post("/api/runbooks/{rb}/run", dependencies=A)
    async def run_runbook(rb: str, body: RunBody):
        return await runbooks.start(rb, body.server, body.service, body.alert_id)

    @app.get("/api/runs", dependencies=A)
    def runs():
        return runbooks.list()

    @app.get("/api/runs/{rid}", dependencies=A)
    def run(rid: int):
        return runbooks.get(rid)

    @app.post("/api/runs/{rid}/approve", dependencies=A)
    async def approve(rid: int, body: ApproveBody):
        return await runbooks.approve(rid, body.pin)

    @app.post("/api/runs/{rid}/reject", dependencies=A)
    def reject(rid: int):
        return runbooks.reject(rid)

    return app
