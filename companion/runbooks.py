"""Runbook engine. Typed steps only: no raw shell from config, API or AI.

restart-service: check status -> restart (needs PIN approval) -> verify health URL == 200
(1 try + 3 retries) -> verified | failed. "Done" means the health check passed, never just
exit code 0. Every step is written to the incident timeline."""
from __future__ import annotations

import asyncio
import json
import time

import httpx

from . import probes
from .config import SERVICE_RE
from .engine import Engine

RUNBOOKS = {
    "restart-service": {
        "title": "Restart service",
        "description": "Check status, restart an allowlisted systemd service (approval + PIN), "
                       "then verify its health URL returns HTTP 200.",
    }
}
MAX_PIN_FAILURES = 5
GLOBAL_PIN_FAILURES = 10  # across all runs, per 15 minutes
HEALTH_RETRIES = 3
HEALTH_DELAY = 2.0


class RunbookError(Exception):
    def __init__(self, msg: str, code: int = 400):
        super().__init__(msg)
        self.code = code


class Runbooks:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.db = engine.db
        self.cfg = engine.cfg
        self.health_delay = HEALTH_DELAY

    # ---------------------------------------------------------------- helpers
    def get(self, run_id: int) -> dict:
        r = self.db.one("SELECT * FROM runs WHERE id=?", (run_id,))
        if not r:
            raise RunbookError("run not found", 404)
        r["approval"] = json.loads(r["approval"] or "{}")
        r["steps"] = json.loads(r["steps"] or "[]")
        return r

    def list(self, limit: int = 50) -> list[dict]:
        return [self.get(r["id"]) for r in self.db.q("SELECT id FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    def _save(self, run: dict) -> None:
        self.db.x("UPDATE runs SET status=?, steps=?, updated_at=?, pin_failures=? WHERE id=?",
                  (run["status"], json.dumps(run["steps"]), time.time(), run["pin_failures"], run["id"]))

    def _step(self, run: dict, i: int, status: str, output: str = "", **extra) -> None:
        st = run["steps"][i]
        now = time.time()
        if status == "running":
            st["started"] = now
        else:
            st["finished"] = now
        st["status"] = status
        if output:
            st["output"] = output[-1500:]
        st.update(extra)
        self._save(run)
        if status != "running":
            self.db.event(run["incident_id"], f"runbook_step_{status}",
                          f"Run #{run['id']} step '{st['name']}': {status}",
                          {"run_id": run["id"], "step": st["name"], "output": st.get("output", "")[-400:]})

    # ---------------------------------------------------------------- create
    async def start(self, runbook: str, server_name: str, service: str, alert_id: int | None = None) -> dict:
        if runbook not in RUNBOOKS:
            raise RunbookError(f"unknown runbook {runbook!r}")
        try:
            server = self.cfg.server(server_name)
        except KeyError:
            raise RunbookError("unknown server", 404)
        if not isinstance(service, str) or not SERVICE_RE.match(service) or service not in server.services:
            raise RunbookError(f"service {service!r} is not allowlisted for {server_name}", 403)
        health_url = server.health_urls.get(service)
        if not health_url:
            raise RunbookError(f"no health URL configured for {service} on {server_name}")

        incident_id = None
        if alert_id is not None:
            a = self.engine.get_alert(int(alert_id))
            if not a:
                raise RunbookError("alert not found", 404)
            incident_id = a["incident_id"]
        if incident_id is None:
            incident_id = self.db.new_incident(f"Restart {service} on {server_name}", server_name)

        approval = {
            "target": f"{server.user}@{server.host}:{server.port} ({server.name})",
            "action": f"systemctl restart {service}",
            "command": probes.service_restart_cmd(server, service),
            "impact": (f"{service} on {server.name} stops and starts again; expect a few seconds of "
                       f"downtime and dropped in-flight connections. Success requires "
                       f"GET {health_url} to return HTTP 200 (up to {HEALTH_RETRIES} retries)."),
            "health_url": health_url,
            "requires_pin": True,
        }
        steps = [
            {"name": "check status", "kind": "check_status", "requires_approval": False, "status": "pending"},
            {"name": "restart", "kind": "restart", "requires_approval": True, "status": "pending"},
            {"name": "verify health", "kind": "verify_health", "requires_approval": False, "status": "pending"},
        ]
        now = time.time()
        run_id = self.db.x(
            "INSERT INTO runs (runbook, server, service, incident_id, alert_id, status, created_at, "
            "updated_at, approval, steps, pin_failures) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
            (runbook, server_name, service, incident_id, alert_id, "running", now, now,
             json.dumps(approval), json.dumps(steps)))
        self.db.event(incident_id, "runbook_started",
                      f"Runbook {runbook} #{run_id} started for {service} on {server_name}", {"run_id": run_id})
        run = self.get(run_id)

        # step 1: check status (read-only)
        self._step(run, 0, "running")
        try:
            r = await self.engine.collector.run_typed(server, probes.service_status_cmd(server, service))
            state = _active_state(r.stdout)
            self._step(run, 0, "ok", r.stdout or r.stderr, active_state=state, exit_status=r.exit_status)
        except Exception as e:  # noqa: BLE001
            self._step(run, 0, "failed", f"{type(e).__name__}: {e}")
            run["status"] = "failed"
            self._save(run)
            self.db.event(incident_id, "runbook_failed", f"Run #{run_id} failed: could not check status")
            return self.get(run_id)

        run["status"] = "awaiting_approval"
        self._save(run)
        self.db.event(incident_id, "approval_requested",
                      f"Approval needed: {approval['action']} on {approval['target']}", {"run_id": run_id})
        return self.get(run_id)

    # ---------------------------------------------------------------- approve / reject
    async def approve(self, run_id: int, pin: str) -> dict:
        run = self.get(run_id)
        if run["status"] != "awaiting_approval":
            raise RunbookError(f"run is {run['status']}, not awaiting approval", 409)
        recent = [t for t in json.loads(self.db.kv_get("pin_failures") or "[]") if t > time.time() - 900]
        if len(recent) >= GLOBAL_PIN_FAILURES:
            raise RunbookError("too many wrong PINs recently; wait 15 minutes", 429)
        if not self.cfg.check_pin(pin):
            self.db.kv_set("pin_failures", json.dumps(recent + [time.time()]))
            run["pin_failures"] += 1
            if run["pin_failures"] >= MAX_PIN_FAILURES:
                run["status"] = "locked"
                self.db.event(run["incident_id"], "runbook_locked",
                              f"Run #{run_id} locked after {MAX_PIN_FAILURES} wrong PINs")
            self._save(run)
            raise RunbookError("wrong PIN", 403)
        server = self.cfg.server(run["server"])
        run["status"] = "running"
        self._save(run)
        self.db.event(run["incident_id"], "approved", f"Run #{run_id} approved with PIN")

        # step 2: restart
        self._step(run, 1, "running")
        try:
            r = await self.engine.collector.run_typed(
                server, probes.service_restart_cmd(server, run["service"]), timeout=90)
            self._step(run, 1, "ok" if r.exit_status == 0 else "failed",
                       (r.stdout + r.stderr) or f"exit {r.exit_status}", exit_status=r.exit_status)
        except Exception as e:  # noqa: BLE001
            self._step(run, 1, "failed", f"{type(e).__name__}: {e}")

        # step 3: verify health (always attempted: the health check is the source of truth)
        self._step(run, 2, "running")
        ok, log = await self._verify(run["approval"]["health_url"])
        self._step(run, 2, "ok" if ok else "failed", "\n".join(log))
        run["status"] = "verified" if ok else "failed"
        self._save(run)
        self.db.event(run["incident_id"], f"runbook_{run['status']}",
                      f"Run #{run_id} {run['status']}: health check "
                      f"{'passed' if ok else 'did not pass'} ({run['approval']['health_url']})")
        return self.get(run_id)

    def reject(self, run_id: int) -> dict:
        run = self.get(run_id)
        if run["status"] != "awaiting_approval":
            raise RunbookError(f"run is {run['status']}", 409)
        run["status"] = "rejected"
        for st in run["steps"]:
            if st["status"] == "pending":
                st["status"] = "skipped"
        self._save(run)
        self.db.event(run["incident_id"], "runbook_rejected", f"Run #{run_id} rejected")
        return self.get(run_id)

    async def _verify(self, url: str) -> tuple[bool, list[str]]:
        log = []
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
            for attempt in range(1 + HEALTH_RETRIES):
                if attempt:
                    await asyncio.sleep(self.health_delay)
                try:
                    r = await c.get(url)
                    log.append(f"attempt {attempt + 1}: HTTP {r.status_code}")
                    if r.status_code == 200:
                        return True, log
                except httpx.HTTPError as e:
                    log.append(f"attempt {attempt + 1}: {type(e).__name__}")
        return False, log


def _active_state(status_output: str) -> str:
    for line in status_output.splitlines():
        s = line.strip()
        if s.startswith("Active:"):
            return s.split()[1] if len(s.split()) > 1 else "unknown"
    return "unknown"
