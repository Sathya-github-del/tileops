"""Scan orchestration, baselines, alert lifecycle (dedup, ack, snooze, accept)."""
from __future__ import annotations

import asyncio
import json
import logging
import time

import asyncssh

from . import notify
from .collector import Collector, HostKeyMismatch, HostKeyNotConfirmed, ProbeResult
from .config import Config
from .db import DB
from .tripwires import Finding, diff, evaluate_processes, process_baseline

log = logging.getLogger("tileops.engine")

ACTIVE = ("open", "acked", "snoozed")


class Engine:
    def __init__(self, cfg: Config, db: DB, collector: Collector, notify_enabled: bool = True):
        self.cfg = cfg
        self.db = db
        self.collector = collector
        self.notify_enabled = notify_enabled and cfg.ntfy_enabled
        self._locks: dict[str, asyncio.Lock] = {}
        self._bg: set[asyncio.Task] = set()
        self.retry_delays: tuple[float, ...] = (5, 15)  # 3 connect attempts over ~20 s

    # ------------------------------------------------------------------ scanning
    def _lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    async def scan(self, server_name: str) -> dict:
        server = self.cfg.server(server_name)
        async with self._lock(server_name):
            started = time.time()
            try:
                results = await self._collect_with_retry(server)
            except HostKeyNotConfirmed as e:
                self._record_scan(server_name, started, False, f"setup: {e}", 0, [])
                return {"server": server_name, "ok": False, "error": str(e), "new_alerts": []}
            except asyncssh.PermissionDenied as e:
                hint = "key not accepted: run the setup command on the server" if server.source == "app" else str(e)
                self._record_scan(server_name, started, False, f"setup: {hint}", 0, [])
                return {"server": server_name, "ok": False, "error": hint, "new_alerts": []}
            except HostKeyMismatch as e:
                f = Finding("host_key", "host_key", f"{server.host}:{server.port}",
                            f"SSH host key mismatch for {server.host}:{server.port}", "critical",
                            "changed", None, {"error": "mismatch"})
                aid, new = self._raise(server_name, f, None, extra={"error": str(e)})
                self._record_scan(server_name, started, False, f"connect: {e}", int(new), [])
                return {"server": server_name, "ok": False, "error": str(e), "new_alerts": [aid] if new else []}
            except Exception as e:  # noqa: BLE001 - unreachable / auth errors are a server status
                err = f"connect: {type(e).__name__}: {e}"
                log.warning("scan of %s failed: %s", server_name, err)
                self._record_scan(server_name, started, False, err, 0, [])
                return {"server": server_name, "ok": False, "error": err, "new_alerts": []}

            new_ids: list[int] = []
            probe_errors = {}
            for res in results:
                if not res.ok:
                    probe_errors[res.name] = res.error
                    continue
                new_ids += self._evaluate(server_name, res)
            degraded = [r.name for r in results if r.degraded]
            err = "; ".join(f"{k}: {v}" for k, v in probe_errors.items())
            self._record_scan(server_name, started, not probe_errors, err, len(new_ids), degraded)
            return {"server": server_name, "ok": not probe_errors, "error": err,
                    "new_alerts": new_ids, "degraded": degraded}

    async def _collect_with_retry(self, server):
        """Retry transient network failures (Wi-Fi blips: EHOSTUNREACH, timeouts, resets) before a
        server counts as unreachable. Host-key mismatches and auth failures are never retried."""
        for attempt, delay in enumerate((*self.retry_delays, None)):
            try:
                return await self.collector.collect(server)
            except (HostKeyMismatch, HostKeyNotConfirmed, asyncssh.PermissionDenied):
                raise
            except (OSError, asyncio.TimeoutError, asyncssh.ConnectionLost) as e:
                if delay is None:
                    raise
                log.info("scan of %s: transient %s (attempt %d), retrying in %ss",
                         server.name, type(e).__name__, attempt + 1, delay)
                await asyncio.sleep(delay)

    def _record_scan(self, server, started, ok, error, n_new, degraded):
        self.db.x("INSERT INTO scans (server, started, finished, ok, error, new_alerts, degraded) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (server, started, time.time(), int(ok), error, n_new, json.dumps(degraded)))
        self.db.x("DELETE FROM scans WHERE server=? AND id NOT IN "
                  "(SELECT id FROM scans WHERE server=? ORDER BY id DESC LIMIT 500)", (server, server))

    def _evaluate(self, server: str, res: ProbeResult) -> list[int]:
        srv = self.cfg.server(server)
        if res.name == "processes":
            procs = res.data
            if not self.db.has_baseline(server, "processes"):
                self.db.save_baseline(server, "processes", process_baseline(procs))
                return []
            base = self.db.get_baseline(server, "processes")
            streaks = {r["name"]: r["streak"] for r in
                       self.db.q("SELECT name, streak FROM hot_procs WHERE server=?", (server,))}
            findings, new_streaks = evaluate_processes(
                procs, base, srv.process_allowlist, streaks,
                self.cfg.cpu_threshold, self.cfg.cpu_consecutive)
            self.db.x("DELETE FROM hot_procs WHERE server=?", (server,))
            for name, s in new_streaks.items():
                self.db.x("INSERT INTO hot_procs VALUES (?,?,?,?)", (server, name, s, time.time()))
        else:
            if not self.db.has_baseline(server, res.name):
                self.db.save_baseline(server, res.name, res.data)
                return []
            findings = diff(res.name, self.db.get_baseline(server, res.name), res.data)

        ids = []
        for f in findings:
            aid, new = self._raise(server, f, res)
            if new:
                ids.append(aid)
        return ids

    # ------------------------------------------------------------------ alerts
    @staticmethod
    def _excerpt(f: Finding, res: ProbeResult | None) -> str:
        if res is None:
            return ""
        needles = {f.key}
        if isinstance(f.new, dict):
            for k in ("user", "comment", "port", "name"):
                if f.new.get(k):
                    needles.add(str(f.new[k]))
            if f.probe == "ports":
                needles = {f":{f.new.get('port')} ", f":{f.new.get('port')}\t"}
        lines = [l for l in res.raw_excerpt.splitlines() if any(n and n in l for n in needles)]
        if f.probe == "cron":  # show the whole section for the cron source
            from .parsers import split_sections
            for header, body in split_sections(res.raw_excerpt):
                if header.strip() == f.key:
                    lines = [f"==> {header} <=="] + body.splitlines()
        if f.probe == "processes":
            lines = [l for l in res.raw_excerpt.splitlines()[:1]] + lines
        return "\n".join(lines[:25])[:2000] or res.raw_excerpt[:800]

    def _raise(self, server: str, f: Finding, res: ProbeResult | None, extra: dict | None = None):
        fp = f.fingerprint(server)
        now = time.time()
        existing = self.db.one("SELECT id FROM alerts WHERE fingerprint=?", (fp,))
        if existing:
            self.db.x("UPDATE alerts SET last_seen=?, count=count+1 WHERE id=?", (now, existing["id"]))
            return existing["id"], False
        evidence = {
            "probe": f.probe,
            "change": f.change,
            "key": f.key,
            "old": f.old,
            "new": f.new,
            "detail": f.detail,
            "command": res.command if res else "ssh connect (host key verification)",
            "raw_excerpt": self._excerpt(f, res),
            "collected_at": res.ts if res else now,
            "degraded": res.degraded if res else False,
        }
        if extra:
            evidence.update(extra)
        aid = self.db.x(
            "INSERT INTO alerts (server, tripwire, key, fingerprint, title, severity, status, "
            "first_seen, last_seen, count, evidence, new_value) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (server, f.tripwire, f.key, fp, f.title, f.severity, "open", now, now, 1,
             json.dumps(evidence, default=str), json.dumps(f.new, default=str)))
        inc = self.db.new_incident(f.title, server, aid)
        self.db.x("UPDATE alerts SET incident_id=? WHERE id=?", (inc, aid))
        self.db.event(inc, "alert_raised", f"[{f.severity}] {f.title}",
                      {"alert_id": aid, "tripwire": f.tripwire})
        self._notify(aid)
        return aid, True

    def _notify(self, aid: int) -> None:
        if not self.notify_enabled:
            return
        topic = self.cfg.ntfy_topic
        a = self.get_alert(aid)
        if not a or not topic:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        t = loop.create_task(notify.send(self.cfg.ntfy_server, topic, a, self.cfg.public_url))
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    def _row(self, r: dict | None) -> dict | None:
        if r is None:
            return None
        if r["status"] == "snoozed" and r["snooze_until"] and r["snooze_until"] < time.time():
            self.db.x("UPDATE alerts SET status='open', snooze_until=NULL WHERE id=?", (r["id"],))
            r["status"], r["snooze_until"] = "open", None
        r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else {}
        r.pop("new_value", None)
        r.pop("fingerprint", None)
        return r

    def get_alert(self, aid: int) -> dict | None:
        return self._row(self.db.one("SELECT * FROM alerts WHERE id=?", (aid,)))

    def list_alerts(self, status: str | None = None, server: str | None = None, limit: int = 200) -> list[dict]:
        rows = [self._row(r) for r in self.db.q("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]
        if server:
            rows = [r for r in rows if r["server"] == server]
        if status == "active":
            rows = [r for r in rows if r["status"] in ACTIVE]
        elif status:
            rows = [r for r in rows if r["status"] == status]
        for r in rows:
            r["evidence"] = {"probe": r["evidence"].get("probe"), "change": r["evidence"].get("change")}
        return rows

    def _set_status(self, aid: int, status: str, kind: str, msg: str, snooze_until=None) -> dict:
        a = self.get_alert(aid)
        if not a:
            raise KeyError(aid)
        self.db.x("UPDATE alerts SET status=?, snooze_until=? WHERE id=?", (status, snooze_until, aid))
        self.db.event(a["incident_id"], kind, msg, {"alert_id": aid})
        if status in ("accepted", "resolved"):
            self.db.x("UPDATE incidents SET status='closed' WHERE id=? AND status='open'", (a["incident_id"],))
        return self.get_alert(aid)

    def ack(self, aid: int) -> dict:
        return self._set_status(aid, "acked", "alert_acked", "Alert acknowledged")

    def snooze(self, aid: int, minutes: int) -> dict:
        minutes = max(1, min(int(minutes), 7 * 24 * 60))
        return self._set_status(aid, "snoozed", "alert_snoozed", f"Snoozed for {minutes} min",
                                time.time() + minutes * 60)

    def accept_baseline(self, aid: int) -> dict:
        row = self.db.one("SELECT * FROM alerts WHERE id=?", (aid,))
        if not row:
            raise KeyError(aid)
        ev = json.loads(row["evidence"])
        probe = ev.get("probe")
        if probe == "host_key":
            server = self.cfg.server(row["server"])
            self.collector.pins.unpin(server)  # re-pin on next scan
            msg = "Host key unpinned; the next scan pins the new key"
        elif probe == "processes":
            self.db.set_baseline_item(row["server"], "processes", row["key"], {"seen": True})
            self.db.x("DELETE FROM hot_procs WHERE server=? AND name=?", (row["server"], row["key"]))
            msg = f"Process '{row['key']}' added to baseline"
        else:
            self.db.set_baseline_item(row["server"], probe, row["key"], json.loads(row["new_value"]))
            msg = f"Accepted current state of {row['key']} as baseline"
        return self._set_status(aid, "accepted", "baseline_accepted", msg)

    # ------------------------------------------------------------------ status
    def servers(self) -> list[dict]:
        out = []
        for s in self.cfg.servers:
            last = self.db.one("SELECT * FROM scans WHERE server=? ORDER BY id DESC LIMIT 1", (s.name,))
            last_ok = self.db.one("SELECT finished FROM scans WHERE server=? AND ok=1 ORDER BY id DESC LIMIT 1", (s.name,))
            active = [a for a in self.list_alerts("active", s.name)]
            open_n = sum(1 for a in active if a["status"] == "open")  # acked/snoozed = being handled
            if last is None:
                status = "needs_setup" if s.confirm_hostkey and not self.collector.pins.get(s) else "pending"
            elif not last["ok"] and (last["error"] or "").startswith("connect:"):
                status = "unreachable"
            elif not last["ok"] and (last["error"] or "").startswith("setup:"):
                status = "needs_setup"
            else:
                status = "ok"
            if status == "ok" and open_n:
                status = "alert"
            out.append({
                "name": s.name, "host": s.host, "port": s.port, "user": s.user,
                "status": status,
                "last_scan": last["finished"] if last else None,
                "last_ok_scan": last_ok["finished"] if last_ok else None,
                "last_error": (last or {}).get("error") or None,
                "degraded_probes": json.loads(last["degraded"]) if last and last["degraded"] else [],
                "open_alerts": open_n,
                "services": s.services,
                "web_roots": s.web_roots,
                "health_urls": s.health_urls,
                "process_allowlist": s.process_allowlist,
                "source": s.source,
                "host_key": self.collector.pins.fingerprint(s),
            })
        return out

    def overall(self) -> dict:
        servers = self.servers()
        bad = [s for s in servers if s["status"] in ("alert", "unreachable")]
        return {
            "ok": not bad,
            "status": "ok" if not bad else "alert",
            "open_alerts": sum(s["open_alerts"] for s in servers),
            "servers": [{k: s[k] for k in ("name", "status", "open_alerts", "last_scan")} for s in servers],
        }

    # ------------------------------------------------------------------ scheduler
    async def run_forever(self) -> None:
        while True:
            for s in self.cfg.servers:
                try:
                    await self.scan(s.name)
                except Exception:  # noqa: BLE001
                    log.exception("scheduled scan of %s crashed", s.name)
            await asyncio.sleep(self.cfg.scan_interval)
