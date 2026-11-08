"""SQLite persistence (stdlib only). One connection guarded by a lock; all calls are short."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
  server TEXT, probe TEXT, key TEXT, value TEXT,
  PRIMARY KEY (server, probe, key));
CREATE TABLE IF NOT EXISTS baseline_meta (
  server TEXT, probe TEXT, created_at REAL, PRIMARY KEY (server, probe));
CREATE TABLE IF NOT EXISTS hot_procs (
  server TEXT, name TEXT, streak INTEGER, last_seen REAL, PRIMARY KEY (server, name));
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server TEXT, tripwire TEXT, key TEXT, fingerprint TEXT UNIQUE,
  title TEXT, severity TEXT, status TEXT DEFAULT 'open', snooze_until REAL,
  first_seen REAL, last_seen REAL, count INTEGER DEFAULT 1,
  evidence TEXT, new_value TEXT, incident_id INTEGER);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, server TEXT, alert_id INTEGER,
  status TEXT DEFAULT 'open', created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, ts REAL,
  kind TEXT, message TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, runbook TEXT, server TEXT, service TEXT,
  incident_id INTEGER, alert_id INTEGER, status TEXT, created_at REAL, updated_at REAL,
  approval TEXT, steps TEXT, pin_failures INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, server TEXT, started REAL, finished REAL,
  ok INTEGER, error TEXT, new_alerts INTEGER, degraded TEXT);
CREATE TABLE IF NOT EXISTS ai_reports (
  alert_id INTEGER PRIMARY KEY, created_at REAL, model TEXT, report TEXT);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS servers (name TEXT PRIMARY KEY, data TEXT, created_at REAL);
"""


class DB:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        try:
            Path(self.path).chmod(0o600)
        except OSError:
            pass

    def q(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args=()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args=()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid

    # ---------------------------------------------------------------- baseline
    def has_baseline(self, server: str, probe: str) -> bool:
        return self.one("SELECT 1 FROM baseline_meta WHERE server=? AND probe=?", (server, probe)) is not None

    def get_baseline(self, server: str, probe: str) -> dict:
        rows = self.q("SELECT key, value FROM baseline WHERE server=? AND probe=?", (server, probe))
        return {r["key"]: json.loads(r["value"]) for r in rows}

    def save_baseline(self, server: str, probe: str, items: dict) -> None:
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.execute("DELETE FROM baseline WHERE server=? AND probe=?", (server, probe))
                self.conn.executemany(
                    "INSERT INTO baseline VALUES (?,?,?,?)",
                    [(server, probe, k, json.dumps(v, sort_keys=True)) for k, v in items.items()],
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO baseline_meta VALUES (?,?,?)", (server, probe, time.time()))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def set_baseline_item(self, server: str, probe: str, key: str, value) -> None:
        if value is None:
            self.x("DELETE FROM baseline WHERE server=? AND probe=? AND key=?", (server, probe, key))
        else:
            self.x("INSERT OR REPLACE INTO baseline VALUES (?,?,?,?)",
                   (server, probe, key, json.dumps(value, sort_keys=True)))

    # ---------------------------------------------------------------- kv
    def kv_get(self, k: str) -> str | None:
        r = self.one("SELECT v FROM kv WHERE k=?", (k,))
        return r["v"] if r else None

    def kv_set(self, k: str, v: str) -> None:
        self.x("INSERT OR REPLACE INTO kv VALUES (?,?)", (k, v))

    # ---------------------------------------------------------------- timeline
    def event(self, incident_id: int | None, kind: str, message: str, data=None) -> None:
        if incident_id is None:
            return
        now = time.time()
        self.x("INSERT INTO events (incident_id, ts, kind, message, data) VALUES (?,?,?,?,?)",
               (incident_id, now, kind, message, json.dumps(data) if data is not None else None))
        self.x("UPDATE incidents SET updated_at=? WHERE id=?", (now, incident_id))

    def new_incident(self, title: str, server: str, alert_id: int | None = None) -> int:
        now = time.time()
        return self.x(
            "INSERT INTO incidents (title, server, alert_id, status, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)", (title, server, alert_id, "open", now, now))
