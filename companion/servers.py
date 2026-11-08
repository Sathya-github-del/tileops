"""Servers added from the app/API ("source: app"). Stored in SQLite next to the YAML servers.

Each app-added server gets its own companion-generated ed25519 key (state_dir/keys/<name>),
so removing a server revokes nothing else, and its host key must be confirmed by the user
before the first scan (no silent trust-on-first-use)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import asyncssh

from . import setup_script
from .collector import PinStore
from .config import Config, ConfigError, ServerConfig, validate_server
from .db import DB

MAX_SERVERS = 50
EDITABLE = ("host", "port", "user", "web_roots", "services", "health_urls", "process_allowlist")


class RegistryError(Exception):
    def __init__(self, msg: str, code: int = 400):
        super().__init__(msg)
        self.code = code


class ServerRegistry:
    def __init__(self, cfg: Config, db: DB, pins: PinStore):
        self.cfg = cfg
        self.db = db
        self.pins = pins
        self.keys_dir = cfg.state_dir / "keys"

    # ------------------------------------------------------------------ load/save
    def load(self) -> None:
        """Append app-added servers from the DB to cfg.servers (call once at startup)."""
        known = {s.name for s in self.cfg.servers}
        for row in self.db.q("SELECT name, data FROM servers ORDER BY created_at"):
            if row["name"] in known:
                continue  # a YAML server with the same name wins
            self.cfg.servers.append(self._from_dict(json.loads(row["data"])))

    def _from_dict(self, d: dict) -> ServerConfig:
        sc = ServerConfig(
            name=str(d["name"]), host=str(d["host"]), port=int(d.get("port", 22)),
            user=str(d.get("user", "tileops")), key_path=str(self.keys_dir / d["name"]),
            web_roots=list(d.get("web_roots") or ["/var/www"]), services=list(d.get("services") or []),
            health_urls=dict(d.get("health_urls") or {}), process_allowlist=list(d.get("process_allowlist") or []),
            source="app", confirm_hostkey=True,
        )
        validate_server(sc)
        return sc

    def _save(self, sc: ServerConfig) -> None:
        data = {k: v for k, v in sc.to_public().items() if k != "source"}
        self.db.x("INSERT INTO servers (name, data, created_at) VALUES (?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET data=excluded.data", (sc.name, json.dumps(data), time.time()))

    def _get_app_server(self, name: str) -> ServerConfig:
        try:
            sc = self.cfg.server(name)
        except KeyError:
            raise RegistryError("unknown server", 404)
        if sc.source != "app":
            raise RegistryError("this server is defined in the companion's config file; edit it there", 409)
        return sc

    # ------------------------------------------------------------------ keys
    def _key_path(self, name: str) -> Path:
        return self.keys_dir / name

    def public_key(self, name: str) -> str:
        return self._key_path(name).with_suffix(".pub").read_text().strip()

    def _make_key(self, name: str) -> str:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.chmod(0o700)
        key = asyncssh.generate_private_key("ssh-ed25519", comment=f"tileops-{name}")
        path = self._key_path(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.export_private_key("openssh"))
        pub = key.export_public_key("openssh").decode().strip()
        path.with_suffix(".pub").write_text(pub + "\n")
        return pub

    # ------------------------------------------------------------------ CRUD
    def add(self, data: dict) -> ServerConfig:
        name = str(data.get("name", "")).strip()
        if any(s.name == name for s in self.cfg.servers):
            raise RegistryError(f"a server named {name!r} already exists", 409)
        if len(self.cfg.servers) >= MAX_SERVERS:
            raise RegistryError(f"at most {MAX_SERVERS} servers", 409)
        try:
            sc = self._from_dict({**data, "name": name})
        except (ConfigError, KeyError, ValueError, TypeError) as e:
            raise RegistryError(str(e) or "invalid server")
        self._make_key(name)
        self._save(sc)
        self.cfg.servers.append(sc)
        return sc

    def update(self, name: str, data: dict) -> ServerConfig:
        old = self._get_app_server(name)
        merged = {**old.to_public(), **{k: v for k, v in data.items() if k in EDITABLE and v is not None}}
        try:
            new = self._from_dict({**merged, "name": name})
        except (ConfigError, KeyError, ValueError, TypeError) as e:
            raise RegistryError(str(e) or "invalid server")
        moved = (new.host, new.port) != (old.host, old.port)
        if moved:  # a different machine: forget its host key and baseline
            self.pins.unpin(old)
            self._forget_state(name)
        self.cfg.servers[self.cfg.servers.index(old)] = new
        self._save(new)
        return new

    def remove(self, name: str) -> None:
        sc = self._get_app_server(name)
        self.pins.unpin(sc)
        self._forget_state(name)
        self.db.x("DELETE FROM servers WHERE name=?", (name,))
        for p in (self._key_path(name), self._key_path(name).with_suffix(".pub")):
            p.unlink(missing_ok=True)
        self.cfg.servers.remove(sc)

    def _forget_state(self, name: str) -> None:
        for table in ("baseline", "baseline_meta", "hot_procs", "scans"):
            self.db.x(f"DELETE FROM {table} WHERE server=?", (name,))

    # ------------------------------------------------------------------ setup
    def setup_info(self, name: str) -> dict:
        sc = self._get_app_server(name)
        pub = self.public_key(name)
        script = setup_script.build(sc, pub)
        return {
            "server": name,
            "user": sc.user,
            "public_key": pub,
            "setup_script": script,
            "setup_command": setup_script.one_liner(script),
            "manual_steps": [
                f"Log in to {sc.host} with any SSH app as root or a sudo user.",
                "Paste the setup command and run it (it asks for your sudo password if needed).",
                "Check that it prints TILEOPS SETUP OK and note the ED25519 fingerprint.",
                "Back in TileOps: fetch the host key, compare the fingerprint, trust it, then test.",
                f"No root? Add the public key to ~/.ssh/authorized_keys of user '{sc.user}' "
                "(e.g. via your hosting panel); TileOps then runs in degraded (read-only) mode.",
            ],
        }
