"""Configuration: one YAML file. Everything that reaches a remote shell is validated here."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SERVICE_RE = re.compile(r"^[A-Za-z0-9@._-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
WEBROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]{0,200}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class ConfigError(ValueError):
    pass


@dataclass
class ServerConfig:
    name: str
    host: str
    port: int = 22
    user: str = "tileops"
    key_path: str = ""
    web_roots: list[str] = field(default_factory=lambda: ["/var/www"])
    services: list[str] = field(default_factory=list)
    health_urls: dict[str, str] = field(default_factory=dict)
    process_allowlist: list[str] = field(default_factory=list)
    # "config" = from the YAML file (read-only in the app); "app" = added from the app/API
    source: str = "config"
    # app-added servers are never trusted on first use: the user confirms the host key fingerprint
    confirm_hostkey: bool = False

    def to_public(self) -> dict:
        return {
            "name": self.name, "host": self.host, "port": self.port, "user": self.user,
            "web_roots": self.web_roots, "services": self.services, "health_urls": self.health_urls,
            "process_allowlist": self.process_allowlist, "source": self.source,
        }


@dataclass
class Config:
    path: Path
    state_dir: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8800
    public_url: str = "https://127.0.0.1:8800"
    # HTTPS with a self-signed certificate pinned by the app (fingerprint in the pairing link)
    tls: bool = True
    scan_interval: int = 300
    cpu_threshold: float = 50.0
    cpu_consecutive: int = 2
    approval_pin_sha256: str = ""
    ntfy_enabled: bool = True
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ai_model: str = "claude-sonnet-5-5"
    servers: list[ServerConfig] = field(default_factory=list)

    def server(self, name: str) -> ServerConfig:
        for s in self.servers:
            if s.name == name:
                return s
        raise KeyError(name)

    def check_pin(self, pin: str) -> bool:
        import hmac

        if not self.approval_pin_sha256 or not isinstance(pin, str):
            return False
        got = hashlib.sha256(pin.encode()).hexdigest()
        return hmac.compare_digest(got, self.approval_pin_sha256)


def _resolve(base: Path, p: str) -> str:
    if not p:
        return p
    p = os.path.expanduser(p)
    return str(p if os.path.isabs(p) else (base / p).resolve())


def load(path: str | os.PathLike) -> Config:
    path = Path(path).resolve()
    raw = yaml.safe_load(path.read_text()) or {}
    base = path.parent
    state_dir = Path(_resolve(base, raw.get("state_dir", "./state")))

    pin_hash = raw.get("approval_pin_sha256") or ""
    if not pin_hash and raw.get("approval_pin") is not None:
        pin_hash = hashlib.sha256(str(raw["approval_pin"]).encode()).hexdigest()

    ntfy = raw.get("ntfy") or {}
    ai = raw.get("ai") or {}
    default_key = raw.get("key_path", "")

    cfg = Config(
        path=path,
        state_dir=state_dir,
        bind_host=str(raw.get("bind_host", "127.0.0.1")),
        bind_port=int(raw.get("bind_port", 8800)),
        public_url=str(raw.get("public_url", "")).rstrip("/")
        or f"http://{raw.get('bind_host', '127.0.0.1')}:{raw.get('bind_port', 8800)}",
        tls=bool(raw.get("tls", True)),
        scan_interval=max(30, int(raw.get("scan_interval", 300))),
        cpu_threshold=float(raw.get("cpu_threshold", 50)),
        cpu_consecutive=max(1, int(raw.get("cpu_consecutive", 2))),
        approval_pin_sha256=pin_hash,
        ntfy_enabled=bool(ntfy.get("enabled", True)),
        ntfy_server=str(ntfy.get("server", "https://ntfy.sh")).rstrip("/"),
        ntfy_topic=str(ntfy.get("topic", "") or ""),
        ai_model=str(ai.get("model", "claude-sonnet-5-5")),
    )

    if cfg.tls and cfg.public_url.startswith("http://"):
        cfg.public_url = "https://" + cfg.public_url[len("http://"):]
    elif not cfg.tls and cfg.public_url.startswith("https://"):
        cfg.public_url = "http://" + cfg.public_url[len("https://"):]

    seen = set()
    for s in raw.get("servers") or []:
        sc = ServerConfig(
            name=str(s["name"]),
            host=str(s["host"]),
            port=int(s.get("port", 22)),
            user=str(s.get("user", "tileops")),
            key_path=_resolve(base, s.get("key_path", default_key)),
            web_roots=list(s.get("web_roots", ["/var/www"])),
            services=list(s.get("services", [])),
            health_urls=dict(s.get("health_urls", {})),
            process_allowlist=list(s.get("process_allowlist", [])),
        )
        validate_server(sc)
        if sc.name in seen:
            raise ConfigError(f"duplicate server name {sc.name}")
        seen.add(sc.name)
        cfg.servers.append(sc)
    return cfg


def validate_server(sc: ServerConfig) -> None:
    if not NAME_RE.match(sc.name):
        raise ConfigError(f"bad server name {sc.name!r}")
    if not HOST_RE.match(sc.host):
        raise ConfigError(f"bad host {sc.host!r}")
    if not USER_RE.match(sc.user):
        raise ConfigError(f"bad user {sc.user!r}")
    if not (0 < sc.port < 65536):
        raise ConfigError(f"bad port {sc.port}")
    for r in sc.web_roots:
        if not WEBROOT_RE.match(r) or ".." in r.split("/"):
            raise ConfigError(f"bad web root {r!r}")
    for svc in sc.services:
        if not SERVICE_RE.match(svc):
            raise ConfigError(f"bad service {svc!r}")
    for name in sc.process_allowlist:
        if not isinstance(name, str) or not (0 < len(name) <= 64) or any(c in name for c in "\n\r\0"):
            raise ConfigError(f"bad process name {name!r}")
    if not (1 <= len(sc.web_roots) <= 10) or len(sc.services) > 20:
        raise ConfigError("too many web roots or services")
    for svc, url in sc.health_urls.items():
        if svc not in sc.services:
            raise ConfigError(f"health url for non-allowlisted service {svc!r}")
        if not re.match(r"^https?://[^\s]{1,500}$", url):
            raise ConfigError(f"bad health url {url!r}")
