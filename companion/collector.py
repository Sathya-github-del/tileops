"""asyncssh collector with host-key pinning (trust on first pairing, refuse on mismatch).

Pins live in an OpenSSH-format known_hosts file inside the companion's state dir;
~/.ssh is never read or written."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from .config import ServerConfig
from .probes import Probe, probes_for

CONNECT_TIMEOUT = 15
CMD_TIMEOUT = 60
EXCERPT = 4000
ACCESS_CHECK = (
    'echo "USER=$(id -un)"; '
    "sudo -n /usr/local/sbin/tileops-read crontabs >/dev/null 2>&1 && echo SUDO=ok || echo SUDO=no; "
    "sudo -n ss -tlnpH >/dev/null 2>&1 && echo SS=ok || echo SS=no; "
    "command -v systemctl >/dev/null 2>&1 && echo SYSTEMCTL=yes || echo SYSTEMCTL=no"
)


class HostKeyMismatch(Exception):
    pass


class HostKeyNotConfirmed(Exception):
    """App-added server whose host key the user has not confirmed yet."""


@dataclass
class ProbeResult:
    name: str
    command: str
    ok: bool
    data: object = None
    raw_excerpt: str = ""
    error: str = ""
    degraded: bool = False
    ts: float = field(default_factory=time.time)


@dataclass
class CmdResult:
    command: str
    exit_status: int | None
    stdout: str
    stderr: str


class PinStore:
    """Pinned host keys, one OpenSSH known_hosts file per *server name* (state/pins/<name>.known_hosts).

    Keyed by name, not host:port, so two server entries that point at the same machine never share
    (or delete) each other's pin. Pins from the older single state/known_hosts file are migrated on
    first use for config-file servers only; app-added servers always need explicit confirmation."""

    def __init__(self, path: Path):
        self.path = Path(path)  # legacy single file (read-only, for migration)
        self.dir = self.path.parent / "pins"

    def _host_id(self, server: ServerConfig) -> str:
        return server.host if server.port == 22 else f"[{server.host}]:{server.port}"

    def _file(self, server: ServerConfig) -> Path:
        return self.dir / f"{server.name}.known_hosts"

    def _legacy(self, server: ServerConfig) -> str | None:
        if not self.path.exists():
            return None
        hid = self._host_id(server)
        for line in self.path.read_text().splitlines():
            if line.strip() and line.split(" ", 1)[0] == hid:
                return line.strip()
        return None

    def _write(self, server: ServerConfig, line: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        f = self._file(server)
        f.write_text(line + "\n")
        f.chmod(0o600)

    def get(self, server: ServerConfig) -> str | None:
        f = self._file(server)
        if f.exists():
            line = f.read_text().strip()
            # a pin is only valid for the host:port it was made for
            return line if line and line.split(" ", 1)[0] == self._host_id(server) else None
        if server.source == "config":
            line = self._legacy(server)
            if line:
                self._write(server, line)
                return line
        return None

    def pin(self, server: ServerConfig, key: asyncssh.SSHKey) -> str:
        line = f"{self._host_id(server)} {key.export_public_key('openssh').decode().strip()}"
        self._write(server, line)
        return line

    def unpin(self, server: ServerConfig) -> None:
        self._file(server).unlink(missing_ok=True)

    def fingerprint(self, server: ServerConfig) -> str | None:
        line = self.get(server)
        if not line:
            return None
        key = asyncssh.import_public_key(line.split(" ", 1)[1])
        return key.get_fingerprint("sha256")


class Collector:
    def __init__(self, pins: PinStore):
        self.pins = pins

    async def _connect(self, server: ServerConfig) -> asyncssh.SSHClientConnection:
        client_key = asyncssh.read_private_key(server.key_path)
        pinned = self.pins.get(server)
        common = dict(
            host=server.host, port=server.port, username=server.user,
            client_keys=[client_key], agent_path=None, config=[],
            connect_timeout=CONNECT_TIMEOUT, keepalive_interval=30,
        )
        if pinned:
            known = asyncssh.import_known_hosts(pinned + "\n")
            try:
                return await asyncssh.connect(known_hosts=known, **common)
            except asyncssh.HostKeyNotVerifiable as e:
                raise HostKeyMismatch(
                    f"host key for {server.name} ({server.host}:{server.port}) does not match "
                    f"the pinned key {self.pins.fingerprint(server)}; refusing to connect"
                ) from e
        if server.confirm_hostkey:
            raise HostKeyNotConfirmed(
                f"host key for {server.name} not confirmed yet: fetch and trust it in the app")
        # config-file servers: trust on first use, then pin
        conn = await asyncssh.connect(known_hosts=None, **common)
        key = conn.get_server_host_key()
        if key is None:
            conn.close()
            raise HostKeyMismatch("server presented no host key")
        self.pins.pin(server, key)
        return conn

    async def _run(self, conn, command: str, timeout: int = CMD_TIMEOUT) -> CmdResult:
        r = await asyncio.wait_for(conn.run(command, check=False), timeout)
        return CmdResult(command, r.exit_status, str(r.stdout or ""), str(r.stderr or ""))

    async def collect(self, server: ServerConfig) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        conn = await self._connect(server)
        try:
            for probe in probes_for(server):
                results.append(await self._probe(conn, probe))
        finally:
            conn.close()
        return results

    async def _probe(self, conn, probe: Probe) -> ProbeResult:
        try:
            r = await self._run(conn, probe.command)
            degraded = probe.degraded_marker in r.stdout
            out = r.stdout.replace(probe.degraded_marker + "\n", "")
            return ProbeResult(
                probe.name, probe.command, True, probe.parse(out),
                raw_excerpt=out[:EXCERPT], degraded=degraded,
            )
        except Exception as e:  # noqa: BLE001 - recorded, never raised past a probe
            return ProbeResult(probe.name, probe.command, False, error=f"{type(e).__name__}: {e}")

    async def fetch_host_key(self, server: ServerConfig) -> asyncssh.SSHKey:
        """Read the server's current host key WITHOUT trusting it (no auth, nothing pinned)."""
        # Prefer ED25519 so the fingerprint matches the line users see most often
        # (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`); fall back to whatever exists.
        key = None
        for algs in (["ssh-ed25519"], ()):
            try:
                key = await asyncio.wait_for(asyncssh.get_server_host_key(
                    server.host, server.port, config=[], server_host_key_algs=algs), CONNECT_TIMEOUT + 5)
                break
            except asyncssh.KeyExchangeFailed:
                continue
        if key is None:
            raise HostKeyMismatch("server presented no host key")
        return key

    async def check_access(self, server: ServerConfig) -> dict:
        """Log in with the companion key (pinned host key required) and check the sudo helper."""
        conn = await self._connect(server)
        try:
            r = await self._run(conn, ACCESS_CHECK, 30)
        finally:
            conn.close()
        out = r.stdout
        return {
            "user": out.split("USER=", 1)[1].split()[0] if "USER=" in out else server.user,
            "sudo_ok": "SUDO=ok" in out,
            "ss_ok": "SS=ok" in out,
            "systemctl": "SYSTEMCTL=yes" in out,
        }

    async def run_typed(self, server: ServerConfig, command: str, timeout: int = 60) -> CmdResult:
        """Run one command produced by a typed runbook step (see probes.service_*_cmd)."""
        conn = await self._connect(server)
        try:
            return await self._run(conn, command, timeout)
        finally:
            conn.close()
