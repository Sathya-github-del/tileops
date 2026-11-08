"""Fixed registry of read-only probe commands.

No command string ever comes from the API, the AI, or free-form config: the only
config values interpolated are web roots, which are regex-validated in config.py
and shell-quoted here."""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Callable

from . import parsers
from .config import ServerConfig

UNIT_GLOBS = "-name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path'"
UNIT_DIRS = ("/etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system "
             "/usr/lib/systemd/system /lib/systemd/system")


@dataclass(frozen=True)
class Probe:
    name: str
    command: str
    parse: Callable[[str], object]
    # string that, if present in output, marks the privileged path as unavailable
    degraded_marker: str = "#TILEOPS-DEGRADED"


def _users() -> Probe:
    return Probe("users", "cat /etc/passwd", parsers.parse_passwd)


def _ssh_keys() -> Probe:
    cmd = (
        "if sudo -n /usr/local/sbin/tileops-read authorized-keys 2>/dev/null; then :; else "
        "echo '#TILEOPS-DEGRADED'; "
        'for f in "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys2"; do '
        '[ -f "$f" ] && { echo "==> $(id -un) $f <=="; cat "$f"; echo; }; done; '
        "for f in /root/.ssh/authorized_keys; do [ -r \"$f\" ] && { echo \"==> root $f <==\"; cat \"$f\"; echo; }; done; "
        "fi"
    )
    return Probe("ssh_keys", cmd, parsers.parse_authorized_keys)


def _cron() -> Probe:
    cmd = (
        "if sudo -n /usr/local/sbin/tileops-read crontabs 2>/dev/null; then :; else "
        "echo '#TILEOPS-DEGRADED'; "
        'c=$(crontab -l 2>/dev/null) && { echo "==> /var/spool/cron/crontabs/$(id -un) <=="; printf "%s\\n" "$c"; }; '
        "fi; "
        "for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/crontabs/* "
        "/etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do "
        '[ -f "$f" ] && [ -r "$f" ] && { echo "==> $f <=="; head -c 65536 "$f"; echo; }; done; true'
    )
    return Probe("cron", cmd, parsers.parse_cron)


def _ports() -> Probe:
    cmd = (
        "sudo -n ss -tlnpH 2>/dev/null || { echo '#TILEOPS-DEGRADED'; ss -tlnH 2>/dev/null "
        "|| netstat -tln 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; }"
    )
    return Probe("ports", cmd, parsers.parse_ports)


def _processes() -> Probe:
    cmd = (
        "if ps -eo pid,user,pcpu,args --sort=-pcpu >/dev/null 2>&1; then "
        "ps -eo pid,user,pcpu,args --sort=-pcpu | head -n 41; "
        "else top -b -n 1 | head -n 60; fi"
    )
    return Probe("processes", cmd, parsers.parse_processes)


def _webroot(roots: list[str]) -> Probe:
    quoted = " ".join(shlex.quote(r) for r in roots)
    cmd = (
        f"for r in {quoted}; do [ -d \"$r\" ] || continue; "
        "find \"$r\" -xdev -type f -exec stat -c '%Y|%s|%n' {} + 2>/dev/null; done | head -n 5000"
    )
    return Probe("webroot", cmd, parsers.parse_webroot)


def _units() -> Probe:
    cmd = (
        f"for d in {UNIT_DIRS}; do [ -d \"$d\" ] || continue; "
        f"find \"$d\" -maxdepth 1 -type f \\( {UNIT_GLOBS} \\) -exec sha256sum {{}} + 2>/dev/null; "
        f"find \"$d\" -maxdepth 1 -type l \\( {UNIT_GLOBS} \\) 2>/dev/null | while read -r f; do "
        'echo "link:$(readlink "$f")  $f"; done; done; true'
    )
    return Probe("units", cmd, parsers.parse_units)


def probes_for(server: ServerConfig) -> list[Probe]:
    return [_users(), _ssh_keys(), _cron(), _ports(), _processes(),
            _webroot(server.web_roots), _units()]


PROBE_NAMES = ["users", "ssh_keys", "cron", "ports", "processes", "webroot", "units"]


# ---- runbook commands (typed; service must be allowlisted for the server) ----
def service_status_cmd(server: ServerConfig, service: str) -> str:
    _check_service(server, service)
    return f"sudo -n systemctl status --no-pager {shlex.quote(service)}"


def service_restart_cmd(server: ServerConfig, service: str) -> str:
    _check_service(server, service)
    return f"sudo -n systemctl restart {shlex.quote(service)}"


def _check_service(server: ServerConfig, service: str) -> None:
    from .config import SERVICE_RE

    if service not in server.services or not SERVICE_RE.match(service):
        raise PermissionError(f"service {service!r} is not allowlisted for {server.name}")
