"""Tripwires: pure diff logic between a saved baseline and the current probe data."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .parsers import sha256

TRIPWIRES = {
    "users": "new_user",
    "ssh_keys": "ssh_key",
    "cron": "cron",
    "ports": "listening_port",
    "processes": "cpu_process",
    "webroot": "webroot_file",
    "units": "systemd_unit",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    tripwire: str
    probe: str
    key: str
    title: str
    severity: str
    change: str  # "added" | "changed"
    old: object = None
    new: object = None
    detail: dict = field(default_factory=dict)

    @property
    def value_hash(self) -> str:
        return sha256(json.dumps(self.new, sort_keys=True, default=str))

    def fingerprint(self, server: str) -> str:
        return sha256(f"{server}|{self.tripwire}|{self.key}|{self.value_hash}")


def _same(probe: str, old, new) -> bool:
    if probe == "ports":  # address family / bind changes are noise; the owning process is not
        return old.get("procs", []) == new.get("procs", [])
    if probe == "users":
        keep = ("uid", "gid", "shell")
        return all(old.get(k) == new.get(k) for k in keep)
    if probe == "cron":
        return old.get("sha256") == new.get("sha256")
    if probe == "webroot":
        return old.get("mtime") == new.get("mtime") and old.get("size") == new.get("size")
    if probe == "units":
        return old.get("hashes") == new.get("hashes")
    return old == new


def diff(probe: str, baseline: dict, current: dict) -> list[Finding]:
    """Additions and changes only (removals are not alerts in v0.1)."""
    tw = TRIPWIRES[probe]
    out: list[Finding] = []
    for key in sorted(current):
        new = current[key]
        old = baseline.get(key)
        if old is None:
            out.append(_added(probe, tw, key, new))
        elif not _same(probe, old, new):
            out.append(_changed(probe, tw, key, old, new))
    return out


def _added(probe: str, tw: str, key: str, new) -> Finding:
    if probe == "users":
        sev = "critical" if new.get("uid") == 0 else "high"
        return Finding(tw, probe, key, f"New user '{key}' (uid {new.get('uid')})", sev, "added", None, new)
    if probe == "ssh_keys":
        return Finding(tw, probe, key,
                       f"New SSH key for '{new.get('user')}' ({new.get('type')})",
                       "critical" if new.get("user") == "root" else "high", "added", None, new)
    if probe == "cron":
        return Finding(tw, probe, key, f"New cron source {key}", "high", "added", None, new,
                       {"lines_added": new.get("lines", [])})
    if probe == "ports":
        procs = ",".join(new.get("procs") or []) or "unknown process"
        return Finding(tw, probe, key, f"New listening port {new.get('port')}/tcp ({procs})",
                       "high", "added", None, new)
    if probe == "webroot":
        return Finding(tw, probe, key, f"New file in web root: {key}", "high", "added", None, new)
    if probe == "units":
        return Finding(tw, probe, key, f"New systemd unit {key}", "high", "added", None, new)
    return Finding(tw, probe, key, f"New {probe} item {key}", "medium", "added", None, new)


def _changed(probe: str, tw: str, key: str, old, new) -> Finding:
    if probe == "users":
        sev = "critical" if new.get("uid") == 0 and old.get("uid") != 0 else "high"
        return Finding(tw, probe, key, f"User '{key}' changed (uid/gid/shell)", sev, "changed", old, new)
    if probe == "cron":
        old_l, new_l = set(old.get("lines", [])), new.get("lines", [])
        added = [l for l in new_l if l not in old_l]
        removed = [l for l in old.get("lines", []) if l not in set(new_l)]
        return Finding(tw, probe, key, f"Cron changed: {key}", "high", "changed", old, new,
                       {"lines_added": added, "lines_removed": removed})
    if probe == "ports":
        return Finding(tw, probe, key,
                       f"Port {new.get('port')}/tcp now owned by {','.join(new.get('procs') or ['?'])}",
                       "medium", "changed", old, new)
    if probe == "webroot":
        return Finding(tw, probe, key, f"Web file modified: {key}", "medium", "changed", old, new)
    if probe == "units":
        return Finding(tw, probe, key, f"Systemd unit changed: {key}", "medium", "changed", old, new)
    return Finding(tw, probe, key, f"{probe} item changed: {key}", "medium", "changed", old, new)


# ------------------------------------------------------------------ processes
def process_baseline(procs: list[dict]) -> dict:
    return {p["name"]: {"seen": True} for p in procs}


def evaluate_processes(
    procs: list[dict], baseline: dict, allowlist: list[str], streaks: dict[str, int],
    threshold: float, consecutive: int,
) -> tuple[list[Finding], dict[str, int]]:
    """Unknown process (name not in baseline/allowlist) above `threshold` %CPU for
    `consecutive` scans in a row -> one finding. Returns (findings, new_streaks)."""
    known = set(baseline) | set(allowlist)
    hot: dict[str, dict] = {}
    for p in procs:
        if p["cpu"] >= threshold and p["name"] not in known:
            if p["name"] not in hot or p["cpu"] > hot[p["name"]]["cpu"]:
                hot[p["name"]] = p
    new_streaks = {name: streaks.get(name, 0) + 1 for name in hot}
    findings = []
    for name, p in sorted(hot.items()):
        if new_streaks[name] >= consecutive:
            findings.append(Finding(
                "cpu_process", "processes", name,
                f"Unknown process '{name}' using {p['cpu']:.0f}% CPU",
                "high", "added", None, {"name": name},
                {"pid": p["pid"], "user": p["user"], "cpu": p["cpu"], "args": p["args"],
                 "streak": new_streaks[name], "threshold": threshold},
            ))
    return findings, new_streaks
