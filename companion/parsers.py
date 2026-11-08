"""Parsers for probe output. Pure functions, tolerant of GNU coreutils/procps/iproute2
and busybox variants. Each returns a dict mapping a stable key -> JSON-able value."""
from __future__ import annotations

import hashlib
import re


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def split_sections(text: str) -> list[tuple[str, str]]:
    """Split `==> header <==` delimited output into (header, body) pairs."""
    out: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        m = re.match(r"^==> (.*) <==$", line)
        if m:
            out.append((m.group(1), []))
        elif out:
            out[-1][1].append(line)
    return [(h, "\n".join(b)) for h, b in out]


# ---------------------------------------------------------------- users
def parse_passwd(text: str) -> dict[str, dict]:
    users: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _pw, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_i, gid_i = int(uid), int(gid)
        except ValueError:
            continue
        users[name] = {"uid": uid_i, "gid": gid_i, "home": home, "shell": shell}
    return users


# ---------------------------------------------------------------- ssh keys
KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-",
)


def _key_blob(line: str) -> tuple[str, str, str] | None:
    """Return (type, blob, comment) for an authorized_keys line (options allowed)."""
    # tokenise respecting double quotes in options
    tokens = re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', line)
    for i, tok in enumerate(tokens):
        if tok.startswith(KEY_TYPES) and i + 1 < len(tokens):
            return tok, tokens[i + 1], " ".join(tokens[i + 2:])
    return None


def parse_authorized_keys(text: str) -> dict[str, dict]:
    """Input: sections `==> <user> <path> <==`. Key: `<user>:<sha256 of key line>`."""
    keys: dict[str, dict] = {}
    for header, body in split_sections(text):
        user, _, path = header.partition(" ")
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kb = _key_blob(line)
            digest = sha256(line)
            keys[f"{user}:{digest[:32]}"] = {
                "user": user,
                "path": path,
                "line_sha256": digest,
                "type": kb[0] if kb else "unknown",
                "comment": (kb[2] if kb else "")[:120],
                "has_options": bool(kb) and not line.startswith(kb[0]),
            }
    return keys


# ---------------------------------------------------------------- cron
def _normalise_cron(body: str) -> list[str]:
    lines = []
    for raw in body.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(re.sub(r"\s+", " ", s))
    return lines


def parse_cron(text: str) -> dict[str, dict]:
    """Input: sections `==> <path> <==` (user crontabs + /etc/cron*). Key: path."""
    out: dict[str, dict] = {}
    for header, body in split_sections(text):
        path = header.strip()
        lines = _normalise_cron(body)
        out[path] = {"sha256": sha256("\n".join(lines)), "lines": lines[:50], "n": len(lines)}
    return out


# ---------------------------------------------------------------- ports
_USERS_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def _split_hostport(s: str) -> tuple[str, int] | None:
    if s.startswith("[") and "]:" in s:
        host, _, port = s[1:].rpartition("]:")
    else:
        host, _, port = s.rpartition(":")
    host = host.split("%")[0] or "*"
    try:
        return host, int(port)
    except ValueError:
        return None


def _hex_addr(h: str) -> str:
    if len(h) == 8:
        b = bytes.fromhex(h)[::-1]
        return ".".join(str(x) for x in b)
    if len(h) == 32:
        if h == "0" * 32:
            return "::"
        return "v6:" + h.lower()
    return h


def parse_ports(text: str) -> dict[str, dict]:
    """Accepts `ss -tlnpH`, `ss -tln` (with header), busybox/net-tools `netstat -tln[p]`,
    or raw /proc/net/tcp[6]. Key: `tcp/<port>`; value lists addresses + processes."""
    found: dict[int, dict] = {}

    def add(port: int, addr: str, proc: str | None):
        e = found.setdefault(port, {"addrs": set(), "procs": set()})
        e["addrs"].add(addr)
        if proc:
            e["procs"].add(proc)

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        cols = s.split()
        head = cols[0]
        if head in ("State", "Netid", "Proto", "Active", "sl"):
            continue
        if re.match(r"^\d+:$", head) and len(cols) >= 4:  # /proc/net/tcp
            if cols[3] != "0A":  # LISTEN
                continue
            ip_hex, _, port_hex = cols[1].partition(":")
            add(int(port_hex, 16), _hex_addr(ip_hex), None)
            continue
        if head in ("tcp", "tcp6", "udp", "udp6"):  # netstat
            if head.startswith("udp") or "LISTEN" not in cols:
                continue
            hp = _split_hostport(cols[3]) if len(cols) > 3 else None
            if not hp:
                continue
            proc = None
            if len(cols) > 6 and "/" in cols[-1]:
                proc = cols[-1].split("/", 1)[1]
            add(hp[1], hp[0], proc)
            continue
        if head == "LISTEN" or (head == "tcp" and len(cols) > 4):
            if len(cols) < 4:
                continue
            hp = _split_hostport(cols[3])
            if not hp:
                continue
            procs = [m.group(1) for m in _USERS_RE.finditer(s)]
            add(hp[1], hp[0], procs[0] if procs else None)
    return {
        f"tcp/{p}": {"port": p, "addrs": sorted(v["addrs"]), "procs": sorted(v["procs"])}
        for p, v in sorted(found.items())
    }


# ---------------------------------------------------------------- processes
def proc_name(args: str) -> str:
    """Name a process by argv[0] basename (what `exec -a` sets), not comm."""
    a = args.strip()
    if not a:
        return "?"
    if a.startswith("[") and "]" in a:  # kernel thread
        return a[: a.index("]") + 1]
    first = a.split()[0]
    name = first.rsplit("/", 1)[-1]
    return name.rstrip(":") or first


def parse_processes(text: str) -> list[dict]:
    """Accepts `ps -eo pid,user,pcpu,args` (GNU) or busybox `top -b -n 1`."""
    lines = text.splitlines()
    procs: list[dict] = []
    hdr_i = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*PID\b", line):
            hdr_i = i
            break
    if hdr_i is None:
        return procs
    header = lines[hdr_i].split()
    cpu_col = None
    for cand in ("%CPU", "CPU%", "%cpu"):
        if cand in header:
            cpu_col = header.index(cand)
            break
    if cpu_col is None:
        return procs
    # columns before the trailing COMMAND/ARGS column
    ncols = len(header) - 1
    user_col = header.index("USER") if "USER" in header else None
    for line in lines[hdr_i + 1:]:
        if not line.strip():
            continue
        parts = line.split(None, ncols)
        if len(parts) <= ncols:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[cpu_col].rstrip("%"))
        except ValueError:
            continue
        args = parts[ncols].strip()
        procs.append({
            "pid": pid,
            "user": parts[user_col] if user_col is not None else "",
            "cpu": cpu,
            "args": args[:300],
            "name": proc_name(args),
        })
    procs.sort(key=lambda p: -p["cpu"])
    return procs


# ---------------------------------------------------------------- web roots
def parse_webroot(text: str) -> dict[str, dict]:
    """Lines `<mtime>|<size>|<path>` (from `stat -c`). Key: path."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        if line.startswith("==> "):
            continue
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            mtime, size = int(float(parts[0])), int(parts[1])
        except ValueError:
            continue
        out[parts[2]] = {"mtime": mtime, "size": size}
    return out


# ---------------------------------------------------------------- systemd units
def parse_units(text: str) -> dict[str, dict]:
    """Lines `<sha256>  <path>` or `link:<target>  <path>`. Key: unit name. /lib vs
    /usr/lib duplicates collapse because the value is the set of content hashes."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+\*?(/\S.*)$", line.strip())
        if not m:
            continue
        digest, path = m.group(1), m.group(2)
        name = path.rsplit("/", 1)[-1]
        e = out.setdefault(name, {"hashes": set(), "paths": set()})
        e["hashes"].add(digest)
        e["paths"].add(path)
    return {
        k: {"hashes": sorted(v["hashes"]), "paths": sorted(v["paths"])}
        for k, v in sorted(out.items())
    }
