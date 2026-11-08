"""Generates the one-time server setup script shown in the app ("Add server").

The template (assets/setup.sh.tmpl) and helper (assets/tileops-read) are shared with the Android
app's phone-only mode, which builds the identical script on the device.

The user runs it as root on their server (pasted into any SSH app). It is a fixed template:
the only interpolated values are the regex-validated user name, service names and the
companion-generated public key."""
from __future__ import annotations

import base64
from pathlib import Path

from .config import SERVICE_RE, USER_RE, ServerConfig

HELPER = (Path(__file__).parent / "assets" / "tileops-read").read_text()

TEMPLATE = (Path(__file__).parent / "assets" / "setup.sh.tmpl").read_text()


def build(server: ServerConfig, public_key: str) -> str:
    if not USER_RE.match(server.user):
        raise ValueError("bad user")
    for s in server.services:
        if not SERVICE_RE.match(s):
            raise ValueError("bad service")
    pk = public_key.strip()
    if "'" in pk or "\n" in pk or not pk.startswith("ssh-ed25519 "):
        raise ValueError("bad public key")
    helper = HELPER if HELPER.endswith("\n") else HELPER + "\n"
    return (TEMPLATE
            .replace("__HELPER__", helper)
            .replace("__NAME__", server.name)
            .replace("__USER__", server.user)
            .replace("__KEY__", pk)
            .replace("__SERVICES_HUMAN__", ", ".join(server.services) or "(none)")
            .replace("__SERVICES__", " ".join(server.services)))


def one_liner(script: str) -> str:
    """Copy-paste command: decodes the script and runs it as root (via sudo when needed)."""
    b64 = base64.b64encode(script.encode()).decode()
    return (f"echo '{b64}' | base64 -d | "
            "if [ \"$(id -u)\" = 0 ]; then sh; else sudo sh; fi")
