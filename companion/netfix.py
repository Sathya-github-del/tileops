"""musl DNS quirk workaround.

On the Alpine chroot some lookups fail because of a bad AAAA answer. When an
AF_UNSPEC lookup fails we retry with AF_INET. Installed once at startup; it only
changes behaviour for lookups that would otherwise have failed.
"""
from __future__ import annotations

import socket

_orig_getaddrinfo = socket.getaddrinfo
_installed = False


def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        if family in (0, socket.AF_UNSPEC):
            return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
        raise


def install() -> None:
    global _installed
    if not _installed:
        socket.getaddrinfo = _getaddrinfo
        _installed = True
