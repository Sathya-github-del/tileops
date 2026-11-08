"""ntfy.sh push. The message body is only "[severity] <title> on <server>": no evidence, no tokens."""
from __future__ import annotations

import logging
import re

import httpx

log = logging.getLogger("tileops.notify")

PRIORITY = {"critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1"}


def _ascii(s: str) -> str:
    # HTTP header values must be latin-1; keep them plain ASCII and free of separators.
    return re.sub(r"[^\x20-\x7e]", "?", s).replace(",", " ").replace(";", " ")


def build(alert: dict, public_url: str) -> tuple[str, dict]:
    body = f"[{alert['severity']}] {alert['title']} on {alert['server']}"
    deep = f"tileops://alert/{alert['id']}"
    web = f"{public_url}/#/alert/{alert['id']}"
    headers = {
        "Priority": PRIORITY.get(alert["severity"], "3"),
        "Tags": "rotating_light" if alert["severity"] in ("critical", "high") else "warning",
        "Click": deep,
        "Actions": f"view, Open in app, {_ascii(deep)}; view, Web UI, {_ascii(web)}",
    }
    return body, headers


async def send(server_url: str, topic: str, alert: dict, public_url: str) -> bool:
    if not topic:
        return False
    body, headers = build(alert, public_url)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(f"{server_url}/{topic}", content=body.encode("utf-8"), headers=headers)
            if r.status_code >= 300:
                log.warning("ntfy returned %s", r.status_code)
                return False
            return True
    except httpx.HTTPError as e:
        log.warning("ntfy send failed: %s", type(e).__name__)
        return False
