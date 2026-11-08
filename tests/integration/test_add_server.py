"""End-to-end "Add server" flow against tileops-target, as a phone-only user would do it:
API add -> paste setup command as root -> compare fingerprint -> trust -> test -> scan."""
from __future__ import annotations

import re
import subprocess
import textwrap

import pytest
from fastapi.testclient import TestClient

from companion import config as config_mod
from companion.api import create_app
from companion.collector import Collector, PinStore
from companion.db import DB
from companion.engine import Engine

from .test_target import CTR, HOST, PORT, _reachable, dx

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not _reachable(), reason="tileops-target not reachable")]
USER = "tileops2"


@pytest.fixture
def client(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(f"""
        state_dir: {tmp_path}/state
        approval_pin: "1357"
        ntfy: {{enabled: false}}
        servers: []
    """))
    cfg = config_mod.load(p)
    cfg.state_dir.mkdir()
    engine = Engine(cfg, DB(cfg.state_dir / "t.db"), Collector(PinStore(cfg.state_dir / "known_hosts")),
                    notify_enabled=False)
    c = TestClient(create_app(engine, "x" * 40, start_scheduler=False))
    c.headers["Authorization"] = "Bearer " + "x" * 40
    yield c
    dx(f"userdel -r {USER} 2>/dev/null; rm -f /etc/sudoers.d/tileops-{USER} /var/www/html/tileops-add-test.txt; true",
       check=False)


def test_add_server_end_to_end(client):
    r = client.post("/api/servers", json={
        "name": "target-app", "host": HOST, "port": PORT, "user": USER,
        "services": ["nginx"], "health_urls": {"nginx": f"http://{HOST}:8088/"}})
    assert r.status_code == 201, r.text
    cmd = r.json()["setup"]["setup_command"]

    # before setup: refused until the host key is confirmed, then the key is rejected
    assert client.post("/api/servers/target-app/test").json()["stage"] == "hostkey"
    hk = client.get("/api/servers/target-app/hostkey").json()
    fp = hk["fingerprint"]
    assert hk["key_type"] == "ssh-ed25519"
    assert client.post("/api/servers/target-app/trust", json={"fingerprint": fp}).json()["ok"]
    assert client.post("/api/servers/target-app/test").json()["stage"] == "auth"

    # the user pastes the command into an SSH session as root
    out = subprocess.run(["docker", "exec", CTR, "bash", "-c", cmd], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "TILEOPS SETUP OK" in out.stdout
    printed = re.findall(r"(SHA256:\S+) .*\(ED25519\)", out.stdout)
    assert printed == [fp], (printed, fp)  # what the script prints == what the app shows

    # running it twice is harmless
    again = subprocess.run(["docker", "exec", CTR, "bash", "-c", cmd], capture_output=True, text=True, timeout=60)
    assert again.returncode == 0 and dx(f"grep -c tileops-target-app /home/{USER}/.ssh/authorized_keys") == "1"

    t = client.post("/api/servers/target-app/test").json()
    assert t["ok"] and t["sudo_ok"] and t["ss_ok"] and t["user"] == USER, t

    s = client.post("/api/servers/target-app/scan").json()
    assert s["ok"] and s["degraded"] == [], s
    dx("echo hi > /var/www/html/tileops-add-test.txt")
    s2 = client.post("/api/servers/target-app/scan").json()
    assert len(s2["new_alerts"]) == 1
    # the new user cannot do anything beyond its exact rules
    assert dx(f"su -s /bin/sh {USER} -c 'sudo -n cat /etc/shadow' 2>&1; echo rc=$?", check=False).endswith("rc=1")

    assert client.delete("/api/servers/target-app").json()["ok"]
