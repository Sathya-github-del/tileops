"""Integration tests against the tileops-target container (deploy/target/setup-target.sh).

Plants fake attacks with `docker exec` (test harness only; the product itself never runs
anything but its fixed probe/runbook commands), scans twice, and asserts that each of the
seven tripwires fires exactly once. Skipped automatically if the target is not reachable."""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import textwrap
from collections import Counter
from pathlib import Path

import asyncssh
import pytest

from companion import config as config_mod
from companion.collector import Collector, HostKeyMismatch, PinStore
from companion.db import DB
from companion.engine import Engine
from companion.runbooks import Runbooks

ROOT = Path(__file__).resolve().parents[2]
HOST = os.environ.get("TILEOPS_TARGET_HOST", "192.168.1.12")
PORT = int(os.environ.get("TILEOPS_TARGET_PORT", "2222"))
KEY = ROOT / "secrets" / "target_ed25519"
CTR = "tileops-target"
EVIL_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEviLkeyForTileOpsIntegrationTestOnly000000 tileops-test-backdoor"


def _reachable() -> bool:
    try:
        socket.create_connection((HOST, PORT), timeout=2).close()
        return KEY.exists()
    except OSError:
        return False


pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not _reachable(), reason=f"tileops-target not reachable at {HOST}:{PORT}")]


def dx(cmd: str, user: str = "root", check: bool = True) -> str:
    r = subprocess.run(["docker", "exec", "-u", user, CTR, "bash", "-c", cmd],
                       capture_output=True, text=True, timeout=60)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd!r} failed: {r.stderr}")
    return r.stdout.strip()


@pytest.fixture
def stack(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(textwrap.dedent(f"""
        state_dir: {tmp_path}/state
        approval_pin: "2468"
        cpu_threshold: 50
        cpu_consecutive: 2
        ntfy: {{enabled: false}}
        servers:
          - name: tileops-target
            host: {HOST}
            port: {PORT}
            user: tileops
            key_path: {KEY}
            web_roots: [/var/www]
            services: [nginx]
            health_urls: {{nginx: "http://{HOST}:8088/"}}
    """))
    cfg = config_mod.load(cfg_path)
    cfg.state_dir.mkdir()
    db = DB(cfg.state_dir / "tileops.db")
    engine = Engine(cfg, db, Collector(PinStore(cfg.state_dir / "known_hosts")), notify_enabled=False)
    return cfg, engine


def _cleanup(pids: list[str]):
    for pid in pids:
        dx(f"kill {pid} 2>/dev/null; true", check=False)
    dx("pkill -x -u nobody python3 2>/dev/null; true", check=False)
    dx("userdel -r tileops-evil 2>/dev/null; true", check=False)
    dx(f"sed -i '/tileops-test-backdoor/d' /root/.ssh/authorized_keys 2>/dev/null; true", check=False)
    dx("crontab -l -u root 2>/dev/null | grep -v tileops-test | crontab -u root - ; "
       "[ -s /var/spool/cron/crontabs/root ] || crontab -r -u root 2>/dev/null; true", check=False)
    dx("rm -f /var/www/html/tileops-test-shell.php /etc/systemd/system/tileops-test-evil.service; true",
       check=False)


def test_tripwires_fire_exactly_once(stack):
    cfg, engine = stack
    pids: list[str] = []
    _cleanup([])
    try:
        base = asyncio.run(engine.scan("tileops-target"))
        assert base["ok"], base
        assert base["new_alerts"] == []
        assert base.get("degraded") == [], f"privileged probes degraded: {base}"
        assert engine.collector.pins.fingerprint(cfg.server("tileops-target")).startswith("SHA256:")

        # ---- plant the attacks
        dx("useradd -m -s /bin/bash tileops-evil")
        dx(f"install -d -m 700 /root/.ssh && echo '{EVIL_KEY}' >> /root/.ssh/authorized_keys")
        dx("(crontab -l -u root 2>/dev/null; echo '*/30 * * * * /bin/true # tileops-test') | crontab -u root -")
        subprocess.run(["docker", "exec", "-d", "-u", "nobody", CTR, "python3", "-m", "http.server", "4444",
                        "--bind", "0.0.0.0", "--directory", "/tmp"], check=True)
        dx("echo '<?php /* tileops test */ ?>' > /var/www/html/tileops-test-shell.php")
        dx("printf '[Unit]\\nDescription=tileops test\\n[Service]\\nExecStart=/bin/true\\n' "
           "> /etc/systemd/system/tileops-test-evil.service")
        pid = dx("setsid nohup bash -c 'exec -a kdevtmpfsi sh -c \"while :; do :; done\"' "
                 ">/dev/null 2>&1 < /dev/null & echo $!", user="nobody")
        pids.append(pid)
        import time
        time.sleep(3)

        s1 = asyncio.run(engine.scan("tileops-target"))
        assert s1["ok"], s1
        time.sleep(2)
        s2 = asyncio.run(engine.scan("tileops-target"))
        assert s2["ok"], s2

        alerts = engine.list_alerts(None)
        by_tw = Counter(a["tripwire"] for a in alerts)
        expected = {"new_user", "ssh_key", "cron", "listening_port", "webroot_file", "systemd_unit", "cpu_process"}
        assert set(by_tw) == expected, [(a["tripwire"], a["title"]) for a in alerts]
        assert all(n == 1 for n in by_tw.values()), by_tw

        # the CPU alert only appears after 2 consecutive hot scans
        cpu = next(a for a in alerts if a["tripwire"] == "cpu_process")
        assert cpu["id"] in s2["new_alerts"] and cpu["id"] not in s1["new_alerts"]
        assert len(s1["new_alerts"]) == 6

        # evidence sanity
        for a in alerts:
            full = engine.get_alert(a["id"])
            ev = full["evidence"]
            assert ev["command"] and ev["collected_at"] and full["severity"] in ("medium", "high", "critical")
        titles = {a["tripwire"]: a["title"] for a in alerts}
        assert "tileops-evil" in titles["new_user"]
        assert "4444" in titles["listening_port"]
        assert "kdevtmpfsi" in titles["cpu_process"]
        assert "tileops-test-shell.php" in titles["webroot_file"]
        assert "tileops-test-evil.service" in titles["systemd_unit"]
        assert "root" in titles["ssh_key"]
        cron_ev = engine.get_alert(next(a["id"] for a in alerts if a["tripwire"] == "cron"))["evidence"]
        assert any("tileops-test" in l for l in cron_ev["detail"]["lines_added"])

        # a third scan raises nothing new (dedup)
        s3 = asyncio.run(engine.scan("tileops-target"))
        assert s3["new_alerts"] == []
    finally:
        _cleanup(pids)


def test_host_key_mismatch_refused(stack):
    cfg, engine = stack
    srv = cfg.server("tileops-target")
    fake = asyncssh.generate_private_key("ssh-ed25519")
    engine.collector.pins.pin(srv, fake)
    with pytest.raises(HostKeyMismatch):
        asyncio.run(engine.collector.collect(srv))
    r = asyncio.run(engine.scan("tileops-target"))
    assert not r["ok"] and "does not match" in r["error"]
    [a] = engine.list_alerts(None)
    assert a["tripwire"] == "host_key" and a["severity"] == "critical"


def test_restart_service_runbook_verifies_health(stack):
    cfg, engine = stack
    rb = Runbooks(engine)
    dx("systemctl stop nginx")
    try:
        assert dx("systemctl is-active nginx", check=False) != "active"
        run = asyncio.run(rb.start("restart-service", "tileops-target", "nginx"))
        assert run["status"] == "awaiting_approval", run
        assert run["steps"][0]["active_state"] in ("inactive", "failed")
        assert run["approval"]["target"] == f"tileops@{HOST}:{PORT} (tileops-target)"
        done = asyncio.run(rb.approve(run["id"], "2468"))
        assert done["status"] == "verified", done
        assert done["steps"][2]["status"] == "ok"
        assert dx("systemctl is-active nginx") == "active"
    finally:
        dx("systemctl start nginx", check=False)


def test_runbook_cannot_touch_unlisted_service(stack):
    cfg, engine = stack
    rb = Runbooks(engine)
    from companion.runbooks import RunbookError
    with pytest.raises(RunbookError):
        asyncio.run(rb.start("restart-service", "tileops-target", "ssh"))
    # and the target's sudoers refuses it even if a command were forged
    out = asyncio.run(engine.collector.run_typed(cfg.server("tileops-target"), "sudo -n systemctl restart ssh"))
    assert out.exit_status != 0
