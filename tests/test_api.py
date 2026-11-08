"""API + engine tests with a fake collector (no SSH)."""
import textwrap

import pytest
from fastapi.testclient import TestClient

from companion import config as config_mod
from companion.api import create_app
from companion.collector import CmdResult, PinStore, ProbeResult
from companion.db import DB
from companion.engine import Engine
from companion.probes import probes_for

TOKEN = "t" * 43

OUT = {
    "users": "root:x:0:0::/root:/bin/bash\ntileops:x:1000:1000::/home/tileops:/bin/bash\n",
    "ssh_keys": "==> tileops /home/tileops/.ssh/authorized_keys <==\nssh-ed25519 AAAA1 me\n",
    "cron": "==> /etc/crontab <==\n17 * * * * root run-parts /etc/cron.hourly\n",
    "ports": 'LISTEN 0 1 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n',
    "processes": "PID USER %CPU COMMAND\n1 root 0.1 /sbin/init\n",
    "webroot": "1|10|/var/www/html/index.html\n",
    "units": "aa  /usr/lib/systemd/system/nginx.service\n",
}


class FakeCollector:
    def __init__(self, pins):
        self.pins = pins
        self.out = dict(OUT)
        self.commands = []
        self.fail = None
        self.fail_times = 0
        self.calls = 0
        import asyncssh
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.sudo_ok = True

    async def collect(self, server):
        if server.confirm_hostkey and not self.pins.get(server):
            from companion.collector import HostKeyNotConfirmed
            raise HostKeyNotConfirmed("host key not confirmed yet")
        self.calls += 1
        if self.fail and (self.fail_times == 0 or self.calls <= self.fail_times):
            raise self.fail
        return [ProbeResult(p.name, p.command, True, p.parse(self.out[p.name]), raw_excerpt=self.out[p.name])
                for p in probes_for(server)]

    async def fetch_host_key(self, server):
        return self.host_key

    async def check_access(self, server):
        if server.confirm_hostkey and not self.pins.get(server):
            from companion.collector import HostKeyNotConfirmed
            raise HostKeyNotConfirmed("host key for x not confirmed yet")
        return {"user": server.user, "sudo_ok": self.sudo_ok, "ss_ok": True, "systemctl": True}

    async def run_typed(self, server, command, timeout=60):
        self.commands.append(command)
        if "status" in command:
            return CmdResult(command, 3, "● nginx.service\n     Active: inactive (dead)\n", "")
        return CmdResult(command, 0, "", "")


@pytest.fixture
def env(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(textwrap.dedent(f"""
        state_dir: {tmp_path}/state
        approval_pin: "4321"
        ntfy: {{enabled: false}}
        servers:
          - name: demo
            host: 127.0.0.1
            port: 2222
            key_path: /nonexistent
            services: [nginx]
            health_urls: {{nginx: "http://127.0.0.1:9/"}}
    """))
    cfg = config_mod.load(cfg_path)
    cfg.state_dir.mkdir()
    db = DB(cfg.state_dir / "t.db")
    col = FakeCollector(PinStore(cfg.state_dir / "known_hosts"))
    engine = Engine(cfg, db, col, notify_enabled=False)
    engine.retry_delays = (0, 0)
    app = create_app(engine, TOKEN, start_scheduler=False)
    client = TestClient(app)
    client.headers["Authorization"] = f"Bearer {TOKEN}"
    return client, engine, col, app


def test_auth_required(env):
    client, *_ = env
    anon = TestClient(client.app)
    assert anon.get("/health").status_code == 200
    assert anon.get("/").status_code == 200  # web shell has no data
    for path in ("/api/servers", "/api/alerts", "/api/status", "/api/incidents"):
        assert anon.get(path).status_code == 401
        assert anon.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert anon.post("/api/servers/demo/scan").status_code == 401


def test_baseline_then_alert_dedup_and_lifecycle(env):
    client, engine, col, _ = env
    r = client.post("/api/servers/demo/scan").json()
    assert r["ok"] and r["new_alerts"] == []
    assert client.get("/api/alerts").json() == []

    col.out["users"] += "evil:x:1001:1001::/home/evil:/bin/sh\n"
    col.out["webroot"] += "5|3|/var/www/html/x.php\n"
    r = client.post("/api/servers/demo/scan").json()
    assert len(r["new_alerts"]) == 2
    r2 = client.post("/api/servers/demo/scan").json()
    assert r2["new_alerts"] == []  # dedup
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 2
    user_alert = next(a for a in alerts if a["tripwire"] == "new_user")
    assert user_alert["count"] == 2

    d = client.get(f"/api/alerts/{user_alert['id']}").json()
    assert d["evidence"]["command"] == "cat /etc/passwd"
    assert "evil" in d["evidence"]["raw_excerpt"]
    assert d["evidence"]["collected_at"] > 0
    assert d["severity"] == "high"

    assert client.post(f"/api/alerts/{user_alert['id']}/ack").json()["status"] == "acked"
    assert client.post(f"/api/alerts/{user_alert['id']}/snooze", json={"minutes": 30}).json()["status"] == "snoozed"
    assert client.post(f"/api/alerts/{user_alert['id']}/accept").json()["status"] == "accepted"

    # accepted -> part of baseline; a new scan raises nothing for it
    assert client.post("/api/servers/demo/scan").json()["new_alerts"] == []
    # but a further change to the same user is a new alert
    col.out["users"] = col.out["users"].replace("1001:1001::/home/evil:/bin/sh", "0:0::/home/evil:/bin/sh")
    r = client.post("/api/servers/demo/scan").json()
    assert len(r["new_alerts"]) == 1
    assert client.get(f"/api/alerts/{r['new_alerts'][0]}").json()["severity"] == "critical"

    inc = client.get(f"/api/incidents/{d['incident_id']}").json()
    kinds = [e["kind"] for e in inc["events"]]
    assert kinds == ["alert_raised", "alert_acked", "alert_snoozed", "baseline_accepted"]

    st = client.get("/api/status").json()
    assert st["ok"] is False and st["open_alerts"] >= 1


def test_unreachable_server_status(env):
    client, engine, col, _ = env
    col.fail = OSError("connection refused")
    r = client.post("/api/servers/demo/scan").json()
    assert not r["ok"]
    s = client.get("/api/servers").json()[0]
    assert s["status"] == "unreachable" and "refused" in s["last_error"]
    assert client.post("/api/servers/nope/scan").status_code == 404


def test_ai_not_configured(env, monkeypatch):
    client, engine, col, _ = env
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert client.get("/api/ai").json()["message"] == "AI not configured"
    client.post("/api/servers/demo/scan")
    col.out["units"] += "bb  /etc/systemd/system/evil.service\n"
    aid = client.post("/api/servers/demo/scan").json()["new_alerts"][0]
    r = client.post(f"/api/alerts/{aid}/investigate")
    assert r.status_code == 503 and r.json()["detail"] == "AI not configured"


def test_runbook_flow(env, monkeypatch):
    client, engine, col, app = env
    rb = app.state.runbooks

    async def ok(url):
        return True, ["attempt 1: HTTP 200"]
    monkeypatch.setattr(rb, "_verify", ok)

    # not allowlisted
    r = client.post("/api/runbooks/restart-service/run", json={"server": "demo", "service": "sshd"})
    assert r.status_code == 403
    r = client.post("/api/runbooks/restart-service/run", json={"server": "demo", "service": "nginx;reboot"})
    assert r.status_code == 403

    run = client.post("/api/runbooks/restart-service/run", json={"server": "demo", "service": "nginx"}).json()
    assert run["status"] == "awaiting_approval"
    assert run["steps"][0]["status"] == "ok" and run["steps"][0]["active_state"] == "inactive"
    assert run["approval"]["target"] == "tileops@127.0.0.1:2222 (demo)"
    assert run["approval"]["action"] == "systemctl restart nginx"
    assert "impact" in run["approval"]
    assert col.commands == ["sudo -n systemctl status --no-pager nginx"]  # nothing restarted yet

    assert client.post(f"/api/runs/{run['id']}/approve", json={"pin": "0000"}).status_code == 403
    assert len(col.commands) == 1
    done = client.post(f"/api/runs/{run['id']}/approve", json={"pin": "4321"}).json()
    assert done["status"] == "verified"
    assert col.commands[-1] == "sudo -n systemctl restart nginx"
    assert client.post(f"/api/runs/{run['id']}/approve", json={"pin": "4321"}).status_code == 409

    inc = client.get(f"/api/incidents/{done['incident_id']}").json()
    kinds = [e["kind"] for e in inc["events"]]
    assert kinds[0] == "runbook_started" and "approval_requested" in kinds and kinds[-1] == "runbook_verified"


def test_runbook_failed_health_is_not_done(env, monkeypatch):
    client, engine, col, app = env

    async def bad(url):
        return False, ["attempt 1: HTTP 502"] * 4
    monkeypatch.setattr(app.state.runbooks, "_verify", bad)
    run = client.post("/api/runbooks/restart-service/run", json={"server": "demo", "service": "nginx"}).json()
    done = client.post(f"/api/runs/{run['id']}/approve", json={"pin": "4321"}).json()
    assert done["steps"][1]["status"] == "ok"  # restart exited 0 ...
    assert done["status"] == "failed"  # ... but health never passed


def test_pin_lockout(env):
    client, *_ = env
    run = client.post("/api/runbooks/restart-service/run", json={"server": "demo", "service": "nginx"}).json()
    for _ in range(5):
        assert client.post(f"/api/runs/{run['id']}/approve", json={"pin": "1"}).status_code == 403
    assert client.get(f"/api/runs/{run['id']}").json()["status"] == "locked"
    assert client.post(f"/api/runs/{run['id']}/approve", json={"pin": "4321"}).status_code == 409


def test_pairing_state(tmp_path):
    from companion.pairing import ensure_state, pair_uri
    p = tmp_path / "c.yaml"
    p.write_text(f"state_dir: {tmp_path}/st\npublic_url: http://192.168.1.9:8800\n")
    cfg = config_mod.load(p)
    tok, first = ensure_state(cfg)
    assert first and len(cfg.ntfy_topic) == 32 and cfg.ntfy_topic.isalnum()
    assert oct((tmp_path / "st" / "api_token").stat().st_mode)[-3:] == "600"
    tok2, first2 = ensure_state(config_mod.load(p))
    assert tok2 == tok and not first2
    # TLS is on by default: the public URL becomes https and the pairing link pins the certificate
    assert cfg.public_url == "https://192.168.1.9:8800"
    from companion.tls import ensure_cert
    ensure_cert(cfg.state_dir, "192.168.1.9")
    uri = pair_uri(cfg, tok)
    assert uri.startswith("tileops://pair?url=https%3A%2F%2F192.168.1.9%3A8800&token=")
    assert "&fp=" in uri and len(uri.split("&fp=")[1]) == 43


def test_transient_network_error_is_retried(env):
    client, engine, col, _ = env
    col.fail, col.fail_times = OSError(113, "No route to host"), 2  # fails twice, then works
    r = client.post("/api/servers/demo/scan").json()
    assert r["ok"] and col.calls == 3
    assert client.get("/api/servers").json()[0]["status"] == "ok"


def test_persistent_network_error_marks_unreachable_after_retries(env):
    client, engine, col, _ = env
    col.fail = OSError(113, "No route to host")
    r = client.post("/api/servers/demo/scan").json()
    assert not r["ok"] and col.calls == 3
    assert client.get("/api/servers").json()[0]["status"] == "unreachable"


def test_host_key_mismatch_is_not_retried(env):
    from companion.collector import HostKeyMismatch
    client, engine, col, _ = env
    col.fail = HostKeyMismatch("pinned key differs")
    r = client.post("/api/servers/demo/scan").json()
    assert not r["ok"] and col.calls == 1


# ---------------------------------------------------------------- add server from the app
NEW = {"name": "web2", "host": "203.0.113.7", "port": 22, "services": ["nginx"],
       "health_urls": {"nginx": "https://web2.example/"}, "web_roots": ["/var/www", "/srv/site"]}


def test_add_server_flow(env):
    client, engine, col, app = env
    r = client.post("/api/servers", json=NEW)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["server"]["source"] == "app" and body["server"]["status"] == "needs_setup"
    setup = body["setup"]
    assert setup["public_key"].startswith("ssh-ed25519 ") and setup["public_key"].endswith("tileops-web2")
    assert "TILEOPS SETUP OK" in setup["setup_script"] and "nginx" in setup["setup_script"]
    assert setup["setup_command"].startswith("echo '") and "base64 -d" in setup["setup_command"]
    # private key stays on the companion, 600
    key = engine.cfg.state_dir / "keys" / "web2"
    assert oct(key.stat().st_mode)[-3:] == "600"
    assert "PRIVATE KEY" not in str(body)

    # no silent trust on first use: scanning before confirming the host key is refused
    r = client.post("/api/servers/web2/scan").json()
    assert not r["ok"] and "not confirmed" in r["error"]
    assert client.post("/api/servers/web2/test").json()["stage"] == "hostkey"

    hk = client.get("/api/servers/web2/hostkey").json()
    fp = col.host_key.get_fingerprint("sha256")
    assert hk["fingerprint"] == fp and hk["pinned"] is None
    assert client.post("/api/servers/web2/trust", json={"fingerprint": "SHA256:wrongwrongwrong"}).status_code == 409
    assert client.post("/api/servers/web2/trust", json={"fingerprint": fp}).json()["pinned"] == fp
    assert client.get("/api/servers/web2/hostkey").json()["matches_pin"] is True

    t = client.post("/api/servers/web2/test").json()
    assert t["ok"] and t["sudo_ok"] and t["user"] == "tileops"
    col.sudo_ok = False
    assert "degraded" in client.post("/api/servers/web2/test").json()["message"]

    assert client.post("/api/servers/web2/scan").json()["ok"]
    srv = next(s for s in client.get("/api/servers").json() if s["name"] == "web2")
    assert srv["status"] == "ok" and srv["host_key"] == fp


def test_add_server_validation(env):
    client, *_ = env
    for bad in ({**NEW, "name": "a b"}, {**NEW, "host": "x;reboot"}, {**NEW, "services": ["nginx; rm -rf /"]},
                {**NEW, "web_roots": ["/var/../etc"]}, {**NEW, "health_urls": {"apache": "http://x/"}},
                {**NEW, "user": "Root!"}, {**NEW, "port": 0}):
        assert client.post("/api/servers", json=bad).status_code in (400, 422), bad
    assert client.post("/api/servers", json={**NEW, "name": "demo"}).status_code == 409  # exists (YAML)
    anon = TestClient(client.app)
    assert anon.post("/api/servers", json=NEW).status_code == 401


def test_edit_and_remove_server(env):
    client, engine, col, app = env
    client.post("/api/servers", json=NEW)
    fp = col.host_key.get_fingerprint("sha256")
    client.post("/api/servers/web2/trust", json={"fingerprint": fp})
    client.post("/api/servers/web2/scan")
    assert engine.db.has_baseline("web2", "users")

    r = client.put("/api/servers/web2", json={"services": ["nginx", "php8.3-fpm"], "health_urls": {}})
    assert r.status_code == 200 and r.json()["services"] == ["nginx", "php8.3-fpm"]
    assert engine.db.has_baseline("web2", "users")  # same machine: baseline kept
    assert "php8.3-fpm" in client.get("/api/servers/web2/setup").json()["setup_script"]

    r = client.put("/api/servers/web2", json={"host": "203.0.113.8"})  # a different machine
    assert r.json()["host_key"] is None and r.json()["status"] == "needs_setup"
    assert not engine.db.has_baseline("web2", "users")

    # YAML servers are read-only from the app
    assert client.put("/api/servers/demo", json={"port": 23}).status_code == 409
    assert client.delete("/api/servers/demo").status_code == 409

    assert client.delete("/api/servers/web2").json()["ok"]
    assert not (engine.cfg.state_dir / "keys" / "web2").exists()
    assert [s["name"] for s in client.get("/api/servers").json()] == ["demo"]
    assert client.delete("/api/servers/web2").status_code == 404


def test_app_servers_survive_restart(env, tmp_path):
    client, engine, col, app = env
    client.post("/api/servers", json=NEW)
    from companion.servers import ServerRegistry
    cfg2 = config_mod.load(engine.cfg.path)
    ServerRegistry(cfg2, engine.db, col.pins).load()
    s = cfg2.server("web2")
    assert s.source == "app" and s.confirm_hostkey and s.web_roots == ["/var/www", "/srv/site"]


def test_pins_are_per_server_not_per_host(env):
    """Two entries for the same host:port must not share or delete each other's pin."""
    client, engine, col, app = env
    demo = engine.cfg.server("demo")
    engine.collector.pins.pin(demo, col.host_key)  # config server already trusted
    r = client.post("/api/servers", json={**NEW, "name": "same-box", "host": demo.host, "port": demo.port,
                                          "user": "tileops2"})
    assert r.json()["server"]["host_key"] is None and r.json()["server"]["status"] == "needs_setup"
    assert client.get("/api/servers/same-box/hostkey").json()["pinned"] is None
    client.delete("/api/servers/same-box")
    assert engine.collector.pins.fingerprint(demo) == col.host_key.get_fingerprint("sha256")


def test_legacy_pin_file_migrates_for_config_servers_only(env):
    client, engine, col, app = env
    demo = engine.cfg.server("demo")
    legacy = engine.collector.pins.path
    pub = col.host_key.export_public_key("openssh").decode().strip()
    legacy.write_text(f"[{demo.host}]:{demo.port} {pub}\n")
    assert engine.collector.pins.fingerprint(demo) == col.host_key.get_fingerprint("sha256")
    assert (legacy.parent / "pins" / "demo.known_hosts").exists()
    client.post("/api/servers", json={**NEW, "name": "same2", "host": demo.host, "port": demo.port})
    assert engine.collector.pins.get(engine.cfg.server("same2")) is None


def test_tls_cert_and_fingerprints(tmp_path):
    import base64, hashlib, ssl
    from companion.tls import ensure_cert, fingerprint, fingerprint_human
    key, crt = ensure_cert(tmp_path, "192.168.1.7")
    assert oct(key.stat().st_mode)[-3:] == "600"
    assert ensure_cert(tmp_path, "192.168.1.7") == (key, crt)  # created once, then reused
    der = ssl.PEM_cert_to_DER_cert(crt.read_text())
    digest = hashlib.sha256(der).digest()
    assert fingerprint(crt) == base64.urlsafe_b64encode(digest).decode().rstrip("=")
    assert fingerprint_human(crt) == ":".join(f"{b:02X}" for b in digest)


def test_tls_can_be_disabled(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(f"state_dir: {tmp_path}/st\npublic_url: https://10.0.0.2:8800\ntls: false\n")
    assert config_mod.load(p).public_url == "http://10.0.0.2:8800"
