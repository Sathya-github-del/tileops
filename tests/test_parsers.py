from companion import parsers as P

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# comment
tileops:x:1000:1000::/home/tileops:/bin/bash
broken line
"""

# busybox/Alpine passwd is the same format but with ash and fewer fields filled
PASSWD_BUSYBOX = """root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
"""


def test_passwd():
    u = P.parse_passwd(PASSWD)
    assert set(u) == {"root", "daemon", "tileops"}
    assert u["tileops"] == {"uid": 1000, "gid": 1000, "home": "/home/tileops", "shell": "/bin/bash"}
    b = P.parse_passwd(PASSWD_BUSYBOX)
    assert b["root"]["shell"] == "/bin/ash" and b["nobody"]["uid"] == 65534


AUTH = """==> tileops /home/tileops/.ssh/authorized_keys <==
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDflavvmjl82utnUtJ/bKPIJpYOn14eEFXrcMWsA/mYW tileops-target
# a comment

==> root /root/.ssh/authorized_keys <==
command="/bin/true",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 backup@host
"""


def test_authorized_keys():
    k = P.parse_authorized_keys(AUTH)
    assert len(k) == 2
    users = sorted(v["user"] for v in k.values())
    assert users == ["root", "tileops"]
    rsa = next(v for v in k.values() if v["user"] == "root")
    assert rsa["type"] == "ssh-rsa" and rsa["has_options"] and rsa["comment"] == "backup@host"
    assert all(len(v["line_sha256"]) == 64 for v in k.values())
    # same line -> same key (stable)
    assert P.parse_authorized_keys(AUTH) == k


def test_authorized_keys_degraded_and_empty():
    assert P.parse_authorized_keys("") == {}
    assert P.parse_authorized_keys("garbage without sections\n") == {}


CRON = """==> /var/spool/cron/crontabs/root <==
# DO NOT EDIT
*/5 * * * *   /usr/local/bin/backup.sh

==> /etc/crontab <==
SHELL=/bin/sh
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
==> /etc/cron.d/empty <==
# nothing
"""

# Alpine busybox crond keeps root's crontab under /etc/crontabs
CRON_BUSYBOX = """==> /etc/crontabs/root <==
# min	hour	day	month	weekday	command
*/15	*	*	*	*	run-parts /etc/periodic/15min
0	*	*	*	*	run-parts /etc/periodic/hourly
"""


def test_cron():
    c = P.parse_cron(CRON)
    assert set(c) == {"/var/spool/cron/crontabs/root", "/etc/crontab", "/etc/cron.d/empty"}
    assert c["/var/spool/cron/crontabs/root"]["lines"] == ["*/5 * * * * /usr/local/bin/backup.sh"]
    assert c["/etc/cron.d/empty"]["n"] == 0
    # whitespace/comment changes don't change the hash
    c2 = P.parse_cron(CRON.replace("*/5 * * * *   ", "*/5 * * * * ").replace("# DO NOT EDIT", "# x"))
    assert c2["/var/spool/cron/crontabs/root"]["sha256"] == c["/var/spool/cron/crontabs/root"]["sha256"]
    b = P.parse_cron(CRON_BUSYBOX)
    assert b["/etc/crontabs/root"]["n"] == 2


SS = """LISTEN 0      511    0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=56,fd=5),("nginx",pid=57,fd=5))
LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=119,fd=3))
LISTEN 0      511       [::]:80    [::]:* users:(("nginx",pid=56,fd=6))
LISTEN 0      4096   127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=9,fd=14))
"""

SS_NOPROC_HEADER = """State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128          *:8080            *:*
"""

NETSTAT_BUSYBOX = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:8022            0.0.0.0:*               LISTEN
tcp        0      0 :::8022                 :::*                    LISTEN
tcp        0      0 192.168.1.9:8800        0.0.0.0:*               LISTEN      4242/python3
"""

PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0900A8C0:0016 0A00A8C0:C350 01 00000000:00000000 02:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
"""


def test_ports_ss():
    p = P.parse_ports(SS)
    assert set(p) == {"tcp/22", "tcp/53", "tcp/80"}
    assert p["tcp/80"]["procs"] == ["nginx"] and p["tcp/80"]["addrs"] == ["0.0.0.0", "::"]
    assert p["tcp/53"]["addrs"] == ["127.0.0.53"]


def test_ports_variants():
    assert P.parse_ports(SS_NOPROC_HEADER)["tcp/8080"]["procs"] == []
    n = P.parse_ports(NETSTAT_BUSYBOX)
    assert set(n) == {"tcp/8022", "tcp/8800"}
    assert n["tcp/8800"]["procs"] == ["python3"]
    assert n["tcp/8022"]["addrs"] == ["0.0.0.0", "::"]
    t = P.parse_ports(PROC_NET_TCP)
    assert set(t) == {"tcp/22", "tcp/8080"}  # ESTABLISHED row (01) ignored
    assert t["tcp/8080"]["addrs"] == ["127.0.0.1"]


PS = """    PID USER     %CPU COMMAND
   4242 root     99.5 kdevtmpfsi -c while :; do :; done
      1 root      1.1 /sbin/init
    119 root      0.0 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
      2 root      0.0 [kthreadd]
"""

TOP_BUSYBOX = """Mem: 3804240K used, 92536K free, 2160K shrd, 106688K buff, 1520596K cached
CPU:  12% usr   3% sys   0% nic  84% idle   0% io   0% irq   0% sirq
Load average: 0.52 0.58 0.59 2/412 4243
  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND
 4242     1 tileops  R     1640   0%   2  97% kdevtmpfsi
 4100     1 tileops  S    48212   1%   0   0% /home/tileops/venv/bin/python3 -m companion serve
    1     0 root     S     1604   0%   1   0% /sbin/init
"""

TOP_BUSYBOX_NOCPUCOL = """  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
   10     1 root     R     1500   0%  55% /usr/bin/miner --pool x
"""


def test_processes_gnu():
    ps = P.parse_processes(PS)
    assert ps[0]["name"] == "kdevtmpfsi" and ps[0]["cpu"] == 99.5 and ps[0]["pid"] == 4242
    names = {p["name"] for p in ps}
    assert "sshd" in names and "[kthreadd]" in names and "init" in names


def test_processes_busybox():
    ps = P.parse_processes(TOP_BUSYBOX)
    assert ps[0] == {"pid": 4242, "user": "tileops", "cpu": 97.0, "args": "kdevtmpfsi", "name": "kdevtmpfsi"}
    assert ps[1]["name"] == "python3"
    ps2 = P.parse_processes(TOP_BUSYBOX_NOCPUCOL)
    assert ps2[0]["cpu"] == 55.0 and ps2[0]["name"] == "miner"
    assert P.parse_processes("no header here") == []


def test_proc_name():
    assert P.proc_name("/usr/bin/python3 -m http.server 4444") == "python3"
    assert P.proc_name("kdevtmpfsi") == "kdevtmpfsi"
    assert P.proc_name("[kworker/0:1-events]") == "[kworker/0:1-events]"
    assert P.proc_name("sshd: tileops [priv]") == "sshd"
    assert P.proc_name("") == "?"


WEB = """1731000000|612|/var/www/html/index.nginx-debian.html
1731000100|10|/var/www/html/shell.php
bad line
1731000000.0|5|/var/www/html/odd|name.txt
"""


def test_webroot():
    w = P.parse_webroot(WEB)
    assert w["/var/www/html/shell.php"] == {"mtime": 1731000100, "size": 10}
    assert w["/var/www/html/odd|name.txt"]["size"] == 5
    assert len(w) == 3


UNITS = """aaaa111  /etc/systemd/system/evil.service
bbbb222  /usr/lib/systemd/system/nginx.service
bbbb222  /lib/systemd/system/nginx.service
link:/dev/null  /etc/systemd/system/getty.target
link:/lib/systemd/system/ssh.service  /etc/systemd/system/sshd.service
"""


def test_units():
    u = P.parse_units(UNITS)
    assert u["nginx.service"]["hashes"] == ["bbbb222"]  # /lib vs /usr/lib collapse
    assert len(u["nginx.service"]["paths"]) == 2
    assert u["sshd.service"]["hashes"] == ["link:/lib/systemd/system/ssh.service"]
    assert "evil.service" in u
    assert P.parse_units("") == {}


def test_split_sections():
    s = P.split_sections("junk\n==> a <==\n1\n2\n==> b c <==\n")
    assert s == [("a", "1\n2"), ("b c", "")]
