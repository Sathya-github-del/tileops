package dev.tileops.app.core

import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Same samples (GNU + busybox) and expectations as tests/test_parsers.py. */
class ParsersTest {
    private fun list(o: kotlinx.serialization.json.JsonObject?, k: String) = o!![k]!!.jsonArray.map { it.jsonPrimitive.content }

    @Test fun passwd() {
        val u = Parsers.passwd("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n# c\ntileops:x:1000:1000::/home/tileops:/bin/bash\nbroken line\n")
        assertEquals(setOf("root", "daemon", "tileops"), u.keys)
        assertEquals(1000, u["tileops"]!!["uid"]!!.jsonPrimitive.int)
        val b = Parsers.passwd("root:x:0:0:root:/root:/bin/ash\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n")
        assertEquals("/bin/ash", b["root"]!!["shell"]!!.jsonPrimitive.content)
    }

    @Test fun authorizedKeys() {
        val text = "==> tileops /home/tileops/.ssh/authorized_keys <==\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDfl tileops-target\n# c\n\n" +
            "==> root /root/.ssh/authorized_keys <==\ncommand=\"/bin/true\",no-pty ssh-rsa AAAAB3NzaC1yc2E backup@host\n"
        val k = Parsers.authorizedKeys(text)
        assertEquals(2, k.size)
        val rsa = k.values.first { it["user"]!!.jsonPrimitive.content == "root" }
        assertEquals("ssh-rsa", rsa["type"]!!.jsonPrimitive.content)
        assertEquals("true", rsa["has_options"]!!.jsonPrimitive.content)
        assertEquals("backup@host", rsa["comment"]!!.jsonPrimitive.content)
        assertEquals(k, Parsers.authorizedKeys(text))
        assertTrue(Parsers.authorizedKeys("garbage\n").isEmpty())
    }

    @Test fun cron() {
        val c = Parsers.cron("==> /var/spool/cron/crontabs/root <==\n# DO NOT EDIT\n*/5 * * * *   /usr/local/bin/backup.sh\n\n==> /etc/crontab <==\nSHELL=/bin/sh\n==> /etc/cron.d/empty <==\n# nothing\n")
        assertEquals(listOf("*/5 * * * * /usr/local/bin/backup.sh"), list(c["/var/spool/cron/crontabs/root"], "lines"))
        assertEquals(0, c["/etc/cron.d/empty"]!!["n"]!!.jsonPrimitive.int)
        val b = Parsers.cron("==> /etc/crontabs/root <==\n# min\thour\n*/15\t*\t*\t*\t*\trun-parts /etc/periodic/15min\n0\t*\t*\t*\t*\trun-parts /etc/periodic/hourly\n")
        assertEquals(2, b["/etc/crontabs/root"]!!["n"]!!.jsonPrimitive.int)
    }

    @Test fun portsAllFormats() {
        val ss = Parsers.ports("LISTEN 0      511    0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=56,fd=5),(\"nginx\",pid=57,fd=5))\n" +
            "LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=119,fd=3))\n" +
            "LISTEN 0      511       [::]:80    [::]:* users:((\"nginx\",pid=56,fd=6))\n" +
            "LISTEN 0      4096   127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=9,fd=14))\n")
        assertEquals(setOf("tcp/22", "tcp/53", "tcp/80"), ss.keys)
        assertEquals(listOf("0.0.0.0", "::"), list(ss["tcp/80"], "addrs"))
        assertEquals(listOf("nginx"), list(ss["tcp/80"], "procs"))
        val ns = Parsers.ports("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
            "tcp        0      0 0.0.0.0:8022            0.0.0.0:*               LISTEN\ntcp        0      0 :::8022                 :::*                    LISTEN\n" +
            "tcp        0      0 192.168.1.9:8800        0.0.0.0:*               LISTEN      4242/python3\n")
        assertEquals(setOf("tcp/8022", "tcp/8800"), ns.keys)
        assertEquals(listOf("python3"), list(ns["tcp/8800"], "procs"))
        val proc = Parsers.ports("  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 0\n   1: 0100007F:1F90 00000000:0000 0A 0\n   2: 0900A8C0:0016 0A00A8C0:C350 01 0\n")
        assertEquals(setOf("tcp/22", "tcp/8080"), proc.keys)
        assertEquals(listOf("127.0.0.1"), list(proc["tcp/8080"], "addrs"))
    }

    @Test fun processesGnuAndBusybox() {
        val ps = Parsers.processes("    PID USER     %CPU COMMAND\n   4242 root     99.5 kdevtmpfsi -c while :; do :; done\n      1 root      1.1 /sbin/init\n      2 root      0.0 [kthreadd]\n")
        assertEquals("kdevtmpfsi", ps[0].name); assertEquals(99.5, ps[0].cpu, 0.0)
        assertTrue(ps.any { it.name == "[kthreadd]" })
        val bb = Parsers.processes("Mem: 1K used\nCPU:  12% usr\n  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND\n" +
            " 4242     1 tileops  R     1640   0%   2  97% kdevtmpfsi\n 4100     1 tileops  S    48212   1%   0   0% /home/tileops/venv/bin/python3 -m companion serve\n")
        assertEquals(Parsers.Proc(4242, "tileops", 97.0, "kdevtmpfsi", "kdevtmpfsi"), bb[0])
        assertEquals("python3", bb[1].name)
        assertEquals(55.0, Parsers.processes("  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n   10     1 root     R     1500   0%  55% /usr/bin/miner --pool x\n")[0].cpu, 0.0)
        assertTrue(Parsers.processes("no header").isEmpty())
        assertEquals("sshd", Parsers.procName("sshd: tileops [priv]"))
    }

    @Test fun webrootAndUnits() {
        val w = Parsers.webroot("1731000000|612|/var/www/html/index.html\n1731000100|10|/var/www/html/shell.php\nbad\n1731000000.0|5|/var/www/html/odd|name.txt\n")
        assertEquals(3, w.size)
        assertEquals(10, w["/var/www/html/shell.php"]!!["size"]!!.jsonPrimitive.int)
        val u = Parsers.units("aaaa111  /etc/systemd/system/evil.service\nbbbb222  /usr/lib/systemd/system/nginx.service\nbbbb222  /lib/systemd/system/nginx.service\nlink:/lib/systemd/system/ssh.service  /etc/systemd/system/sshd.service\n")
        assertEquals(listOf("bbbb222"), list(u["nginx.service"], "hashes"))
        assertEquals(2, list(u["nginx.service"], "paths").size)
        assertEquals(listOf("link:/lib/systemd/system/ssh.service"), list(u["sshd.service"], "hashes"))
    }
}
