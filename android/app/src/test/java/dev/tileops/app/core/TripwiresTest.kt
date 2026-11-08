package dev.tileops.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Same cases as tests/test_tripwires.py. */
class TripwiresTest {
    @Test fun newUserAndUid0() {
        val base = Parsers.passwd("root:x:0:0::/root:/bin/sh\n")
        val f = Tripwires.diff("users", base, Parsers.passwd("root:x:0:0::/root:/bin/sh\nevil:x:1001:1001::/home/evil:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n")).associateBy { it.key }
        assertEquals("high", f["evil"]!!.severity); assertEquals("critical", f["toor"]!!.severity)
        assertTrue(Tripwires.diff("users", base, base).isEmpty())
        assertTrue(Tripwires.diff("users", Parsers.passwd("root:x:0:0::/root:/bin/sh\nold:x:5:5::/:/bin/sh\n"), base).isEmpty()) // removals
        val chg = Tripwires.diff("users", Parsers.passwd("bob:x:1000:1000::/h:/bin/sh\n"), Parsers.passwd("bob:x:0:1000::/h:/bin/sh\n")).single()
        assertEquals("changed", chg.change); assertEquals("critical", chg.severity)
    }

    @Test fun cronPortsWebUnits() {
        val c = Tripwires.diff("cron", Parsers.cron("==> /etc/crontab <==\n0 * * * * root a\n"),
            Parsers.cron("==> /etc/crontab <==\n0 * * * * root a\n* * * * * root curl x|sh\n")).single()
        assertTrue(c.detail.toString().contains("curl x|sh"))
        val base = Parsers.ports("LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=1))\n")
        val same = Parsers.ports("LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=99,fd=1))\nLISTEN 0 1 [::]:80 [::]:* users:((\"nginx\",pid=99,fd=2))\n")
        assertTrue(Tripwires.diff("ports", base, same).isEmpty())
        val p = Tripwires.diff("ports", base, same + Parsers.ports("LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:((\"python3\",pid=7,fd=3))\n")).single()
        assertEquals("tcp/4444", p.key); assertTrue("python3" in p.title)
        val hijack = Tripwires.diff("ports", base, Parsers.ports("LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:((\"nc\",pid=5,fd=1))\n")).single()
        assertEquals("medium", hijack.severity)
        val w = Tripwires.diff("webroot", Parsers.webroot("1|10|/a\n"), Parsers.webroot("2|10|/a\n3|5|/x.php\n")).associateBy { it.key }
        assertEquals("added", w["/x.php"]!!.change); assertEquals("changed", w["/a"]!!.change)
        assertEquals("x.service", Tripwires.diff("units", Parsers.units("a  /usr/lib/systemd/system/nginx.service\n"),
            Parsers.units("a  /usr/lib/systemd/system/nginx.service\nb  /etc/systemd/system/x.service\n")).single().key)
    }

    @Test fun fingerprints() {
        val a = Tripwires.diff("webroot", emptyMap(), Parsers.webroot("1|1|/p\n")).single()
        val b = Tripwires.diff("webroot", emptyMap(), Parsers.webroot("1|1|/p\n")).single()
        val c = Tripwires.diff("webroot", emptyMap(), Parsers.webroot("2|1|/p\n")).single()
        assertEquals(a.fingerprint("s"), b.fingerprint("s")); assertNotEquals(a.fingerprint("s"), c.fingerprint("s"))
    }

    private fun procs(vararg rows: Pair<String, Double>) = rows.mapIndexed { i, (n, c) -> Parsers.Proc(i, "u", c, n, n) }

    @Test fun cpuNeedsConsecutiveScans() {
        val base = Tripwires.processBaseline(procs("nginx" to 0.0, "sshd" to 0.0))
        val (f1, s1) = Tripwires.evaluateProcesses(procs("kdevtmpfsi" to 99.0, "nginx" to 90.0), base, emptyList(), emptyMap(), 50.0, 2)
        assertTrue(f1.isEmpty()); assertEquals(mapOf("kdevtmpfsi" to 1), s1)
        val (f2, s2) = Tripwires.evaluateProcesses(procs("kdevtmpfsi" to 98.0), base, emptyList(), s1, 50.0, 2)
        assertEquals("kdevtmpfsi", f2.single().key)
        val (f3, s3) = Tripwires.evaluateProcesses(procs("kdevtmpfsi" to 1.0), base, emptyList(), s2, 50.0, 2)
        assertTrue(f3.isEmpty() && s3.isEmpty())
        val (f4, _) = Tripwires.evaluateProcesses(procs("ffmpeg" to 99.0), Tripwires.processBaseline(emptyList()), listOf("ffmpeg"), mapOf("ffmpeg" to 5), 50.0, 1)
        assertTrue(f4.isEmpty())
    }
}
