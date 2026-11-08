package dev.tileops.app.core

import dev.tileops.app.data.AesGcmTokenCipher
import dev.tileops.app.data.ApiException
import dev.tileops.app.data.ServerInput
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import javax.crypto.KeyGenerator

/**
 * Phone-only mode end to end against the tileops-target container (deploy/target/setup-target.sh),
 * using the real SSH client, encrypted store and setup script: the same scenario as the companion's
 * tests/integration. Skipped when the target or docker isn't available.
 */
class LocalEngineTargetTest {
    @get:Rule val tmp = TemporaryFolder()

    private val host = System.getenv("TILEOPS_TARGET_HOST") ?: "192.168.1.12"
    private val port = 2222
    private val user = "tileops5"
    private val ctr = "tileops-target"
    private lateinit var engine: LocalEngine
    private var burnerPid: String? = null

    private fun dx(cmd: String, asUser: String = "root", check: Boolean = true): String {
        val p = ProcessBuilder("docker", "exec", "-u", asUser, ctr, "bash", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        val rc = p.waitFor()
        if (check && rc != 0) throw AssertionError("'$cmd' failed: $out")
        return out
    }

    private fun reachable() = runCatching { Socket().use { it.connect(InetSocketAddress(host, port), 2000) }; true }.getOrDefault(false) &&
        runCatching { ProcessBuilder("docker", "ps").start().waitFor() == 0 }.getOrDefault(false)

    @Before fun setUp() {
        assumeTrue("tileops-target not reachable", reachable())
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val assets = File("../../companion/assets")
        engine = LocalEngine(
            LocalStore(tmp.newFolder("local"), AesGcmTokenCipher { key }),
            SetupScript(File(assets, "setup.sh.tmpl").readText(), File(assets, "tileops-read").readText()),
        ).apply { retryDelaysMs = emptyList(); healthDelayMs = 700 }
        cleanup()
    }

    private fun cleanup() {
        burnerPid?.let { dx("kill $it 2>/dev/null; true", check = false) }
        dx("pkill -x -u nobody python3 2>/dev/null; userdel -r tileops-evil2 2>/dev/null; " +
            "sed -i '/tileops-phone-test/d' /root/.ssh/authorized_keys 2>/dev/null; " +
            "crontab -l -u root 2>/dev/null | grep -v tileops-phone-test | crontab -u root - ; " +
            "[ -s /var/spool/cron/crontabs/root ] || crontab -r -u root 2>/dev/null; " +
            "rm -f /var/www/html/tileops-phone-test.php /etc/systemd/system/tileops-phone-test.service; " +
            "systemctl start nginx; true", check = false)
    }

    @After fun tearDown() {
        if (!::engine.isInitialized) return
        cleanup()
        dx("userdel -r $user 2>/dev/null; rm -f /etc/sudoers.d/tileops-$user; true", check = false)
    }

    @Test fun phoneOnlyModeEndToEnd() = runBlocking {
        // ---- add server + guided setup, exactly like the app's screens do
        val added = engine.addServer(ServerInput("phone-lab", host, port, user, listOf("/var/www"), listOf("nginx"),
            mapOf("nginx" to "http://$host:8088/")))
        assertEquals("needs_setup", added.server.status)
        assertFalse(engine.scan("phone-lab").ok) // refused: host key not confirmed
        assertEquals("hostkey", engine.testServer("phone-lab").stage)

        val hk = engine.hostKey("phone-lab")
        assertEquals("ssh-ed25519", hk.keyType)
        engine.trustHostKey("phone-lab", hk.fingerprint)
        assertEquals("auth", engine.testServer("phone-lab").stage) // setup not run yet

        val out = dx(added.setup.setupCommand)
        assertTrue(out, "TILEOPS SETUP OK" in out)
        assertTrue("fingerprint printed by the server must match the app", "${hk.fingerprint} " in out && "(ED25519)" in out)
        val t = engine.testServer("phone-lab")
        assertTrue(t.message, t.ok && t.sudoOk == true)

        // ---- baseline
        val base = engine.scan("phone-lab")
        assertTrue(base.error ?: "", base.ok)
        assertTrue(base.newAlerts.isEmpty())
        assertTrue(engine.servers().single().degradedProbes.isEmpty())

        // ---- the same seven fake attacks as the companion's integration test
        dx("useradd -m -s /bin/bash tileops-evil2")
        dx("install -d -m 700 /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPhoneTestKeyForTileOpsOnly000000000000000 tileops-phone-test' >> /root/.ssh/authorized_keys")
        dx("(crontab -l -u root 2>/dev/null; echo '*/30 * * * * /bin/true # tileops-phone-test') | crontab -u root -")
        ProcessBuilder("docker", "exec", "-d", "-u", "nobody", ctr, "python3", "-m", "http.server", "4444", "--bind", "0.0.0.0", "--directory", "/tmp").start().waitFor()
        dx("echo '<?php /* tileops phone test */ ?>' > /var/www/html/tileops-phone-test.php")
        dx("printf '[Unit]\\nDescription=t\\n[Service]\\nExecStart=/bin/true\\n' > /etc/systemd/system/tileops-phone-test.service")
        burnerPid = dx("setsid nohup bash -c 'exec -a kdevtmpfsi sh -c \"while :; do :; done\"' >/dev/null 2>&1 < /dev/null & echo \$!", asUser = "nobody")
        Thread.sleep(3000)

        val s1 = engine.scan("phone-lab"); assertTrue(s1.error ?: "", s1.ok)
        Thread.sleep(2000)
        val s2 = engine.scan("phone-lab"); assertTrue(s2.ok)
        val alerts = engine.alerts("all")
        val byTw = alerts.groupingBy { it.tripwire }.eachCount()
        assertEquals(alerts.joinToString { it.title },
            setOf("new_user", "ssh_key", "cron", "listening_port", "webroot_file", "systemd_unit", "cpu_process"), byTw.keys)
        assertTrue(byTw.toString(), byTw.values.all { it == 1 })
        assertEquals(6, s1.newAlerts.size)
        assertTrue(alerts.first { it.tripwire == "cpu_process" }.id in s2.newAlerts)
        assertTrue(alerts.first { it.tripwire == "cpu_process" }.title.contains("kdevtmpfsi"))
        assertTrue(engine.scan("phone-lab").newAlerts.isEmpty()) // dedup

        val web = engine.alert(alerts.first { it.tripwire == "webroot_file" }.id)
        assertTrue(web.evidence.command!!.startsWith("for r in /var/www"))
        assertTrue(web.evidence.rawExcerpt!!.contains("tileops-phone-test.php"))
        assertEquals("nginx", web.runbookOptions.single().service)
        assertEquals("open", engine.status().servers.single().let { if (it.status == "alert") "open" else it.status })

        // mark as expected -> no longer alerts; timeline records it
        engine.acceptBaseline(web.id)
        assertTrue(engine.scan("phone-lab").newAlerts.isEmpty())
        assertEquals(listOf("alert_raised", "baseline_accepted"), engine.incident(web.incidentId!!).events.map { it.kind })

        // ---- restart-service runbook with PIN; done = health check
        dx("systemctl stop nginx")
        val run = engine.startRestart("phone-lab", "nginx", null)
        assertEquals("awaiting_approval", run.status)
        assertEquals("tileops5@$host:$port (phone-lab)", run.approval.target)
        assertTrue(runCatching { engine.approve(run.id, "1111") }.exceptionOrNull().let { it is ApiException && it.code == 409 }) // no PIN yet
        engine.setApprovalPin("2468")
        assertTrue(runCatching { engine.approve(run.id, "1111") }.exceptionOrNull().let { it is ApiException && it.code == 403 })
        val done = engine.approve(run.id, "2468")
        assertEquals(done.steps.toString(), "verified", done.status)
        assertEquals("active", dx("systemctl is-active nginx"))
        // non-allowlisted service is refused before anything runs
        assertTrue(runCatching { engine.startRestart("phone-lab", "ssh", null) }.exceptionOrNull().let { it is ApiException && it.code == 403 })

        // the store on disk is encrypted: no server name or alert text in plain text
        val raw = tmp.root.walkTopDown().filter { it.isFile }.joinToString("") { it.readBytes().decodeToString() }
        assertFalse("phone-lab" in raw || "kdevtmpfsi" in raw || "BEGIN OPENSSH" in raw)

        engine.deleteServer("phone-lab")
        assertTrue(engine.servers().isEmpty())
    }
}
