package dev.tileops.app.core

import dev.tileops.app.data.AesGcmTokenCipher
import dev.tileops.app.data.ApiException
import dev.tileops.app.data.ServerInput
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.KeyGenerator

/** VPN-only servers: skipped quietly while no VPN is connected, checked normally once it is. */
class LocalEngineVpnTest {
    @get:Rule val tmp = TemporaryFolder()

    private class FakeSsh : SshPort {
        var sessions = 0
        val hk = WireHostKey("ssh-ed25519", "SHA256:fake", "AAAA")
        override fun fetchHostKey(host: String, port: Int) = hk.also { sessions++ }
        override fun generateKey(comment: String) = Ssh.ClientKey("PRIVATE".toByteArray(), "ssh-ed25519 AAAAC3Nz $comment")
        override fun run(server: LocalServer, key: Ssh.ClientKey, pinned: WireHostKey?, commands: List<String>, timeoutMs: Long): List<CmdResult> {
            sessions++
            return commands.map { cmd ->
                CmdResult(0, when {
                    cmd == "cat /etc/passwd" -> "root:x:0:0::/root:/bin/sh\n"
                    cmd.startsWith("echo \"USER=") -> "USER=tileops\nSUDO=ok\nSS=ok\nSYSTEMCTL=yes\n"
                    cmd.startsWith("if ps") -> "PID USER %CPU COMMAND\n1 root 0.0 /sbin/init\n"
                    else -> ""
                }, "")
            }
        }
    }

    @Test fun vpnOnlyServerWaitsForVpn() = runBlocking {
        var vpnUp = false
        val ssh = FakeSsh()
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val assets = File("../../companion/assets")
        val e = LocalEngine(LocalStore(tmp.newFolder(), AesGcmTokenCipher { key }),
            SetupScript(File(assets, "setup.sh.tmpl").readText(), File(assets, "tileops-read").readText()),
            ssh, vpnActive = { vpnUp }).apply { retryDelaysMs = emptyList() }

        e.addServer(ServerInput("office", "10.8.0.5", 22, vpnRequired = true))
        e.addServer(ServerInput("public", "203.0.113.9", 22))
        assertTrue(e.servers().first { it.name == "office" }.vpnRequired)
        assertEquals("needs_vpn", e.servers().first { it.name == "office" }.status)
        assertEquals("needs_setup", e.servers().first { it.name == "public" }.status)

        // no VPN: no SSH at all, a clear message, not "unreachable", nothing red
        val before = ssh.sessions
        val r = e.scan("office")
        assertFalse(r.ok)
        assertTrue(r.error!!, "VPN" in r.error!!)
        assertEquals(before, ssh.sessions)
        assertEquals("vpn", e.testServer("office").stage)
        assertTrue(runCatching { e.hostKey("office") }.exceptionOrNull().let { it is ApiException && it.code == 409 })
        assertTrue(e.status().ok)
        assertTrue(e.vpnServersDue().isEmpty())

        // VPN connected: works like any server, and is reported as due for a check
        vpnUp = true
        assertEquals(listOf("office"), e.vpnServersDue())
        e.trustHostKey("office", e.hostKey("office").fingerprint)
        assertTrue(e.testServer("office").ok)
        assertTrue(e.scan("office").ok)
        assertEquals("ok", e.servers().first { it.name == "office" }.status)
        assertTrue(e.vpnServersDue().isEmpty()) // just checked

        // VPN dropped again: back to waiting, the last good scan is kept
        vpnUp = false
        assertEquals("needs_vpn", e.servers().first { it.name == "office" }.status)
        assertTrue(e.servers().first { it.name == "office" }.lastOkScan != null)

        // edit keeps / changes the flag
        e.updateServer("office", ServerInput(host = "10.8.0.5", port = 22, vpnRequired = false))
        assertFalse(e.servers().first { it.name == "office" }.vpnRequired)
    }
}
