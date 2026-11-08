package dev.tileops.app.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** Phone-only mode must run exactly what the companion runs: compared against fixtures exported from Python. */
class ParityTest {
    private fun res(name: String) = javaClass.classLoader!!.getResource(name)!!.readText()

    @Test
    fun probeCommandsMatchCompanion() {
        val expected = Json.parseToJsonElement(res("probe_commands.json")).jsonObject.mapValues { it.value.jsonPrimitive.content }
        val mine = Probes.all(listOf("/var/www", "/srv/my site", "/srv/it's")).associate { it.name to it.command } +
            mapOf("access_check" to Probes.ACCESS_CHECK, "status:nginx" to Probes.serviceStatus("nginx"),
                "restart:php8.3-fpm" to Probes.serviceRestart("php8.3-fpm"))
        assertEquals(expected.keys, mine.keys)
        for (k in expected.keys) assertEquals("command '$k'", expected[k], mine[k])
    }

    @Test
    fun setupScriptMatchesCompanion() {
        val assets = File("../../companion/assets")
        val setup = SetupScript(File(assets, "setup.sh.tmpl").readText(), File(assets, "tileops-read").readText())
        val pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDflavvmjl82utnUtJ/bKPIJpYOn14eEFXrcMWsA/mYW tileops-web1"
        val script = setup.build("web1", "tileops", listOf("nginx", "php8.3-fpm"), pk)
        assertEquals(res("setup_expected.sh"), script)
        assertEquals(res("setup_expected_oneliner.txt"), SetupScript.oneLiner(script))
    }

    @Test(expected = IllegalArgumentException::class)
    fun setupRejectsInjectedKey() {
        SetupScript("x", "y").build("w", "tileops", emptyList(), "ssh-ed25519 AAAA'; rm -rf / #")
    }
}
