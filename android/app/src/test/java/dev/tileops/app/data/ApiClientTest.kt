package dev.tileops.app.data

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList

/** Runs ApiClient against a real local HTTP server that mimics the companion. */
class ApiClientTest {
    private data class Seen(val method: String, val path: String, val auth: String?, val body: String)

    private lateinit var server: HttpServer
    private val seen = CopyOnWriteArrayList<Seen>()
    private val routes = mutableMapOf<String, Pair<Int, String>>()
    private val token = "tok_abcdefghijklmnopqrstuvwxyz0123456789"
    private lateinit var api: ApiClient

    @Before
    fun setUp() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            val body = ex.requestBody.readBytes().decodeToString()
            val path = ex.requestURI.toString()
            seen += Seen(ex.requestMethod, path, ex.requestHeaders.getFirst("Authorization"), body)
            val authed = ex.requestHeaders.getFirst("Authorization") == "Bearer $token"
            val (code, resp) = when {
                path == "/health" -> 200 to """{"ok":true,"version":"0.1.0"}"""
                !authed -> 401 to """{"detail":"invalid or missing bearer token"}"""
                else -> routes["${ex.requestMethod} $path"] ?: (404 to """{"detail":"Not Found"}""")
            }
            val bytes = resp.toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(code, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
        server.start()
        api = ApiClient("127.0.0.1:${server.address.port}/", token)
    }

    @After
    fun tearDown() = server.stop(0)

    @Test
    fun normalizesBaseUrl() {
        assertEquals("http://127.0.0.1:${server.address.port}", api.baseUrl)
        assertEquals("https://x.lan:8800", ApiClient.normalizeUrl(" https://x.lan:8800/ "))
    }

    @Test
    fun healthNeedsNoTokenAndOtherCallsSendBearer() = runTest {
        routes["GET /api/status"] = 200 to """{"ok":false,"status":"alert","open_alerts":2,
            "servers":[{"name":"tileops-target","status":"alert","open_alerts":2,"last_scan":1794074325.4}],"extra":"ignored"}"""
        assertTrue(api.health())
        val s = api.status()
        assertFalse(s.ok)
        assertEquals(2, s.openAlerts)
        assertEquals("tileops-target", s.servers.single().name)
        assertNull(seen.first { it.path == "/health" }.auth)
        assertEquals("Bearer $token", seen.first { it.path == "/api/status" }.auth)
    }

    @Test
    fun parsesAlertDetailWithArbitraryEvidence() = runTest {
        routes["GET /api/alerts/7"] = 200 to """{"id":7,"server":"web1","tripwire":"listening_port","key":"tcp/4444",
            "title":"New listening port 4444/tcp (python3)","severity":"high","status":"open","snooze_until":null,
            "first_seen":1.0,"last_seen":2.0,"count":3,"incident_id":9,"ai_report":null,
            "evidence":{"probe":"ports","change":"added","key":"tcp/4444","old":null,
              "new":{"port":4444,"addrs":["0.0.0.0"],"procs":["python3"]},"detail":{},
              "command":"sudo -n ss -tlnpH","raw_excerpt":"LISTEN 0 5 0.0.0.0:4444","collected_at":2.0,"degraded":false},
            "runbook_options":[{"runbook":"restart-service","server":"web1","service":"nginx"}]}"""
        val a = api.alert(7)
        assertEquals("high", a.severity)
        assertEquals(3, a.count)
        assertEquals(9L, a.incidentId)
        assertEquals("sudo -n ss -tlnpH", a.evidence.command)
        assertTrue(a.evidence.newValue.toString().contains("4444"))
        assertEquals("nginx", a.runbookOptions.single().service)
    }

    @Test
    fun alertActionsPostJson() = runTest {
        val alertJson = """{"id":5,"server":"s","tripwire":"new_user","title":"t","severity":"high","status":"snoozed"}"""
        routes["POST /api/alerts/5/snooze"] = 200 to alertJson
        routes["POST /api/alerts/5/accept"] = 200 to alertJson.replace("snoozed", "accepted")
        routes["GET /api/alerts?status=all"] = 200 to "[$alertJson]"
        assertEquals("snoozed", api.snooze(5, 60).status)
        assertEquals("accepted", api.acceptBaseline(5).status)
        assertEquals(1, api.alerts("all").size)
        val snooze = seen.first { it.path == "/api/alerts/5/snooze" }
        assertEquals("POST", snooze.method)
        assertEquals("""{"minutes":60}""", snooze.body)
    }

    @Test
    fun runbookStartAndApprove() = runTest {
        val run = """{"id":3,"runbook":"restart-service","server":"s","service":"nginx","incident_id":1,"status":"%s",
            "approval":{"target":"tileops@10.0.0.2:22 (s)","action":"systemctl restart nginx","impact":"x","health_url":"http://h/"},
            "steps":[{"name":"check status","status":"ok"},{"name":"restart","requires_approval":true,"status":"pending"}]}"""
        routes["POST /api/runbooks/restart-service/run"] = 200 to run.format("awaiting_approval")
        routes["POST /api/runs/3/approve"] = 200 to run.format("verified")
        val r = api.startRestart("s", "nginx", alertId = 4)
        assertEquals("awaiting_approval", r.status)
        assertEquals("systemctl restart nginx", r.approval.action)
        assertTrue(r.steps[1].requiresApproval)
        assertEquals("""{"server":"s","service":"nginx","alert_id":4}""", seen.last().body)
        assertEquals("verified", api.approve(3, "246810").status)
        assertEquals("""{"pin":"246810"}""", seen.last().body)
    }

    @Test
    fun errorsCarryStatusAndDetail() = runTest {
        routes["POST /api/runs/3/approve"] = 403 to """{"detail":"wrong PIN"}"""
        try {
            api.approve(3, "0000")
            fail("expected ApiException")
        } catch (e: ApiException) {
            assertEquals(403, e.code)
            assertEquals("wrong PIN", e.message)
        }
        val bad = ApiClient("http://127.0.0.1:${server.address.port}", "wrong-token")
        try {
            bad.servers()
            fail("expected 401")
        } catch (e: ApiException) {
            assertEquals(401, e.code)
        }
    }

    @Test
    fun pathSegmentsAreEncoded() = runTest {
        routes["POST /api/servers/my%20box/scan"] = 200 to """{"server":"my box","ok":true,"new_alerts":[1,2]}"""
        val r = api.scan("my box")
        assertEquals(listOf(1L, 2L), r.newAlerts)
    }

    @Test(expected = java.io.IOException::class)
    fun unreachableCompanionThrowsIOException() = runTest {
        ApiClient("http://127.0.0.1:1", token).status()
    }

    @Test
    fun serverManagementCalls() = runTest {
        val srv = """{"name":"web2","host":"203.0.113.7","port":22,"user":"tileops","status":"needs_setup",
            "services":["nginx"],"web_roots":["/var/www"],"health_urls":{"nginx":"https://w/"},"source":"app"}"""
        val setup = """{"server":"web2","user":"tileops","public_key":"ssh-ed25519 AAAA tileops-web2",
            "setup_script":"#!/bin/sh\necho TILEOPS SETUP OK","setup_command":"echo 'IyE=' | base64 -d | sh"}"""
        routes["POST /api/servers"] = 201 to """{"server":$srv,"setup":$setup}"""
        routes["PUT /api/servers/web2"] = 200 to srv.replace("22,", "2222,")
        routes["DELETE /api/servers/web2"] = 200 to """{"ok":true,"removed":"web2"}"""
        routes["GET /api/servers/web2/setup"] = 200 to setup
        routes["GET /api/servers/web2/hostkey"] = 200 to """{"fingerprint":"SHA256:abc","key_type":"ssh-ed25519","pinned":null,"matches_pin":null}"""
        routes["POST /api/servers/web2/trust"] = 200 to """{"ok":true,"pinned":"SHA256:abc"}"""
        routes["POST /api/servers/web2/test"] = 200 to """{"ok":false,"stage":"auth","message":"Run the setup command"}"""

        val added = api.addServer(ServerInput(name = "web2", host = "203.0.113.7", services = listOf("nginx"),
            healthUrls = mapOf("nginx" to "https://w/")))
        assertEquals("needs_setup", added.server.status)
        assertEquals("app", added.server.source)
        assertTrue(added.setup.setupCommand.contains("base64 -d"))
        val addBody = seen.last { it.path == "/api/servers" }.body
        assertTrue(addBody, addBody.contains("\"name\":\"web2\"") && addBody.contains("\"port\":22") &&
            addBody.contains("\"web_roots\":[\"/var/www\"]") && addBody.contains("\"health_urls\":{\"nginx\":\"https://w/\"}"))

        val edited = api.updateServer("web2", ServerInput(name = "ignored", host = "203.0.113.7", port = 2222))
        assertEquals(2222, edited.port)
        val put = seen.last { it.method == "PUT" }
        assertFalse(put.body, put.body.contains("\"name\""))  // name is not editable
        assertTrue(put.body.contains("\"port\":2222"))

        assertEquals("ssh-ed25519", api.hostKey("web2").keyType)
        api.trustHostKey("web2", "SHA256:abc")
        assertEquals("""{"fingerprint":"SHA256:abc"}""", seen.last().body)
        assertEquals("auth", api.testServer("web2").stage)
        assertEquals("ssh-ed25519 AAAA tileops-web2", api.serverSetup("web2").publicKey)
        api.deleteServer("web2")
        assertEquals("DELETE", seen.last().method)
    }
}
