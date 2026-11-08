package dev.tileops.app.data

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.net.InetSocketAddress
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** Companion-style HTTPS with a self-signed certificate, trusted only via the pinned fingerprint. */
class PinnedTlsTest {
    @get:Rule val tmp = TemporaryFolder()
    private lateinit var server: HttpsServer
    private lateinit var url: String
    private lateinit var pin: String
    private val token = "tok_abcdefghijklmnopqrstuvwxyz0123456789"

    @Before fun setUp() {
        val ks = File(tmp.root, "ks.p12")
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val p = ProcessBuilder(keytool, "-genkeypair", "-keystore", ks.path, "-storetype", "PKCS12", "-storepass", "secret",
            "-alias", "c", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=TileOps companion", "-validity", "2",
            "-ext", "SAN=ip:127.0.0.1").redirectErrorStream(true).start()
        assertEquals(p.inputStream.bufferedReader().readText(), 0, p.waitFor())
        val store = KeyStore.getInstance("PKCS12").apply { ks.inputStream().use { load(it, "secret".toCharArray()) } }
        pin = ApiClient.pinOf(store.getCertificate("c"))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "secret".toCharArray()) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.httpsConfigurator = HttpsConfigurator(ctx)
        server.createContext("/") { ex ->
            val ok = ex.requestHeaders.getFirst("Authorization") == "Bearer $token" || ex.requestURI.path == "/health"
            val body = (if (ex.requestURI.path == "/health") """{"ok":true}""" else """{"ok":true,"status":"ok","open_alerts":0}""").toByteArray()
            ex.sendResponseHeaders(if (ok) 200 else 401, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.start()
        url = "https://127.0.0.1:${server.address.port}"
    }

    @After fun tearDown() = server.stop(0)

    @Test fun correctPinConnects() = runTest {
        val s = ApiClient(url, token, pin).status()
        assertTrue(s.ok)
        // same certificate also works under another name/IP (hostname isn't checked when pinned)
        assertTrue(ApiClient("https://localhost:${server.address.port}", token, pin).status().ok)
    }

    @Test fun wrongPinIsRefused() = runTest {
        val wrong = "A".repeat(43)
        val e = runCatching { ApiClient(url, token, wrong).status() }.exceptionOrNull()
        assertTrue(e.toString(), e is javax.net.ssl.SSLException)
    }

    @Test fun selfSignedWithoutPinIsRefused() = runTest {
        val e = runCatching { ApiClient(url, token).status() }.exceptionOrNull()
        assertTrue(e.toString(), e is javax.net.ssl.SSLException)
    }

    @Test fun fetchCertPinReadsTheCertificateOnly() = runTest {
        assertEquals(pin, ApiClient.fetchCertPin(url))
        assertEquals(95, ApiClient.humanPin(pin).length) // 32 bytes as AB:CD:… colon hex
    }
}
