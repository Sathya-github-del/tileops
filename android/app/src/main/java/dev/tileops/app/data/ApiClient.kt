package dev.tileops.app.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** HTTP error from the companion; [code] is the HTTP status (401 = bad/expired token). */
class ApiException(val code: Int, message: String) : IOException(message)

/**
 * Thin client for the TileOps companion API. Uses only HttpURLConnection + kotlinx.serialization,
 * so it runs unchanged in JVM unit tests. Every call except [health] sends the bearer token.
 */
class ApiClient(
    baseUrl: String,
    private val token: String,
    /** base64url SHA-256 of the companion's certificate: when set, ONLY that certificate is trusted. */
    private val certPin: String? = null,
    private val timeoutMs: Int = 20_000,
) : TileOpsBackend {
    val baseUrl: String = normalizeUrl(baseUrl)
    override val label: String get() = baseUrl
    override val isLocal: Boolean = false

    companion object {
        val json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            encodeDefaults = true
            coerceInputValues = true
        }

        fun normalizeUrl(raw: String): String {
            var u = raw.trim().trimEnd('/')
            if (!u.startsWith("http://") && !u.startsWith("https://")) u = "http://$u"
            return u
        }

        private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

        fun pinOf(cert: Certificate): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.encoded))

        /** The same fingerprint as the companion prints it ("AB:CD:…"), for comparing by eye. */
        fun humanPin(pin: String): String =
            Base64.getUrlDecoder().decode(pin).joinToString(":") { "%02X".format(it) }

        private fun pinnedSocketFactory(check: (X509Certificate) -> Unit): SSLSocketFactory {
            val tm = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
                    throw CertificateException("client certificates are not used")
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    if (chain.isEmpty()) throw CertificateException("no server certificate")
                    check(chain[0])
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            return SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(tm), null) }.socketFactory
        }

        /**
         * Reads the certificate a companion presents, WITHOUT trusting it or sending anything
         * (TLS handshake only). Used when a user types the address by hand, so they can compare
         * the fingerprint with what the companion printed before anything is trusted.
         */
        suspend fun fetchCertPin(url: String): String = withContext(Dispatchers.IO) {
            var seen: String? = null
            val conn = URL(normalizeUrl(url) + "/health").openConnection() as HttpsURLConnection
            conn.sslSocketFactory = pinnedSocketFactory { cert ->
                seen = pinOf(cert)
                throw CertificateException("recorded")
            }
            conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            try { conn.connect() } catch (_: IOException) { } finally { conn.disconnect() }
            seen ?: throw IOException("no TLS certificate received from $url")
        }
    }

    internal suspend fun request(
        method: String,
        path: String,
        body: String? = null,
        auth: Boolean = true,
        readTimeoutMs: Int = timeoutMs,
    ): String = withContext(Dispatchers.IO) {
        val conn = URL(baseUrl + path).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection && certPin != null) {
            // Exact certificate pinning: CA chain and hostname are deliberately not used, so the
            // companion's self-signed certificate works and keeps working if its LAN IP changes.
            conn.sslSocketFactory = pinnedSocketFactory { cert ->
                if (pinOf(cert) != certPin) throw CertificateException(
                    "the companion's certificate (${humanPin(pinOf(cert)).take(23)}…) is not the one you paired with")
            }
            conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
        try {
            conn.requestMethod = method
            conn.connectTimeout = 10_000
            conn.readTimeout = readTimeoutMs
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.setRequestProperty("Accept", "application/json")
            if (auth) conn.setRequestProperty("Authorization", "Bearer $token")
            val payload = body ?: if (method == "POST") "{}" else null
            if (payload != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) throw ApiException(code, detail(text) ?: "HTTP $code")
            text
        } finally {
            conn.disconnect()
        }
    }

    private fun detail(text: String): String? = runCatching {
        json.parseToJsonElement(text).jsonObject["detail"]?.jsonPrimitive?.content
    }.getOrNull()

    private suspend inline fun <reified T> get(path: String): T =
        json.decodeFromString(request("GET", path))

    private suspend inline fun <reified T> post(path: String, body: JsonObject? = null, readTimeoutMs: Int = timeoutMs): T =
        json.decodeFromString(request("POST", path, body?.toString(), readTimeoutMs = readTimeoutMs))

    // ---------------------------------------------------------------- endpoints
    suspend fun health(): Boolean = runCatching {
        json.parseToJsonElement(request("GET", "/health", auth = false)).jsonObject["ok"]?.jsonPrimitive?.content == "true"
    }.getOrDefault(false)

    override suspend fun status(): OverallStatus = get("/api/status")
    override suspend fun servers(): List<Server> = get("/api/servers")
    override suspend fun scan(server: String): ScanResult = post("/api/servers/${enc(server)}/scan", readTimeoutMs = 150_000)
    override suspend fun scanAll(): List<ScanResult> = post("/api/scan", readTimeoutMs = 300_000)

    override suspend fun alerts(status: String): List<Alert> = get("/api/alerts?status=${enc(status)}")
    override suspend fun alert(id: Long): Alert = get("/api/alerts/$id")
    override suspend fun ack(id: Long): Alert = post("/api/alerts/$id/ack")
    override suspend fun snooze(id: Long, minutes: Int): Alert = post("/api/alerts/$id/snooze", buildJsonObject { put("minutes", minutes) })
    override suspend fun acceptBaseline(id: Long): Alert = post("/api/alerts/$id/accept")

    override suspend fun aiStatus(): AiStatus = get("/api/ai")
    override suspend fun investigate(id: Long): AiReport = post("/api/alerts/$id/investigate", readTimeoutMs = 200_000)

    override suspend fun incidents(): List<Incident> = get("/api/incidents")
    override suspend fun incident(id: Long): Incident = get("/api/incidents/$id")

    override suspend fun startRestart(server: String, service: String, alertId: Long?): Run =
        post("/api/runbooks/restart-service/run", buildJsonObject {
            put("server", server)
            put("service", service)
            if (alertId != null) put("alert_id", alertId)
        }, readTimeoutMs = 120_000)

    // ---- server management (add/edit/remove + guided setup)
    override suspend fun addServer(input: ServerInput): AddServerResult =
        json.decodeFromString(request("POST", "/api/servers", json.encodeToString(ServerInput.serializer(), input)))

    override suspend fun updateServer(name: String, input: ServerInput): Server =
        json.decodeFromString(request("PUT", "/api/servers/${enc(name)}",
            json.encodeToString(ServerInput.serializer(), input.copy(name = null))))

    override suspend fun deleteServer(name: String) {
        request("DELETE", "/api/servers/${enc(name)}")
    }

    override suspend fun serverSetup(name: String): ServerSetup = get("/api/servers/${enc(name)}/setup")
    override suspend fun hostKey(name: String): HostKeyInfo = get("/api/servers/${enc(name)}/hostkey")
    override suspend fun trustHostKey(name: String, fingerprint: String) {
        post<JsonObject>("/api/servers/${enc(name)}/trust", buildJsonObject { put("fingerprint", fingerprint) })
    }
    override suspend fun testServer(name: String): AccessTest = post("/api/servers/${enc(name)}/test", readTimeoutMs = 60_000)
    override suspend fun about(): CompanionAbout = runCatching { get<CompanionAbout>("/about") }.getOrDefault(CompanionAbout())

    override suspend fun run(id: Long): Run = get("/api/runs/$id")
    override suspend fun approve(id: Long, pin: String): Run =
        post("/api/runs/$id/approve", buildJsonObject { put("pin", pin) }, readTimeoutMs = 150_000)
    override suspend fun reject(id: Long): Run = post("/api/runs/$id/reject")
}
