package dev.tileops.app.data

/**
 * Everything the screens need, implemented twice:
 *  - [ApiClient]: "Always-on" mode, talks to a TileOps companion over HTTP.
 *  - [dev.tileops.app.core.LocalEngine]: "Phone only" mode, the app itself logs in to servers over SSH.
 * Errors are reported as [ApiException] (with an HTTP-like code) in both modes.
 */
interface TileOpsBackend {
    /** Shown in the UI: the companion address, or "This phone". */
    val label: String
    val isLocal: Boolean

    suspend fun status(): OverallStatus
    suspend fun servers(): List<Server>
    suspend fun scan(server: String): ScanResult
    suspend fun scanAll(): List<ScanResult>

    suspend fun alerts(status: String = "active"): List<Alert>
    suspend fun alert(id: Long): Alert
    suspend fun ack(id: Long): Alert
    suspend fun snooze(id: Long, minutes: Int): Alert
    suspend fun acceptBaseline(id: Long): Alert

    suspend fun aiStatus(): AiStatus
    suspend fun investigate(id: Long): AiReport

    suspend fun incidents(): List<Incident>
    suspend fun incident(id: Long): Incident

    suspend fun startRestart(server: String, service: String, alertId: Long? = null): Run
    suspend fun run(id: Long): Run
    suspend fun approve(id: Long, pin: String): Run
    suspend fun reject(id: Long): Run

    suspend fun addServer(input: ServerInput): AddServerResult
    suspend fun updateServer(name: String, input: ServerInput): Server
    suspend fun deleteServer(name: String)
    suspend fun serverSetup(name: String): ServerSetup
    suspend fun hostKey(name: String): HostKeyInfo
    suspend fun trustHostKey(name: String, fingerprint: String)
    suspend fun testServer(name: String): AccessTest
    suspend fun about(): CompanionAbout

    /** Phone-only mode keeps its own approval PIN; the companion has one in its config. */
    suspend fun approvalPinSet(): Boolean = true
    suspend fun setApprovalPin(pin: String): Unit = throw UnsupportedOperationException("the companion's PIN is set in its config")
}
