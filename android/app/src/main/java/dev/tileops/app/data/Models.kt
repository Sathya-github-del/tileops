package dev.tileops.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class OverallStatus(
    val ok: Boolean,
    val status: String,
    @SerialName("open_alerts") val openAlerts: Int = 0,
    val servers: List<ServerBrief> = emptyList(),
)

@Serializable
data class ServerBrief(
    val name: String,
    val status: String,
    @SerialName("open_alerts") val openAlerts: Int = 0,
    @SerialName("last_scan") val lastScan: Double? = null,
)

@Serializable
data class Server(
    val name: String,
    val host: String,
    val port: Int,
    val user: String,
    val status: String,
    @SerialName("last_scan") val lastScan: Double? = null,
    @SerialName("last_ok_scan") val lastOkScan: Double? = null,
    @SerialName("last_error") val lastError: String? = null,
    @SerialName("degraded_probes") val degradedProbes: List<String> = emptyList(),
    @SerialName("open_alerts") val openAlerts: Int = 0,
    val services: List<String> = emptyList(),
    @SerialName("web_roots") val webRoots: List<String> = emptyList(),
    @SerialName("health_urls") val healthUrls: Map<String, String> = emptyMap(),
    @SerialName("process_allowlist") val processAllowlist: List<String> = emptyList(),
    /** "config" = companion config file (read-only here), "app" = added from the app */
    val source: String = "config",
    /** Phone-only mode: the server can only be reached while a VPN is connected on this phone. */
    @SerialName("vpn_required") val vpnRequired: Boolean = false,
    @SerialName("host_key") val hostKey: String? = null,
)

/** Body for add (with name) / edit (name ignored) of an app-managed server. */
@Serializable
data class ServerInput(
    val name: String? = null,
    val host: String,
    val port: Int = 22,
    val user: String = "tileops",
    @SerialName("web_roots") val webRoots: List<String> = listOf("/var/www"),
    val services: List<String> = emptyList(),
    @SerialName("health_urls") val healthUrls: Map<String, String> = emptyMap(),
    @SerialName("vpn_required") val vpnRequired: Boolean = false,
)

@Serializable
data class ServerSetup(
    val server: String,
    val user: String,
    @SerialName("public_key") val publicKey: String,
    @SerialName("setup_script") val setupScript: String,
    @SerialName("setup_command") val setupCommand: String,
    @SerialName("manual_steps") val manualSteps: List<String> = emptyList(),
)

@Serializable
data class AddServerResult(val server: Server, val setup: ServerSetup)

@Serializable
data class HostKeyInfo(
    val fingerprint: String,
    @SerialName("key_type") val keyType: String,
    val pinned: String? = null,
    @SerialName("matches_pin") val matchesPin: Boolean? = null,
)

@Serializable
data class AccessTest(
    val ok: Boolean,
    val stage: String,
    val message: String = "",
    val user: String? = null,
    @SerialName("sudo_ok") val sudoOk: Boolean? = null,
    val error: String? = null,
)

@Serializable
data class CompanionAbout(val name: String = "TileOps", val version: String = "", val author: String = "")

@Serializable
data class ScanResult(
    val server: String,
    val ok: Boolean,
    val error: String? = null,
    @SerialName("new_alerts") val newAlerts: List<Long> = emptyList(),
)

@Serializable
data class Evidence(
    val probe: String? = null,
    val change: String? = null,
    val key: String? = null,
    val old: JsonElement? = null,
    @SerialName("new") val newValue: JsonElement? = null,
    val detail: JsonElement? = null,
    val command: String? = null,
    @SerialName("raw_excerpt") val rawExcerpt: String? = null,
    @SerialName("collected_at") val collectedAt: Double? = null,
    val degraded: Boolean = false,
)

@Serializable
data class RunbookOption(val runbook: String, val server: String, val service: String)

@Serializable
data class AiReport(
    val summary: String = "",
    val known: List<String> = emptyList(),
    val suspected: List<String> = emptyList(),
    val unverified: List<String> = emptyList(),
    @SerialName("next_read_only_checks") val nextChecks: List<String> = emptyList(),
    @SerialName("_model") val model: String? = null,
    @SerialName("created_at") val createdAt: Double? = null,
)

@Serializable
data class AiStatus(val enabled: Boolean, val model: String? = null, val message: String? = null)

@Serializable
data class Alert(
    val id: Long,
    val server: String,
    val tripwire: String,
    val key: String = "",
    val title: String,
    val severity: String,
    val status: String,
    @SerialName("snooze_until") val snoozeUntil: Double? = null,
    @SerialName("first_seen") val firstSeen: Double = 0.0,
    @SerialName("last_seen") val lastSeen: Double = 0.0,
    val count: Int = 1,
    val evidence: Evidence = Evidence(),
    @SerialName("incident_id") val incidentId: Long? = null,
    @SerialName("ai_report") val aiReport: AiReport? = null,
    @SerialName("runbook_options") val runbookOptions: List<RunbookOption> = emptyList(),
)

@Serializable
data class Incident(
    val id: Long,
    val title: String,
    val server: String,
    @SerialName("alert_id") val alertId: Long? = null,
    val status: String,
    @SerialName("created_at") val createdAt: Double = 0.0,
    @SerialName("updated_at") val updatedAt: Double = 0.0,
    val events: List<TimelineEvent> = emptyList(),
    val runs: List<Run> = emptyList(),
)

@Serializable
data class TimelineEvent(
    val id: Long,
    val ts: Double,
    val kind: String,
    val message: String,
    val data: JsonElement? = null,
)

@Serializable
data class Approval(
    val target: String = "",
    val action: String = "",
    val command: String = "",
    val impact: String = "",
    @SerialName("health_url") val healthUrl: String = "",
    @SerialName("requires_pin") val requiresPin: Boolean = true,
)

@Serializable
data class RunStep(
    val name: String,
    val kind: String = "",
    @SerialName("requires_approval") val requiresApproval: Boolean = false,
    val status: String,
    val output: String? = null,
)

@Serializable
data class Run(
    val id: Long,
    val runbook: String,
    val server: String,
    val service: String,
    @SerialName("incident_id") val incidentId: Long? = null,
    @SerialName("alert_id") val alertId: Long? = null,
    val status: String,
    val approval: Approval = Approval(),
    val steps: List<RunStep> = emptyList(),
)

/** [certPin]: base64url SHA-256 of the companion's TLS certificate (from the pairing link), or null. */
data class Pairing(val baseUrl: String, val token: String, val certPin: String? = null)
