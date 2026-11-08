package dev.tileops.app.core

import dev.tileops.app.data.Alert
import dev.tileops.app.data.Incident
import dev.tileops.app.data.Run
import dev.tileops.app.data.TokenCipher
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.File

@Serializable
data class LocalServer(
    val name: String,
    val host: String,
    val port: Int = 22,
    val user: String = "tileops",
    val webRoots: List<String> = listOf("/var/www"),
    val services: List<String> = emptyList(),
    val healthUrls: Map<String, String> = emptyMap(),
    val processAllowlist: List<String> = emptyList(),
    val publicKey: String = "",
    val createdAt: Double = 0.0,
    /** Only reachable while a VPN (e.g. OpenVPN Connect) is connected on the phone. */
    val vpnRequired: Boolean = false,
)

@Serializable
data class LocalScan(val lastScan: Double? = null, val lastOk: Double? = null, val error: String? = null, val degraded: List<String> = emptyList())

@Serializable
data class LocalAlert(val alert: Alert, val fingerprint: String, val probe: String, val newValue: JsonElement? = null)

@Serializable
data class LocalState(
    val servers: MutableList<LocalServer> = mutableListOf(),
    val pins: MutableMap<String, WireHostKey> = mutableMapOf(),
    val scans: MutableMap<String, LocalScan> = mutableMapOf(),
    val alerts: MutableList<LocalAlert> = mutableListOf(),
    val incidents: MutableList<Incident> = mutableListOf(),
    val runs: MutableList<Run> = mutableListOf(),
    val hot: MutableMap<String, Map<String, Int>> = mutableMapOf(),
    var nextId: Long = 1,
    var pinHash: String? = null,
    var pinSalt: String? = null,
    val pinFailures: MutableList<Long> = mutableListOf(),
)

/** probe -> key -> value (processes: name -> {"seen":true}) */
@Serializable
data class Baseline(val probes: MutableMap<String, Map<String, JsonObject>> = mutableMapOf())

/**
 * Phone-only mode storage: small JSON documents in the app's private directory, each encrypted
 * with the Android-Keystore-backed AES-GCM key (same scheme as the pairing token). Writes are
 * atomic (temp file + rename). Not thread-safe by itself: [LocalEngine] serialises access.
 */
class LocalStore(private val dir: File, private val cipher: TokenCipher) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }

    init { dir.mkdirs() }

    private fun read(name: String): ByteArray? {
        val f = File(dir, name)
        if (!f.exists()) return null
        return runCatching { cipher.decrypt(f.readBytes()) }.getOrNull()
    }

    private fun write(name: String, data: ByteArray) {
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(cipher.encrypt(data))
        if (!tmp.renameTo(File(dir, name))) throw java.io.IOException("could not save $name")
    }

    private fun delete(name: String) { File(dir, name).delete() }

    fun loadState(): LocalState =
        read("state.bin")?.let { runCatching { json.decodeFromString(LocalState.serializer(), it.decodeToString()) }.getOrNull() } ?: LocalState()

    fun saveState(s: LocalState) = write("state.bin", json.encodeToString(LocalState.serializer(), s).toByteArray())

    fun loadBaseline(server: String): Baseline =
        read("baseline-$server.bin")?.let { runCatching { json.decodeFromString(Baseline.serializer(), it.decodeToString()) }.getOrNull() } ?: Baseline()

    fun saveBaseline(server: String, b: Baseline) = write("baseline-$server.bin", json.encodeToString(Baseline.serializer(), b).toByteArray())
    fun deleteBaseline(server: String) = delete("baseline-$server.bin")

    fun loadKey(server: String): ByteArray? = read("key-$server.bin")
    fun saveKey(server: String, privateKey: ByteArray) = write("key-$server.bin", privateKey)
    fun deleteKey(server: String) = delete("key-$server.bin")

    /** Forget everything (switching away from phone-only mode keeps data unless this is called). */
    fun wipe() { dir.listFiles()?.forEach { it.delete() } }
}
