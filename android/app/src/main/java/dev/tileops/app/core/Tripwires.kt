package dev.tileops.app.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray

/** Tripwire diff logic for phone-only mode: port of companion/tripwires.py. */
object Tripwires {
    val BY_PROBE = mapOf(
        "users" to "new_user", "ssh_keys" to "ssh_key", "cron" to "cron", "ports" to "listening_port",
        "processes" to "cpu_process", "webroot" to "webroot_file", "units" to "systemd_unit",
    )

    data class Finding(
        val tripwire: String, val probe: String, val key: String, val title: String, val severity: String,
        val change: String, val old: JsonObject?, val new: JsonObject?, val detail: JsonObject = JsonObject(emptyMap()),
    ) {
        fun fingerprint(server: String): String =
            Parsers.sha256("$server|$tripwire|$key|${Parsers.sha256(Parsers.canonical(new))}")
    }

    private fun JsonObject.str(k: String) = this[k]?.jsonPrimitive?.content
    private fun JsonObject.intOrNull(k: String) = runCatching { this[k]?.jsonPrimitive?.int }.getOrNull()
    private fun JsonObject.list(k: String): List<String> = (this[k] as? JsonArray)?.map { it.jsonPrimitive.content } ?: emptyList()

    private fun same(probe: String, old: JsonObject, new: JsonObject): Boolean = when (probe) {
        "ports" -> old.list("procs") == new.list("procs")
        "users" -> listOf("uid", "gid", "shell").all { old[it] == new[it] }
        "cron" -> old.str("sha256") == new.str("sha256")
        "webroot" -> old["mtime"] == new["mtime"] && old["size"] == new["size"]
        "units" -> old.list("hashes") == new.list("hashes")
        else -> Parsers.canonical(old) == Parsers.canonical(new)
    }

    /** Additions and changes only (removals are not alerts in v0.x). */
    fun diff(probe: String, baseline: Map<String, JsonObject>, current: Map<String, JsonObject>): List<Finding> {
        val tw = BY_PROBE.getValue(probe)
        return current.keys.sorted().mapNotNull { key ->
            val new = current.getValue(key)
            val old = baseline[key]
            when {
                old == null -> added(probe, tw, key, new)
                !same(probe, old, new) -> changed(probe, tw, key, old, new)
                else -> null
            }
        }
    }

    private fun lines(vararg pairs: Pair<String, List<String>>) = buildJsonObject {
        pairs.forEach { (k, v) -> put(k, buildJsonArray { v.forEach { add(JsonPrimitive(it)) } }) }
    }

    private fun added(probe: String, tw: String, key: String, new: JsonObject): Finding = when (probe) {
        "users" -> Finding(tw, probe, key, "New user '$key' (uid ${new.intOrNull("uid")})",
            if (new.intOrNull("uid") == 0) "critical" else "high", "added", null, new)
        "ssh_keys" -> Finding(tw, probe, key, "New SSH key for '${new.str("user")}' (${new.str("type")})",
            if (new.str("user") == "root") "critical" else "high", "added", null, new)
        "cron" -> Finding(tw, probe, key, "New cron source $key", "high", "added", null, new,
            lines("lines_added" to new.list("lines")))
        "ports" -> Finding(tw, probe, key,
            "New listening port ${new.intOrNull("port")}/tcp (${new.list("procs").joinToString(",").ifEmpty { "unknown process" }})",
            "high", "added", null, new)
        "webroot" -> Finding(tw, probe, key, "New file in web root: $key", "high", "added", null, new)
        "units" -> Finding(tw, probe, key, "New systemd unit $key", "high", "added", null, new)
        else -> Finding(tw, probe, key, "New $probe item $key", "medium", "added", null, new)
    }

    private fun changed(probe: String, tw: String, key: String, old: JsonObject, new: JsonObject): Finding = when (probe) {
        "users" -> Finding(tw, probe, key, "User '$key' changed (uid/gid/shell)",
            if (new.intOrNull("uid") == 0 && old.intOrNull("uid") != 0) "critical" else "high", "changed", old, new)
        "cron" -> {
            val oldL = old.list("lines").toSet()
            val newL = new.list("lines")
            Finding(tw, probe, key, "Cron changed: $key", "high", "changed", old, new,
                lines("lines_added" to newL.filter { it !in oldL }, "lines_removed" to old.list("lines").filter { it !in newL.toSet() }))
        }
        "ports" -> Finding(tw, probe, key,
            "Port ${new.intOrNull("port")}/tcp now owned by ${new.list("procs").joinToString(",").ifEmpty { "?" }}", "medium", "changed", old, new)
        "webroot" -> Finding(tw, probe, key, "Web file modified: $key", "medium", "changed", old, new)
        "units" -> Finding(tw, probe, key, "Systemd unit changed: $key", "medium", "changed", old, new)
        else -> Finding(tw, probe, key, "$probe item changed: $key", "medium", "changed", old, new)
    }

    // ------------------------------------------------------------------ processes
    fun processBaseline(procs: List<Parsers.Proc>): Map<String, JsonObject> =
        procs.associate { it.name to buildJsonObject { put("seen", true) } }

    /** Unknown process above [threshold] %CPU for [consecutive] scans in a row -> one finding. */
    fun evaluateProcesses(
        procs: List<Parsers.Proc>, baseline: Map<String, JsonObject>, allowlist: List<String>,
        streaks: Map<String, Int>, threshold: Double, consecutive: Int,
    ): Pair<List<Finding>, Map<String, Int>> {
        val known = baseline.keys + allowlist
        val hot = linkedMapOf<String, Parsers.Proc>()
        for (p in procs) {
            if (p.cpu >= threshold && p.name !in known) {
                val prev = hot[p.name]
                if (prev == null || p.cpu > prev.cpu) hot[p.name] = p
            }
        }
        val newStreaks = hot.keys.associateWith { (streaks[it] ?: 0) + 1 }
        val findings = hot.toSortedMap().mapNotNull { (name, p) ->
            if (newStreaks.getValue(name) < consecutive) null
            else Finding("cpu_process", "processes", name, "Unknown process '$name' using ${"%.0f".format(p.cpu)}% CPU",
                "high", "added", null, buildJsonObject { put("name", name) },
                buildJsonObject {
                    put("pid", p.pid); put("user", p.user); put("cpu", p.cpu); put("args", p.args)
                    put("streak", newStreaks.getValue(name)); put("threshold", threshold)
                })
        }
        return findings to newStreaks
    }
}
