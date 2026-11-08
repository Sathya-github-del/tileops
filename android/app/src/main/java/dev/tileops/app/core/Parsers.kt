package dev.tileops.app.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/**
 * Probe-output parsers for phone-only mode: a 1:1 port of companion/parsers.py (same keys,
 * same values), tolerant of GNU coreutils/procps/iproute2 and busybox output.
 */
object Parsers {
    fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    /** Canonical JSON (sorted keys) so hashes/fingerprints are stable. */
    fun canonical(e: JsonElement?): String = when (e) {
        null, is JsonNull -> "null"
        is JsonObject -> e.keys.sorted().joinToString(",", "{", "}") { "\"$it\":" + canonical(e[it]) }
        is JsonArray -> e.joinToString(",", "[", "]") { canonical(it) }
        is JsonPrimitive -> e.toString()
    }

    fun splitSections(text: String): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, MutableList<String>>>()
        val header = Regex("^==> (.*) <==$")
        for (line in text.lines()) {
            val m = header.matchEntire(line)
            if (m != null) out += m.groupValues[1] to mutableListOf()
            else if (out.isNotEmpty()) out.last().second += line
        }
        return out.map { it.first to it.second.joinToString("\n") }
    }

    private fun strs(items: Collection<String>) = buildJsonArray { items.forEach { add(JsonPrimitive(it)) } }

    // ---------------------------------------------------------------- users
    fun passwd(text: String): Map<String, JsonObject> {
        val users = linkedMapOf<String, JsonObject>()
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val p = line.split(":")
            if (p.size < 7) continue
            val uid = p[2].toIntOrNull() ?: continue
            val gid = p[3].toIntOrNull() ?: continue
            users[p[0]] = buildJsonObject { put("gid", gid); put("home", p[5]); put("shell", p[6]); put("uid", uid) }
        }
        return users
    }

    // ---------------------------------------------------------------- ssh keys
    private val KEY_TYPES = listOf("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-")
    private val TOKEN = Regex("(?:[^\\s\"]|\"(?:\\\\.|[^\"])*\")+")

    fun authorizedKeys(text: String): Map<String, JsonObject> {
        val keys = linkedMapOf<String, JsonObject>()
        for ((header, body) in splitSections(text)) {
            val user = header.substringBefore(' ')
            val path = header.substringAfter(' ', "")
            for (raw in body.lines()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val tokens = TOKEN.findAll(line).map { it.value }.toList()
                val i = tokens.indexOfFirst { t -> KEY_TYPES.any { t.startsWith(it) } }
                val kb = if (i >= 0 && i + 1 < tokens.size) Triple(tokens[i], tokens[i + 1], tokens.drop(i + 2).joinToString(" ")) else null
                val digest = sha256(line)
                keys["$user:${digest.take(32)}"] = buildJsonObject {
                    put("comment", (kb?.third ?: "").take(120))
                    put("has_options", kb != null && !line.startsWith(kb.first))
                    put("line_sha256", digest)
                    put("path", path)
                    put("type", kb?.first ?: "unknown")
                    put("user", user)
                }
            }
        }
        return keys
    }

    // ---------------------------------------------------------------- cron
    private val WS = Regex("\\s+")

    fun cron(text: String): Map<String, JsonObject> {
        val out = linkedMapOf<String, JsonObject>()
        for ((header, body) in splitSections(text)) {
            val lines = body.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.map { WS.replace(it, " ") }
            out[header.trim()] = buildJsonObject {
                put("lines", strs(lines.take(50)))
                put("n", lines.size)
                put("sha256", sha256(lines.joinToString("\n")))
            }
        }
        return out
    }

    // ---------------------------------------------------------------- ports
    private val USERS_RE = Regex("\\(\"([^\"]+)\",pid=(\\d+)")

    private fun splitHostPort(s: String): Pair<String, Int>? {
        val (host, port) = if (s.startsWith("[") && s.contains("]:")) {
            s.substring(1).substringBeforeLast("]:") to s.substringAfterLast("]:")
        } else s.substringBeforeLast(":", "") to s.substringAfterLast(":")
        val h = host.substringBefore('%').ifEmpty { "*" }
        return port.toIntOrNull()?.let { h to it }
    }

    private fun hexAddr(h: String): String = when (h.length) {
        8 -> h.chunked(2).reversed().joinToString(".") { it.toInt(16).toString() }
        32 -> if (h == "0".repeat(32)) "::" else "v6:" + h.lowercase()
        else -> h
    }

    fun ports(text: String): Map<String, JsonObject> {
        val found = sortedMapOf<Int, Pair<MutableSet<String>, MutableSet<String>>>()
        fun add(port: Int, addr: String, proc: String?) {
            val e = found.getOrPut(port) { sortedSetOf<String>() to sortedSetOf() }
            e.first += addr
            if (proc != null) e.second += proc
        }
        for (line in text.lines()) {
            val s = line.trim()
            if (s.isEmpty()) continue
            val cols = s.split(WS)
            val head = cols[0]
            if (head in setOf("State", "Netid", "Proto", "Active", "sl")) continue
            if (Regex("^\\d+:$").matches(head) && cols.size >= 4) { // /proc/net/tcp
                if (cols[3] != "0A") continue
                val ip = cols[1].substringBefore(':')
                val port = cols[1].substringAfter(':').toIntOrNull(16) ?: continue
                add(port, hexAddr(ip), null)
                continue
            }
            if (head in setOf("tcp", "tcp6", "udp", "udp6")) { // netstat
                if (head.startsWith("udp") || "LISTEN" !in cols) continue
                val hp = cols.getOrNull(3)?.let { splitHostPort(it) } ?: continue
                val proc = if (cols.size > 6 && "/" in cols.last()) cols.last().substringAfter('/') else null
                add(hp.second, hp.first, proc)
                continue
            }
            if (head == "LISTEN" && cols.size >= 4) {
                val hp = splitHostPort(cols[3]) ?: continue
                add(hp.second, hp.first, USERS_RE.find(s)?.groupValues?.get(1))
            }
        }
        return found.entries.associate { (port, v) ->
            "tcp/$port" to buildJsonObject { put("addrs", strs(v.first)); put("port", port); put("procs", strs(v.second)) }
        }
    }

    // ---------------------------------------------------------------- processes
    data class Proc(val pid: Int, val user: String, val cpu: Double, val args: String, val name: String)

    fun procName(args: String): String {
        val a = args.trim()
        if (a.isEmpty()) return "?"
        if (a.startsWith("[") && a.contains("]")) return a.substring(0, a.indexOf(']') + 1)
        val first = a.split(WS)[0]
        return first.substringAfterLast('/').trimEnd(':').ifEmpty { first }
    }

    fun processes(text: String): List<Proc> {
        val lines = text.lines()
        val hdr = lines.indexOfFirst { Regex("^\\s*PID\\b").containsMatchIn(it) }
        if (hdr < 0) return emptyList()
        val header = lines[hdr].trim().split(WS)
        val cpuCol = listOf("%CPU", "CPU%", "%cpu").map { header.indexOf(it) }.firstOrNull { it >= 0 } ?: return emptyList()
        val ncols = header.size - 1
        val userCol = header.indexOf("USER")
        val out = mutableListOf<Proc>()
        for (line in lines.drop(hdr + 1)) {
            if (line.isBlank()) continue
            val parts = line.trim().split(WS, limit = ncols + 1)
            if (parts.size <= ncols) continue
            val pid = parts[0].toIntOrNull() ?: continue
            val cpu = parts[cpuCol].trimEnd('%').toDoubleOrNull() ?: continue
            val args = parts[ncols].trim()
            out += Proc(pid, if (userCol >= 0) parts[userCol] else "", cpu, args.take(300), procName(args))
        }
        return out.sortedByDescending { it.cpu }
    }

    // ---------------------------------------------------------------- web roots
    fun webroot(text: String): Map<String, JsonObject> {
        val out = linkedMapOf<String, JsonObject>()
        for (line in text.lines()) {
            if (line.startsWith("==> ")) continue
            val p = line.split("|", limit = 3)
            if (p.size != 3) continue
            val mtime = p[0].toDoubleOrNull()?.toLong() ?: continue
            val size = p[1].toLongOrNull() ?: continue
            out[p[2]] = buildJsonObject { put("mtime", mtime); put("size", size) }
        }
        return out
    }

    // ---------------------------------------------------------------- systemd units
    private val UNIT_LINE = Regex("^(\\S+)\\s+\\*?(/\\S.*)$")

    fun units(text: String): Map<String, JsonObject> {
        val acc = sortedMapOf<String, Pair<MutableSet<String>, MutableSet<String>>>()
        for (line in text.lines()) {
            val m = UNIT_LINE.matchEntire(line.trim()) ?: continue
            val path = m.groupValues[2]
            val e = acc.getOrPut(path.substringAfterLast('/')) { sortedSetOf<String>() to sortedSetOf() }
            e.first += m.groupValues[1]
            e.second += path
        }
        return acc.mapValues { (_, v) -> buildJsonObject { put("hashes", strs(v.first)); put("paths", strs(v.second)) } }
    }
}
