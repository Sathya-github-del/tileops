package dev.tileops.app.data

import java.net.URLDecoder

/** Parses the companion's pairing QR: tileops://pair?url=<urlencoded http(s) URL>&token=<token>. */
object PairingUri {
    private val TOKEN_RE = Regex("^[A-Za-z0-9_\\-]{16,128}$")
    private val PIN_RE = Regex("^[A-Za-z0-9_-]{43}$")

    /** Finds a pairing link inside pasted text (people copy whole terminal lines). */
    fun extract(text: String?): Pairing? {
        val t = text ?: return null
        val i = t.indexOf("tileops://pair")
        if (i < 0) return null
        return parse(t.substring(i).takeWhile { !it.isWhitespace() && it != '"' && it != '\'' && it != '<' })
    }

    fun parse(raw: String?): Pairing? {
        val s = raw?.trim() ?: return null
        if (!s.startsWith("tileops://pair")) return null
        val query = s.substringAfter('?', "")
        val params = query.split('&').mapNotNull { part ->
            val k = part.substringBefore('=', "")
            if (k.isEmpty()) null else k to runCatching { URLDecoder.decode(part.substringAfter('='), "UTF-8") }.getOrNull()
        }.toMap()
        val url = params["url"]?.trim()?.trimEnd('/') ?: return null
        val token = params["token"]?.trim() ?: return null
        if (!validUrl(url) || !TOKEN_RE.matches(token)) return null
        val pin = params["fp"]?.trim()?.takeIf { PIN_RE.matches(it) }
        if (params["fp"] != null && pin == null) return null // a malformed pin is not silently dropped
        return Pairing(url, token, pin)
    }

    fun validUrl(url: String): Boolean =
        Regex("^https?://[A-Za-z0-9.\\-\\[\\]:]+(:\\d{1,5})?(/.*)?$").matches(url.trim())

    /** Alert id from tileops://alert/<id>, or null. */
    fun alertId(raw: String?): Long? {
        val s = raw?.trim() ?: return null
        if (!s.startsWith("tileops://alert/")) return null
        return s.removePrefix("tileops://alert/").substringBefore('?').trimEnd('/').toLongOrNull()
    }
}
