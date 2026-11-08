package dev.tileops.app.core

import java.util.Base64

/**
 * Builds the one-time server setup script from the template + helper shared with the companion
 * (companion/assets/setup.sh.tmpl and tileops-read, packaged as app assets).
 */
class SetupScript(private val template: String, private val helper: String) {

    fun build(name: String, user: String, services: List<String>, publicKey: String): String {
        require(Validation.USER.matches(user)) { "bad user" }
        require(services.all { Validation.SERVICE.matches(it) }) { "bad service" }
        val pk = publicKey.trim()
        require(!pk.contains('\'') && !pk.contains('\n') && pk.startsWith("ssh-ed25519 ")) { "bad public key" }
        val h = if (helper.endsWith("\n")) helper else helper + "\n"
        return template
            .replace("__HELPER__", h)
            .replace("__NAME__", name)
            .replace("__USER__", user)
            .replace("__KEY__", pk)
            .replace("__SERVICES_HUMAN__", services.joinToString(", ").ifEmpty { "(none)" })
            .replace("__SERVICES__", services.joinToString(" "))
    }

    companion object {
        /** Copy-paste command: decodes the script and runs it as root (via sudo when needed). */
        fun oneLiner(script: String): String {
            val b64 = Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_8))
            return "echo '$b64' | base64 -d | if [ \"\$(id -u)\" = 0 ]; then sh; else sudo sh; fi"
        }
    }
}
