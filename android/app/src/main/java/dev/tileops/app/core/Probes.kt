package dev.tileops.app.core

import kotlinx.serialization.json.JsonObject

/**
 * Fixed registry of read-only probe commands: the exact same strings as companion/probes.py.
 * Nothing from the UI or elsewhere is ever run as a command; web roots and service names are
 * validated in [Validation] and quoted.
 */
object Probes {
    private const val UNIT_GLOBS = "-name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path'"
    private const val UNIT_DIRS = "/etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system " +
        "/usr/lib/systemd/system /lib/systemd/system"
    const val DEGRADED = "#TILEOPS-DEGRADED"

    sealed class Parsed {
        data class Items(val items: Map<String, JsonObject>) : Parsed()
        data class Procs(val procs: List<Parsers.Proc>) : Parsed()
    }

    data class Probe(val name: String, val command: String, val parse: (String) -> Parsed)

    fun shellQuote(s: String): String =
        if (s.isNotEmpty() && Regex("^[A-Za-z0-9_@%+=:,./-]+$").matches(s)) s else "'" + s.replace("'", "'\"'\"'") + "'"

    fun all(webRoots: List<String>): List<Probe> = listOf(
        Probe("users", "cat /etc/passwd") { Parsed.Items(Parsers.passwd(it)) },
        Probe("ssh_keys",
            "if sudo -n /usr/local/sbin/tileops-read authorized-keys 2>/dev/null; then :; else " +
                "echo '#TILEOPS-DEGRADED'; " +
                "for f in \"\$HOME/.ssh/authorized_keys\" \"\$HOME/.ssh/authorized_keys2\"; do " +
                "[ -f \"\$f\" ] && { echo \"==> \$(id -un) \$f <==\"; cat \"\$f\"; echo; }; done; " +
                "for f in /root/.ssh/authorized_keys; do [ -r \"\$f\" ] && { echo \"==> root \$f <==\"; cat \"\$f\"; echo; }; done; " +
                "fi") { Parsed.Items(Parsers.authorizedKeys(it)) },
        Probe("cron",
            "if sudo -n /usr/local/sbin/tileops-read crontabs 2>/dev/null; then :; else " +
                "echo '#TILEOPS-DEGRADED'; " +
                "c=\$(crontab -l 2>/dev/null) && { echo \"==> /var/spool/cron/crontabs/\$(id -un) <==\"; printf \"%s\\n\" \"\$c\"; }; " +
                "fi; " +
                "for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/crontabs/* " +
                "/etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do " +
                "[ -f \"\$f\" ] && [ -r \"\$f\" ] && { echo \"==> \$f <==\"; head -c 65536 \"\$f\"; echo; }; done; true") {
            Parsed.Items(Parsers.cron(it))
        },
        Probe("ports",
            "sudo -n ss -tlnpH 2>/dev/null || { echo '#TILEOPS-DEGRADED'; ss -tlnH 2>/dev/null " +
                "|| netstat -tln 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; }") { Parsed.Items(Parsers.ports(it)) },
        Probe("processes",
            "if ps -eo pid,user,pcpu,args --sort=-pcpu >/dev/null 2>&1; then " +
                "ps -eo pid,user,pcpu,args --sort=-pcpu | head -n 41; " +
                "else top -b -n 1 | head -n 60; fi") { Parsed.Procs(Parsers.processes(it)) },
        Probe("webroot",
            "for r in ${webRoots.joinToString(" ") { shellQuote(it) }}; do [ -d \"\$r\" ] || continue; " +
                "find \"\$r\" -xdev -type f -exec stat -c '%Y|%s|%n' {} + 2>/dev/null; done | head -n 5000") {
            Parsed.Items(Parsers.webroot(it))
        },
        Probe("units",
            "for d in $UNIT_DIRS; do [ -d \"\$d\" ] || continue; " +
                "find \"\$d\" -maxdepth 1 -type f \\( $UNIT_GLOBS \\) -exec sha256sum {} + 2>/dev/null; " +
                "find \"\$d\" -maxdepth 1 -type l \\( $UNIT_GLOBS \\) 2>/dev/null | while read -r f; do " +
                "echo \"link:\$(readlink \"\$f\")  \$f\"; done; done; true") { Parsed.Items(Parsers.units(it)) },
    )

    const val ACCESS_CHECK =
        "echo \"USER=\$(id -un)\"; " +
            "sudo -n /usr/local/sbin/tileops-read crontabs >/dev/null 2>&1 && echo SUDO=ok || echo SUDO=no; " +
            "sudo -n ss -tlnpH >/dev/null 2>&1 && echo SS=ok || echo SS=no; " +
            "command -v systemctl >/dev/null 2>&1 && echo SYSTEMCTL=yes || echo SYSTEMCTL=no"

    fun serviceStatus(service: String) = "sudo -n systemctl status --no-pager ${shellQuote(service)}"
    fun serviceRestart(service: String) = "sudo -n systemctl restart ${shellQuote(service)}"
}

/** Same validation rules as companion/config.py. */
object Validation {
    val SERVICE = Regex("^[A-Za-z0-9@._-]{1,64}$")
    val NAME = Regex("^[A-Za-z0-9._-]{1,64}$")
    val WEBROOT = Regex("^/[A-Za-z0-9._/-]{0,200}$")
    val HOST = Regex("^[A-Za-z0-9.:-]{1,253}$")
    val USER = Regex("^[a-z_][a-z0-9_-]{0,31}$")
    val URL = Regex("^https?://\\S{1,500}$")
}
