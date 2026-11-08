package dev.tileops.app.core

import dev.tileops.app.data.AccessTest
import dev.tileops.app.data.AddServerResult
import dev.tileops.app.data.AiReport
import dev.tileops.app.data.AiStatus
import dev.tileops.app.data.Alert
import dev.tileops.app.data.ApiException
import dev.tileops.app.data.Approval
import dev.tileops.app.data.CompanionAbout
import dev.tileops.app.data.Evidence
import dev.tileops.app.data.HostKeyInfo
import dev.tileops.app.data.Incident
import dev.tileops.app.data.OverallStatus
import dev.tileops.app.data.Run
import dev.tileops.app.data.RunStep
import dev.tileops.app.data.RunbookOption
import dev.tileops.app.data.ScanResult
import dev.tileops.app.data.Server
import dev.tileops.app.data.ServerBrief
import dev.tileops.app.data.ServerInput
import dev.tileops.app.data.ServerSetup
import dev.tileops.app.data.TileOpsBackend
import dev.tileops.app.data.TimelineEvent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/** SSH operations the engine needs; [RealSsh] in the app, a fake in unit tests. */
interface SshPort {
    fun fetchHostKey(host: String, port: Int): WireHostKey
    fun generateKey(comment: String): Ssh.ClientKey
    /** Runs the commands in one session; returns results in order. */
    fun run(server: LocalServer, key: Ssh.ClientKey, pinned: WireHostKey?, commands: List<String>, timeoutMs: Long = 60_000): List<CmdResult>
}

object RealSsh : SshPort {
    override fun fetchHostKey(host: String, port: Int) = Ssh.fetchHostKey(host, port)
    override fun generateKey(comment: String) = Ssh.generateKey(comment)
    override fun run(server: LocalServer, key: Ssh.ClientKey, pinned: WireHostKey?, commands: List<String>, timeoutMs: Long) =
        Ssh.withSession(server.host, server.port, server.user, key, pinned) { s -> commands.map { Ssh.exec(s, it, timeoutMs) } }
}

/**
 * Phone-only mode: the app itself is the companion. Same behaviour as the Python companion
 * (probes, baseline, dedup, alerts, incidents, restart-service runbook with PIN + health check),
 * minus AI and 24/7 scheduling (Android decides when background work runs).
 */
class LocalEngine(
    private val store: LocalStore,
    private val setup: SetupScript,
    private val ssh: SshPort = RealSsh,
    private val appVersion: String = "",
    private val onNewAlert: (Alert) -> Unit = {},
    private val now: () -> Double = { System.currentTimeMillis() / 1000.0 },
    /** Is a VPN connected on this phone right now? (ConnectivityManager in the app.) */
    private val vpnActive: () -> Boolean = { false },
) : TileOpsBackend {
    override val label = "This phone"
    override val isLocal = true

    var cpuThreshold = 50.0
    var cpuConsecutive = 2
    var retryDelaysMs = listOf(3_000L, 8_000L)
    var healthDelayMs = 2_000L

    private val lock = Mutex()
    private val scanLocks = mutableMapOf<String, Mutex>()
    private var state: LocalState = store.loadState()

    private fun save() = store.saveState(state)
    private fun nextId(): Long = state.nextId++
    private fun err(code: Int, msg: String): Nothing = throw ApiException(code, msg)

    private fun srv(name: String): LocalServer = state.servers.firstOrNull { it.name == name } ?: err(404, "unknown server")

    private fun waitingForVpn(s: LocalServer) = s.vpnRequired && !runCatching(vpnActive).getOrDefault(false)
    private fun vpnMessage(s: LocalServer) =
        "${s.name} is only reachable over your VPN. Connect your VPN (e.g. in OpenVPN Connect), then try again."
    private fun requireVpn(s: LocalServer) { if (waitingForVpn(s)) err(409, vpnMessage(s)) }

    /** VPN-only servers not checked in the last [maxAgeSec] (to check right after the user connects the VPN). */
    suspend fun vpnServersDue(maxAgeSec: Double = 300.0): List<String> = lock.withLock {
        if (!runCatching(vpnActive).getOrDefault(false)) return@withLock emptyList()
        state.servers.filter { it.vpnRequired && (now() - (state.scans[it.name]?.lastScan ?: 0.0)) > maxAgeSec }.map { it.name }
    }

    // ================================================================== status
    private fun openCount(server: String) = state.alerts.count { it.alert.server == server && fresh(it.alert).status == "open" }

    private fun serverStatus(s: LocalServer): String {
        val scan = state.scans[s.name]
        if (waitingForVpn(s) && openCount(s.name) == 0) return "needs_vpn"
        return when {
            scan?.lastScan == null -> if (state.pins[s.name] == null) "needs_setup" else "pending"
            scan.error?.startsWith("connect:") == true && scan.lastOk != scan.lastScan -> "unreachable"
            scan.error?.startsWith("setup:") == true -> "needs_setup"
            openCount(s.name) > 0 -> "alert"
            else -> "ok"
        }
    }

    private fun toServer(s: LocalServer): Server {
        val scan = state.scans[s.name]
        return Server(
            name = s.name, host = s.host, port = s.port, user = s.user, status = serverStatus(s),
            lastScan = scan?.lastScan, lastOkScan = scan?.lastOk,
            lastError = scan?.error?.substringAfter(": "),
            degradedProbes = scan?.degraded ?: emptyList(), openAlerts = openCount(s.name), services = s.services,
            webRoots = s.webRoots, healthUrls = s.healthUrls, processAllowlist = s.processAllowlist,
            source = "app", hostKey = state.pins[s.name]?.fingerprint, vpnRequired = s.vpnRequired,
        )
    }

    override suspend fun servers(): List<Server> = lock.withLock { state.servers.map { toServer(it) } }

    override suspend fun status(): OverallStatus = lock.withLock {
        val list = state.servers.map { toServer(it) }
        val bad = list.any { it.status == "alert" || it.status == "unreachable" }
        OverallStatus(!bad, if (bad) "alert" else "ok", list.sumOf { it.openAlerts },
            list.map { ServerBrief(it.name, it.status, it.openAlerts, it.lastScan) })
    }

    // ================================================================== scanning
    private data class ProbeRun(val probe: Probes.Probe, val result: CmdResult?, val error: String?)

    override suspend fun scanAll(): List<ScanResult> = lock.withLock { state.servers.map { it.name } }.map { scan(it) }

    override suspend fun scan(server: String): ScanResult {
        val m = lock.withLock { scanLocks.getOrPut(server) { Mutex() } }
        return m.withLock { doScan(server) }
    }

    private suspend fun doScan(name: String): ScanResult {
        val (s, key, pin) = lock.withLock { Triple(srv(name), store.loadKey(name), state.pins[name]) }
        // VPN-only server and no VPN: skip quietly (not "unreachable", no SSH attempt, no alert)
        if (waitingForVpn(s)) return ScanResult(name, false, "VPN not connected: ${vpnMessage(s)}")
        val started = now()
        if (key == null) return recordFailure(name, started, "setup: TileOps key missing; remove and re-add this server")
        val probes = Probes.all(s.webRoots)
        var runs: List<ProbeRun>? = null
        var lastErr: Exception? = null
        for (attempt in 0..retryDelaysMs.size) {
            try {
                val results = withContext(Dispatchers.IO) {
                    ssh.run(s, Ssh.ClientKey(key, s.publicKey), pin, probes.map { it.command })
                }
                runs = probes.zip(results).map { (p, r) -> ProbeRun(p, r, null) }
                break
            } catch (e: CancellationException) {
                throw e
            } catch (e: HostKeyNotConfirmedException) {
                return recordFailure(name, started, "setup: ${e.message}")
            } catch (e: AuthFailedException) {
                return recordFailure(name, started, "setup: key not accepted: run the setup command on the server")
            } catch (e: HostKeyMismatchException) {
                val f = Tripwires.Finding("host_key", "host_key", "${s.host}:${s.port}",
                    "SSH host key mismatch for ${s.host}:${s.port}", "critical", "changed", null,
                    buildJsonObject { put("error", "mismatch") })
                val ids = lock.withLock { listOfNotNull(raise(name, f, null, e.message)).also { save() } }
                return recordFailure(name, started, "connect: ${e.message}", ids)
            } catch (e: Exception) {
                lastErr = e
                if (attempt < retryDelaysMs.size) delay(retryDelaysMs[attempt])
            }
        }
        if (runs == null) return recordFailure(name, started, "connect: ${lastErr?.message ?: lastErr?.javaClass?.simpleName}")

        return lock.withLock {
            val baseline = store.loadBaseline(name)
            val newIds = mutableListOf<Long>()
            val degraded = mutableListOf<String>()
            val errors = mutableListOf<String>()
            var baselineChanged = false
            for (r in runs) {
                val out = r.result?.stdout ?: ""
                if (Probes.DEGRADED in out) degraded += r.probe.name
                val clean = out.replace(Probes.DEGRADED + "\n", "")
                val parsed = try { r.probe.parse(clean) } catch (e: Exception) { errors += "${r.probe.name}: ${e.message}"; continue }
                val excerpt = clean.take(4000)
                val findings = when (parsed) {
                    is Probes.Parsed.Procs -> {
                        val base = baseline.probes["processes"]
                        if (base == null) { baseline.probes["processes"] = Tripwires.processBaseline(parsed.procs); baselineChanged = true; emptyList() }
                        else {
                            val (f, streaks) = Tripwires.evaluateProcesses(parsed.procs, base, s.processAllowlist,
                                state.hot[name] ?: emptyMap(), cpuThreshold, cpuConsecutive)
                            state.hot[name] = streaks
                            f
                        }
                    }
                    is Probes.Parsed.Items -> {
                        val base = baseline.probes[r.probe.name]
                        if (base == null) { baseline.probes[r.probe.name] = parsed.items; baselineChanged = true; emptyList() }
                        else Tripwires.diff(r.probe.name, base, parsed.items)
                    }
                }
                for (f in findings) raise(name, f, Triple(r.probe.command, excerpt, r.probe.name in degraded))?.let { newIds += it }
            }
            if (baselineChanged) store.saveBaseline(name, baseline)
            val t = now()
            state.scans[name] = LocalScan(t, if (errors.isEmpty()) t else state.scans[name]?.lastOk,
                errors.joinToString("; ").ifEmpty { null }, degraded)
            save()
            ScanResult(name, errors.isEmpty(), errors.joinToString("; ").ifEmpty { null }, newIds)
        }
    }

    private suspend fun recordFailure(name: String, started: Double, error: String, newIds: List<Long> = emptyList()): ScanResult =
        lock.withLock {
            val prev = state.scans[name]
            state.scans[name] = LocalScan(now(), prev?.lastOk, error, emptyList())
            save()
            ScanResult(name, false, error.substringAfter(": "), newIds)
        }

    // ================================================================== alerts (call with lock held)
    private fun excerpt(f: Tripwires.Finding, raw: String): String {
        val needles = mutableSetOf(f.key)
        f.new?.let { n -> listOf("user", "comment", "port", "name").forEach { k -> n[k]?.jsonPrimitive?.content?.takeIf { it.isNotEmpty() }?.let { needles += it } } }
        if (f.probe == "ports") needles.apply { clear(); add(":${f.new?.get("port")?.jsonPrimitive?.content} ") }
        var lines = raw.lines().filter { l -> needles.any { it.isNotEmpty() && it in l } }
        if (f.probe == "cron") Parsers.splitSections(raw).firstOrNull { it.first.trim() == f.key }?.let { (h, b) -> lines = listOf("==> $h <==") + b.lines() }
        if (f.probe == "processes") lines = raw.lines().take(1) + lines
        return lines.take(25).joinToString("\n").take(2000).ifEmpty { raw.take(800) }
    }

    /** Returns the new alert id, or null if this exact change was already alerted (dedup). */
    private fun raise(server: String, f: Tripwires.Finding, probeInfo: Triple<String, String, Boolean>?, extraError: String? = null): Long? {
        val fp = f.fingerprint(server)
        val t = now()
        val i = state.alerts.indexOfFirst { it.fingerprint == fp }
        if (i >= 0) {
            val a = state.alerts[i]
            state.alerts[i] = a.copy(alert = a.alert.copy(lastSeen = t, count = a.alert.count + 1))
            return null
        }
        val id = nextId()
        val incidentId = nextId()
        val ev = Evidence(
            probe = f.probe, change = f.change, key = f.key, old = f.old, newValue = f.new,
            detail = if (extraError != null) buildJsonObject { put("error", extraError) } else f.detail,
            command = probeInfo?.first ?: "ssh connect (host key verification)",
            rawExcerpt = probeInfo?.let { excerpt(f, it.second) } ?: "",
            collectedAt = t, degraded = probeInfo?.third ?: false,
        )
        val alert = Alert(id, server, f.tripwire, f.key, f.title, f.severity, "open", null, t, t, 1, ev, incidentId)
        state.alerts += LocalAlert(alert, fp, f.probe, f.new)
        state.incidents += Incident(incidentId, f.title, server, id, "open", t, t,
            listOf(TimelineEvent(nextId(), t, "alert_raised", "[${f.severity}] ${f.title}")))
        if (state.alerts.size > 2000) state.alerts.removeAt(0)
        runCatching { onNewAlert(alert) }
        return id
    }

    private fun fresh(a: Alert): Alert =
        if (a.status == "snoozed" && (a.snoozeUntil ?: 0.0) < now()) a.copy(status = "open", snoozeUntil = null) else a

    private fun event(incidentId: Long?, kind: String, message: String, data: JsonObject? = null) {
        val i = state.incidents.indexOfFirst { it.id == incidentId }
        if (i < 0) return
        val inc = state.incidents[i]
        val t = now()
        state.incidents[i] = inc.copy(updatedAt = t, events = inc.events + TimelineEvent(nextId(), t, kind, message, data))
    }

    private fun closeIncident(id: Long?) {
        val i = state.incidents.indexOfFirst { it.id == id }
        if (i >= 0 && state.incidents[i].status == "open") state.incidents[i] = state.incidents[i].copy(status = "closed")
    }

    override suspend fun alerts(status: String): List<Alert> = lock.withLock {
        state.alerts.map { fresh(it.alert) }.reversed().filter {
            when (status) {
                "all" -> true
                "active" -> it.status in setOf("open", "acked", "snoozed")
                else -> it.status == status
            }
        }
    }

    override suspend fun alert(id: Long): Alert = lock.withLock {
        val a = fresh(state.alerts.firstOrNull { it.alert.id == id }?.alert ?: err(404, "alert not found"))
        val s = state.servers.firstOrNull { it.name == a.server }
        a.copy(runbookOptions = s?.services?.filter { it in s.healthUrls }?.map { RunbookOption("restart-service", s.name, it) } ?: emptyList())
    }

    private suspend fun setStatus(id: Long, status: String, kind: String, msg: String, snoozeUntil: Double? = null): Alert {
        lock.withLock {
            val i = state.alerts.indexOfFirst { it.alert.id == id }
            if (i < 0) err(404, "alert not found")
            val a = state.alerts[i]
            state.alerts[i] = a.copy(alert = a.alert.copy(status = status, snoozeUntil = snoozeUntil))
            event(a.alert.incidentId, kind, msg)
            if (status == "accepted") closeIncident(a.alert.incidentId)
            save()
        }
        return alert(id)
    }

    override suspend fun ack(id: Long) = setStatus(id, "acked", "alert_acked", "Alert acknowledged")

    override suspend fun snooze(id: Long, minutes: Int): Alert {
        val m = minutes.coerceIn(1, 7 * 24 * 60)
        return setStatus(id, "snoozed", "alert_snoozed", "Snoozed for $m min", now() + m * 60)
    }

    override suspend fun acceptBaseline(id: Long): Alert {
        val msg = lock.withLock {
            val la = state.alerts.firstOrNull { it.alert.id == id } ?: err(404, "alert not found")
            val server = la.alert.server
            when (la.probe) {
                "host_key" -> { state.pins.remove(server); "Host key forgotten; confirm the new one in the server's setup" }
                "processes" -> {
                    val b = store.loadBaseline(server)
                    b.probes["processes"] = (b.probes["processes"] ?: emptyMap()) + (la.alert.key to buildJsonObject { put("seen", true) })
                    store.saveBaseline(server, b)
                    state.hot[server] = (state.hot[server] ?: emptyMap()) - la.alert.key
                    "Process '${la.alert.key}' added to baseline"
                }
                else -> {
                    val b = store.loadBaseline(server)
                    val cur = (b.probes[la.probe] ?: emptyMap()).toMutableMap()
                    val nv = la.newValue as? JsonObject
                    if (nv != null) cur[la.alert.key] = nv else cur.remove(la.alert.key)
                    b.probes[la.probe] = cur
                    store.saveBaseline(server, b)
                    "Accepted current state of ${la.alert.key} as baseline"
                }
            }
        }
        return setStatus(id, "accepted", "baseline_accepted", msg)
    }

    // ================================================================== AI (not in phone-only mode)
    override suspend fun aiStatus() = AiStatus(false, null, "AI not configured")
    override suspend fun investigate(id: Long): AiReport = err(503, "AI not configured")

    // ================================================================== incidents
    override suspend fun incidents(): List<Incident> = lock.withLock {
        state.incidents.sortedByDescending { it.updatedAt }.take(200).map { it.copy(events = emptyList()) }
    }

    override suspend fun incident(id: Long): Incident = lock.withLock {
        val inc = state.incidents.firstOrNull { it.id == id } ?: err(404, "incident not found")
        inc.copy(runs = state.runs.filter { it.incidentId == id })
    }

    // ================================================================== runbook: restart-service
    private fun saveRun(r: Run) {
        val i = state.runs.indexOfFirst { it.id == r.id }
        if (i >= 0) state.runs[i] = r else state.runs += r
    }

    private fun step(r: Run, i: Int, status: String, output: String = ""): Run {
        val steps = r.steps.toMutableList()
        steps[i] = steps[i].copy(status = status, output = output.takeLast(1500).ifEmpty { steps[i].output })
        val nr = r.copy(steps = steps)
        saveRun(nr)
        if (status != "running") event(r.incidentId, "runbook_step_$status", "Run #${r.id} step '${steps[i].name}': $status",
            buildJsonObject { put("run_id", r.id); put("step", steps[i].name); put("output", output.takeLast(400)) })
        return nr
    }

    override suspend fun startRestart(server: String, service: String, alertId: Long?): Run {
        val (s, key, pin, run0) = lock.withLock {
            val s = state.servers.firstOrNull { it.name == server } ?: err(404, "unknown server")
            requireVpn(s)
            if (!Validation.SERVICE.matches(service) || service !in s.services) err(403, "service '$service' is not allowlisted for $server")
            val health = s.healthUrls[service] ?: err(400, "no health URL set for $service on $server")
            var incidentId = alertId?.let { aid -> (state.alerts.firstOrNull { it.alert.id == aid } ?: err(404, "alert not found")).alert.incidentId }
            val t = now()
            if (incidentId == null) {
                incidentId = nextId()
                state.incidents += Incident(incidentId, "Restart $service on $server", server, null, "open", t, t)
            }
            val run = Run(
                nextId(), "restart-service", server, service, incidentId, alertId, "running",
                Approval(
                    target = "${s.user}@${s.host}:${s.port} (${s.name})", action = "systemctl restart $service",
                    command = Probes.serviceRestart(service),
                    impact = "$service on ${s.name} stops and starts again; expect a few seconds of downtime and dropped " +
                        "in-flight connections. Success requires GET $health to return HTTP 200 (up to 3 retries).",
                    healthUrl = health,
                ),
                listOf(RunStep("check status", "check_status", false, "pending"), RunStep("restart", "restart", true, "pending"),
                    RunStep("verify health", "verify_health", false, "pending")),
            )
            saveRun(run)
            event(incidentId, "runbook_started", "Runbook restart-service #${run.id} started for $service on $server", buildJsonObject { put("run_id", run.id) })
            save()
            Quad(s, store.loadKey(server), state.pins[server], run)
        }
        var run = run0
        val res = runCatching {
            withContext(Dispatchers.IO) { ssh.run(s, Ssh.ClientKey(key ?: err(409, "server key missing"), s.publicKey), pin, listOf(Probes.serviceStatus(service)), 30_000) }.first()
        }
        return lock.withLock {
            run = res.fold(
                onSuccess = { step(run, 0, "ok", it.stdout.ifEmpty { it.stderr }).copy(status = "awaiting_approval") },
                onFailure = { step(run, 0, "failed", "${it.javaClass.simpleName}: ${it.message}").copy(status = "failed") },
            )
            saveRun(run)
            if (run.status == "awaiting_approval") event(run.incidentId, "approval_requested",
                "Approval needed: ${run.approval.action} on ${run.approval.target}", buildJsonObject { put("run_id", run.id) })
            save()
            run
        }
    }

    private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)

    override suspend fun run(id: Long): Run = lock.withLock { state.runs.firstOrNull { it.id == id } ?: err(404, "run not found") }

    override suspend fun reject(id: Long): Run = lock.withLock {
        val r = state.runs.firstOrNull { it.id == id } ?: err(404, "run not found")
        if (r.status != "awaiting_approval") err(409, "run is ${r.status}")
        val nr = r.copy(status = "rejected", steps = r.steps.map { if (it.status == "pending") it.copy(status = "skipped") else it })
        saveRun(nr)
        event(r.incidentId, "runbook_rejected", "Run #$id rejected")
        save()
        nr
    }

    override suspend fun approvalPinSet(): Boolean = lock.withLock { state.pinHash != null }

    override suspend fun setApprovalPin(pin: String) {
        if (!Regex("^\\d{4,12}$").matches(pin)) err(400, "Use 4 to 12 digits")
        lock.withLock {
            val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            state.pinSalt = Base64.getEncoder().encodeToString(salt)
            state.pinHash = hashPin(pin, salt)
            save()
        }
    }

    private fun hashPin(pin: String, salt: ByteArray): String {
        val spec = PBEKeySpec(pin.toCharArray(), salt, 120_000, 256)
        return Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded)
    }

    override suspend fun approve(id: Long, pin: String): Run {
        val (s, key, pinned, run0) = lock.withLock {
            val r = state.runs.firstOrNull { it.id == id } ?: err(404, "run not found")
            if (r.status != "awaiting_approval") err(409, "run is ${r.status}, not awaiting approval")
            val hash = state.pinHash ?: err(409, "Set an approval PIN first")
            val cutoff = System.currentTimeMillis() - 15 * 60_000
            state.pinFailures.removeAll { it < cutoff }
            if (state.pinFailures.size >= 10) err(429, "too many wrong PINs recently; wait 15 minutes")
            val ok = java.security.MessageDigest.isEqual(
                hashPin(pin, Base64.getDecoder().decode(state.pinSalt)).toByteArray(), hash.toByteArray())
            if (!ok) {
                state.pinFailures += System.currentTimeMillis()
                val fails = state.pinFailures.size
                if (fails >= 5) {
                    saveRun(r.copy(status = "locked"))
                    event(r.incidentId, "runbook_locked", "Run #$id locked after 5 wrong PINs")
                }
                save()
                err(403, "wrong PIN")
            }
            requireVpn(srv(r.server))
            val running = r.copy(status = "running")
            saveRun(running)
            event(r.incidentId, "approved", "Run #$id approved with PIN")
            save()
            Quad(srv(r.server), store.loadKey(r.server), state.pins[r.server], running)
        }
        var run = run0
        val restart = runCatching {
            withContext(Dispatchers.IO) {
                ssh.run(s, Ssh.ClientKey(key ?: throw IOException("server key missing"), s.publicKey), pinned,
                    listOf(Probes.serviceRestart(run.service)), 90_000)
            }.first()
        }
        lock.withLock {
            run = restart.fold(
                onSuccess = { step(run, 1, if (it.exitStatus == 0) "ok" else "failed", (it.stdout + it.stderr).ifEmpty { "exit ${it.exitStatus}" }) },
                onFailure = { step(run, 1, "failed", "${it.javaClass.simpleName}: ${it.message}") },
            )
            save()
        }
        // the health check is the source of truth, never the exit code alone
        val (ok, log) = verify(run.approval.healthUrl)
        return lock.withLock {
            run = step(run, 2, if (ok) "ok" else "failed", log.joinToString("\n")).copy(status = if (ok) "verified" else "failed")
            saveRun(run)
            event(run.incidentId, "runbook_${run.status}",
                "Run #$id ${run.status}: health check ${if (ok) "passed" else "did not pass"} (${run.approval.healthUrl})")
            save()
            run
        }
    }

    private suspend fun verify(url: String): Pair<Boolean, List<String>> {
        val log = mutableListOf<String>()
        for (attempt in 0..3) {
            if (attempt > 0) delay(healthDelayMs)
            val code = withContext(Dispatchers.IO) {
                runCatching {
                    val c = URL(url).openConnection() as HttpURLConnection
                    c.connectTimeout = 5_000; c.readTimeout = 5_000; c.instanceFollowRedirects = false
                    try { c.responseCode } finally { c.disconnect() }
                }
            }
            code.fold(
                onSuccess = { log += "attempt ${attempt + 1}: HTTP $it"; if (it == 200) return true to log },
                onFailure = { log += "attempt ${attempt + 1}: ${it.javaClass.simpleName}" },
            )
        }
        return false to log
    }

    // ================================================================== server registry
    private fun validate(s: LocalServer) {
        fun bad(m: String): Nothing = err(400, m)
        if (!Validation.NAME.matches(s.name)) bad("Name: letters, digits, . _ - (max 64)")
        if (!Validation.HOST.matches(s.host)) bad("bad host ${s.host}")
        if (!Validation.USER.matches(s.user)) bad("bad user ${s.user}")
        if (s.port !in 1..65535) bad("bad port")
        if (s.webRoots.isEmpty() || s.webRoots.size > 10 || s.webRoots.any { !Validation.WEBROOT.matches(it) || ".." in it.split("/") }) bad("bad web root")
        if (s.services.size > 20 || s.services.any { !Validation.SERVICE.matches(it) }) bad("bad service name")
        s.healthUrls.forEach { (svc, url) ->
            if (svc !in s.services) bad("health URL for a service that isn't allowlisted: $svc")
            if (!Validation.URL.matches(url)) bad("bad health URL $url")
        }
    }

    private fun setupFor(s: LocalServer): ServerSetup {
        val script = setup.build(s.name, s.user, s.services, s.publicKey)
        return ServerSetup(s.name, s.user, s.publicKey, script, SetupScript.oneLiner(script), listOf(
            "Log in to ${s.host} with any SSH app as root or a sudo user.",
            "Paste the setup command and run it (it asks for your sudo password if needed).",
            "Check that it prints TILEOPS SETUP OK and note the ED25519 fingerprint.",
            "Back in TileOps: fetch the host key, compare the fingerprint, trust it, then test.",
            "No root? Add the public key to ~/.ssh/authorized_keys of user '${s.user}'; TileOps then runs in degraded (read-only) mode.",
        ))
    }

    override suspend fun addServer(input: ServerInput): AddServerResult {
        val name = input.name?.trim().orEmpty()
        val draft = LocalServer(name, input.host.trim(), input.port, input.user, input.webRoots, input.services, input.healthUrls,
            vpnRequired = input.vpnRequired)
        lock.withLock {
            validate(draft)
            if (state.servers.any { it.name == name }) err(409, "a server named '$name' already exists")
            if (state.servers.size >= 50) err(409, "at most 50 servers")
        }
        val key = withContext(Dispatchers.Default) { ssh.generateKey("tileops-$name") }
        val s = draft.copy(publicKey = key.publicLine, createdAt = now())
        lock.withLock {
            store.saveKey(name, key.privateKey)
            state.servers += s
            save()
        }
        return AddServerResult(servers().first { it.name == name }, setupFor(s))
    }

    override suspend fun updateServer(name: String, input: ServerInput): Server {
        lock.withLock {
            val old = srv(name)
            val new = old.copy(host = input.host.trim(), port = input.port, user = input.user, webRoots = input.webRoots,
                services = input.services, healthUrls = input.healthUrls, vpnRequired = input.vpnRequired)
            validate(new)
            if (new.host != old.host || new.port != old.port) {
                state.pins.remove(name); state.scans.remove(name); state.hot.remove(name); store.deleteBaseline(name)
            }
            state.servers[state.servers.indexOf(old)] = new
            save()
        }
        return servers().first { it.name == name }
    }

    override suspend fun deleteServer(name: String) = lock.withLock {
        val s = srv(name)
        state.servers.remove(s)
        state.pins.remove(name); state.scans.remove(name); state.hot.remove(name)
        store.deleteBaseline(name); store.deleteKey(name)
        save()
    }

    override suspend fun serverSetup(name: String): ServerSetup = lock.withLock { setupFor(srv(name)) }

    override suspend fun hostKey(name: String): HostKeyInfo {
        val s = lock.withLock { srv(name).also { requireVpn(it) } }
        val k = try {
            withContext(Dispatchers.IO) { ssh.fetchHostKey(s.host, s.port) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            err(502, "Can't reach ${s.host}:${s.port} from this phone (${e.message ?: e.javaClass.simpleName})")
        }
        val pinned = lock.withLock { state.pins[name]?.fingerprint }
        return HostKeyInfo(k.fingerprint, k.type, pinned, pinned?.let { it == k.fingerprint })
    }

    override suspend fun trustHostKey(name: String, fingerprint: String) {
        val s = lock.withLock { srv(name).also { requireVpn(it) } }
        val k = withContext(Dispatchers.IO) { runCatching { ssh.fetchHostKey(s.host, s.port) } }
            .getOrElse { err(502, "Can't reach ${s.host}:${s.port}") }
        if (k.fingerprint != fingerprint.trim()) err(409, "the server now presents ${k.fingerprint}, not the fingerprint you confirmed; nothing trusted")
        lock.withLock { state.pins[name] = k; save() }
    }

    override suspend fun testServer(name: String): AccessTest {
        val (s, key, pin) = lock.withLock { Triple(srv(name), store.loadKey(name), state.pins[name]) }
        if (waitingForVpn(s)) return AccessTest(false, "vpn", vpnMessage(s))
        return try {
            val out = withContext(Dispatchers.IO) {
                ssh.run(s, Ssh.ClientKey(key ?: throw IOException("key missing"), s.publicKey), pin, listOf(Probes.ACCESS_CHECK), 30_000)
            }.first().stdout
            val sudo = "SUDO=ok" in out
            AccessTest(true, "done", if (sudo) "All good." else "Logged in, but the sudo rules are missing: TileOps will run in degraded (read-only) mode.",
                out.substringAfter("USER=", "").substringBefore("\n").ifEmpty { s.user }, sudo)
        } catch (e: HostKeyNotConfirmedException) {
            AccessTest(false, "hostkey", "Fetch and trust the host key first.")
        } catch (e: HostKeyMismatchException) {
            AccessTest(false, "hostkey", e.message ?: "host key mismatch")
        } catch (e: AuthFailedException) {
            AccessTest(false, "auth", "The server did not accept the TileOps key. Run the setup command, then test again.")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            AccessTest(false, "connect", "Can't reach ${s.host}:${s.port} from this phone (firewall? wrong port? same network?" +
                (if (s.vpnRequired) " Is your VPN connected and does it route to this server?" else "") + ").",
                error = "${e.javaClass.simpleName}: ${e.message}".take(300))
        }
    }

    override suspend fun about() = CompanionAbout("TileOps on this phone", appVersion, "Sathya Prakash J")

    @Suppress("unused")
    private val unused = JsonPrimitive(0)
}
