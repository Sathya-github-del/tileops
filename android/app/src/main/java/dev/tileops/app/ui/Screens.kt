package dev.tileops.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tileops.app.data.Alert
import dev.tileops.app.data.TileOpsBackend
import dev.tileops.app.data.Run
import dev.tileops.app.work.StatusCache
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

private val pretty = Json { prettyPrint = true }
private fun JsonElement?.pretty(): String? =
    if (this == null || this is JsonNull || (this is JsonObject && isEmpty())) null
    else pretty.encodeToString(JsonElement.serializer(), this)

// ======================================================================== servers
@Composable
fun ServersScreen(
    api: TileOpsBackend, refreshKey: Int, onToast: (String) -> Unit, onOpenRun: (Long) -> Unit,
    onAdd: () -> Unit = {}, onEdit: (String) -> Unit = {}, onSetup: (String) -> Unit = {},
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(refreshKey, local) { api.servers() }
    var busy by remember { mutableStateOf<String?>(null) }
    var confirmRemove by remember { mutableStateOf<dev.tileops.app.data.Server?>(null) }
    LoadView(state, onRetry = { local++ }) { servers ->
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            item {
                Button(onClick = onAdd, modifier = Modifier.fillMaxWidth().padding(top = 6.dp)) { Text("+ Add server") }
            }
            if (servers.isEmpty()) item { SectionCard { Text("No servers yet. Tap \"Add server\" to watch your first one.", color = Palette.muted) } }
            items(servers, key = { it.name }) { s ->
                SectionCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Dot(statusColor(s.status))
                        Text(s.name, fontWeight = FontWeight.Bold, fontSize = 17.sp, modifier = Modifier.padding(start = 8.dp).weight(1f))
                        Badge(s.status, statusColor(s.status), dark = false)
                    }
                    KV("Target", "${s.user}@${s.host}:${s.port}")
                    KV("Last scan", ago(s.lastScan))
                    KV("Open alerts", s.openAlerts.toString(), if (s.openAlerts > 0) Palette.critical else Palette.fg)
                    KV("Host key", s.hostKey ?: "not pinned yet")
                    if (s.degradedProbes.isNotEmpty()) KV("Degraded probes", s.degradedProbes.joinToString(), Palette.medium)
                    if (s.vpnRequired) KV("Network", "Only over VPN")
                    if (s.status == "needs_vpn") {
                        Text("Waiting for your VPN: connect it to check this server. TileOps skips it until then (no false alarms).",
                            color = Palette.medium, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp))
                        ConnectVpnButton(onMessage = onToast)
                    } else if (s.status == "needs_setup") {
                        Text("Setup not finished: run the setup command and confirm the host key.",
                            color = Palette.medium, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp))
                    } else s.lastError?.let { KV("Last error", it, Palette.critical) }
                    @OptIn(ExperimentalLayoutApi::class)
                    FlowRow(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(enabled = busy == null, onClick = {
                            busy = s.name
                            scope.launch {
                                try {
                                    val r = api.scan(s.name)
                                    onToast(if (r.ok) "Scan done: ${r.newAlerts.size} new alert(s)" else "Scan failed: ${r.error}")
                                    runCatching { StatusCache.save(ctx, api.status()) }
                                    StatusCache.refreshSurfaces(ctx)
                                } catch (e: Exception) {
                                    onToast(errorText(e))
                                }
                                busy = null
                                local++
                            }
                        }) { Text(if (busy == s.name) "Scanning…" else "Scan now") }
                        s.services.forEach { svc ->
                            OutlinedButton(enabled = busy == null, onClick = {
                                scope.launch {
                                    try { onOpenRun(api.startRestart(s.name, svc).id) } catch (e: Exception) { onToast(errorText(e)) }
                                }
                            }) { Text("Restart $svc…") }
                        }
                        if (s.source == "app") {
                            if (s.status == "needs_setup") Button(onClick = { onSetup(s.name) }) { Text("Finish setup") }
                            else OutlinedButton(onClick = { onSetup(s.name) }) { Text("Setup") }
                            OutlinedButton(onClick = { onEdit(s.name) }) { Text("Edit") }
                            TextButton(onClick = { confirmRemove = s }) { Text("Remove", color = Palette.critical) }
                        }
                    }
                    if (s.source != "app") Text("Defined in the companion's config file.", color = Palette.muted, fontSize = 12.sp)
                }
            }
            item { Spacer(Modifier.height(16.dp)) }
        }
    }
    confirmRemove?.let { srv ->
        val n = srv.name
        AlertDialog(
            onDismissRequest = { confirmRemove = null },
            title = { Text("Remove $n?") },
            text = { Text("TileOps stops watching $n and deletes its key and baseline. Past alerts stay in the timeline. " +
                "To fully revoke access, also delete the '${srv.user}' user (or its key) on ${srv.host}.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = null
                    scope.launch {
                        try { api.deleteServer(n); onToast("Removed $n") } catch (e: Exception) { onToast(errorText(e)) }
                        StatusCache.refreshSurfaces(ctx)
                        local++
                    }
                }) { Text("Remove", color = Palette.critical) }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = null }) { Text("Cancel") } },
        )
    }
}

// ======================================================================== alerts
@Composable
fun AlertsScreen(api: TileOpsBackend, refreshKey: Int, onOpen: (Long) -> Unit) {
    var filter by rememberSaveable { mutableStateOf("active") }
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(refreshKey, local, filter) { api.alerts(filter) }
    Column(Modifier.fillMaxSize()) {
        @OptIn(ExperimentalLayoutApi::class)
        FlowRow(Modifier.padding(horizontal = 16.dp, vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("active", "open", "acked", "snoozed", "accepted", "all").forEach { f ->
                FilterChip(selected = filter == f, onClick = { filter = f }, label = { Text(f) })
            }
        }
        LoadView(state, onRetry = { local++ }) { alerts ->
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
                if (alerts.isEmpty()) item { SectionCard { Text("No alerts. All quiet.", color = Palette.muted) } }
                items(alerts, key = { it.id }) { a -> AlertRow(a) { onOpen(a.id) } }
                item { Spacer(Modifier.height(16.dp)) }
            }
        }
    }
}

@Composable
private fun AlertRow(a: Alert, onClick: () -> Unit) {
    SectionCard(Modifier.clickable(onClick = onClick)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(4.dp).height(36.dp).background(severityColor(a.severity)))
            Column(Modifier.padding(start = 10.dp).weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Badge(a.severity, severityColor(a.severity))
                    Badge(a.status, Palette.muted, dark = false)
                    Spacer(Modifier.weight(1f))
                    Text(ago(a.lastSeen), color = Palette.muted, fontSize = 12.sp)
                }
                Text(a.title, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 6.dp))
                Text("${a.server} · ${tripwireName(a.tripwire)}" + if (a.count > 1) " · seen ${a.count}×" else "", color = Palette.muted, fontSize = 13.sp)
            }
        }
    }
}

// ======================================================================== alert detail
@Composable
fun AlertDetailScreen(api: TileOpsBackend, id: Long, onToast: (String) -> Unit, onOpenRun: (Long) -> Unit, onOpenIncident: (Long) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(id, local) { api.alert(id) to api.aiStatus() }
    var aiBusy by remember { mutableStateOf(false) }
    var confirmAccept by remember { mutableStateOf(false) }

    fun act(label: String, block: suspend () -> Unit) = scope.launch {
        try {
            block()
            onToast(label)
            runCatching { StatusCache.save(ctx, api.status()) }
            StatusCache.refreshSurfaces(ctx)
        } catch (e: Exception) {
            onToast(errorText(e))
        }
        local++
    }

    LoadView(state, onRetry = { local++ }) { (a, ai) ->
        val ev = a.evidence
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp)) {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Badge(a.severity, severityColor(a.severity))
                    Badge(a.status, Palette.muted, dark = false)
                    Spacer(Modifier.weight(1f))
                    Text("#${a.id}", color = Palette.muted)
                }
                Text(a.title, fontSize = 18.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(vertical = 8.dp))
                KV("Server", a.server)
                KV("What changed", tripwireName(a.tripwire))
                KV("First seen", whenText(a.firstSeen))
                KV("Last seen", "${whenText(a.lastSeen)} (${a.count}×)")
                a.snoozeUntil?.let { KV("Snoozed until", whenText(it)) }
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { act("Acknowledged") { api.ack(a.id) } }) { Text("Ack") }
                    OutlinedButton(onClick = { act("Snoozed 1h") { api.snooze(a.id, 60) } }) { Text("Snooze 1h") }
                    OutlinedButton(onClick = { act("Snoozed 24h") { api.snooze(a.id, 1440) } }) { Text("Snooze 24h") }
                    Button(onClick = { confirmAccept = true }) { Text("Mark as expected") }
                }
            }

            SectionCard {
                Text("Evidence", fontWeight = FontWeight.Bold)
                KV("Change", ev.change ?: "-")
                KV("Key", ev.key ?: a.key)
                KV("Collected", whenText(ev.collectedAt))
                KV("Command", ev.command ?: "-")
                if (ev.degraded) KV("Note", "privileged read unavailable (degraded)", Palette.medium)
                ev.detail.pretty()?.let { Text("Detail", color = Palette.muted, fontSize = 12.sp); Mono(it) }
                ev.old.pretty()?.let { Text("Before", color = Palette.muted, fontSize = 12.sp); Mono(it) }
                ev.newValue.pretty()?.let { Text("Now", color = Palette.muted, fontSize = 12.sp); Mono(it) }
                Text("Raw output excerpt", color = Palette.muted, fontSize = 12.sp)
                Mono(ev.rawExcerpt?.ifBlank { null } ?: "(none)")
            }

            SectionCard {
                Text("Investigate & respond", fontWeight = FontWeight.Bold)
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(Modifier.padding(top = 6.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = ai.enabled && !aiBusy, onClick = {
                        aiBusy = true
                        act("AI report ready") { api.investigate(a.id) }.invokeOnCompletion { aiBusy = false }
                    }) { Text(if (!ai.enabled) "AI not configured" else if (aiBusy) "Investigating…" else "AI report") }
                    a.runbookOptions.forEach { o ->
                        OutlinedButton(onClick = {
                            scope.launch {
                                try { onOpenRun(api.startRestart(o.server, o.service, a.id).id) } catch (e: Exception) { onToast(errorText(e)) }
                            }
                        }) { Text("Restart ${o.service}…") }
                    }
                }
                a.incidentId?.let { inc ->
                    TextButton(onClick = { onOpenIncident(inc) }) { Text("Incident timeline →") }
                }
            }

            a.aiReport?.let { r ->
                SectionCard {
                    Text("AI investigation (advisory only, cannot take actions)", fontWeight = FontWeight.Bold)
                    Text(r.summary, modifier = Modifier.padding(vertical = 6.dp))
                    listOf("Known" to r.known, "Suspected" to r.suspected, "Unverified" to r.unverified, "Next read-only checks" to r.nextChecks)
                        .filter { it.second.isNotEmpty() }
                        .forEach { (t, items) ->
                            Text(t, color = Palette.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
                            items.forEach { Text("• $it", fontSize = 14.sp) }
                        }
                    Text("${r.model ?: ""} · ${whenText(r.createdAt)}", color = Palette.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
                }
            }
            Spacer(Modifier.height(16.dp))
        }

        if (confirmAccept) AlertDialog(
            onDismissRequest = { confirmAccept = false },
            title = { Text("Mark as expected?") },
            text = { Text("Do this only if you made or approved this change. TileOps will treat the current state of " +
                "\"${a.key}\" on ${a.server} as normal (its new baseline) and stop alerting about it. " +
                "Any later change will alert again.") },
            confirmButton = { TextButton(onClick = { confirmAccept = false; act("Marked as expected") { api.acceptBaseline(a.id) } }) { Text("Mark as expected") } },
            dismissButton = { TextButton(onClick = { confirmAccept = false }) { Text("Cancel") } },
        )
    }
}

// ======================================================================== runbook approval
@Composable
fun RunScreen(api: TileOpsBackend, id: Long, onToast: (String) -> Unit, onOpenIncident: (Long) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(id, local) { api.run(id) }
    var pin by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }

    val pinSet by rememberLoad(id, local) { api.approvalPinSet() }
    var newPin by remember { mutableStateOf("") }
    var newPin2 by remember { mutableStateOf("") }
    LoadView(state, onRetry = { local++ }) { r: Run ->
        val ap = r.approval
        val needsPin = r.status == "awaiting_approval" && (pinSet as? Load.Ok<Boolean>)?.value == false
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp)) {
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Runbook: ${r.runbook} #${r.id}", fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                    Badge(r.status, statusColor(r.status), dark = false)
                }
                KV("Target", ap.target)
                KV("Action", ap.action)
                KV("Impact", ap.impact)
                KV("Done when", "GET ${ap.healthUrl} returns 200")
            }
            if (needsPin) {
                SectionCard {
                    Text("Create your approval PIN", fontWeight = FontWeight.Bold)
                    Text("Restarts need a PIN you choose (4–12 digits) plus your fingerprint or screen lock. " +
                        "You'll use this PIN for every restart from this phone.", color = Palette.muted, fontSize = 13.sp,
                        modifier = Modifier.padding(vertical = 6.dp))
                    OutlinedTextField(newPin, { newPin = it.filter(Char::isDigit).take(12) }, label = { Text("New PIN") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(newPin2, { newPin2 = it.filter(Char::isDigit).take(12) }, label = { Text("Repeat PIN") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
                    if (newPin2.isNotEmpty() && newPin != newPin2) Text("The PINs don't match.", color = Palette.medium, fontSize = 13.sp)
                    Button(enabled = newPin.length >= 4 && newPin == newPin2, modifier = Modifier.padding(top = 8.dp), onClick = {
                        scope.launch {
                            try { api.setApprovalPin(newPin); onToast("Approval PIN saved") } catch (e: Exception) { onToast(errorText(e)) }
                            newPin = ""; newPin2 = ""; local++
                        }
                    }) { Text("Save PIN") }
                }
            } else if (r.status == "awaiting_approval") {
                SectionCard {
                    Text("Approve this action", fontWeight = FontWeight.Bold)
                    Text("This restarts a live service. Enter the approval PIN; you'll then confirm with your fingerprint or screen lock.",
                        color = Palette.muted, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp))
                    OutlinedTextField(
                        value = pin, onValueChange = { pin = it.filter(Char::isLetterOrDigit).take(32) },
                        label = { Text("Approval PIN") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    note?.let { Text(it, color = Palette.medium, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp)) }
                    Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            enabled = pin.isNotEmpty() && !busy,
                            colors = ButtonDefaults.buttonColors(containerColor = Palette.critical, contentColor = Color(0xFF160307)),
                            onClick = {
                                val act = ctx.findFragmentActivity()
                                busy = true
                                scope.launch {
                                    val auth = if (act != null) confirmWithBiometric(act, "Approve ${ap.action}", ap.target) else AuthResult.UNAVAILABLE
                                    if (auth == AuthResult.FAILED) {
                                        note = "Confirmation cancelled."
                                        busy = false
                                        return@launch
                                    }
                                    if (auth == AuthResult.UNAVAILABLE) note = "No biometric or screen lock set up on this phone: approving with the PIN only."
                                    try {
                                        val res = api.approve(r.id, pin)
                                        onToast("Run ${res.status}")
                                        runCatching { StatusCache.save(ctx, api.status()) }
                                        StatusCache.refreshSurfaces(ctx)
                                    } catch (e: Exception) {
                                        onToast(errorText(e))
                                    }
                                    pin = ""
                                    busy = false
                                    local++
                                }
                            },
                        ) { Text(if (busy) "Running…" else "Approve & restart") }
                        OutlinedButton(enabled = !busy, onClick = {
                            scope.launch {
                                try { api.reject(r.id); onToast("Rejected") } catch (e: Exception) { onToast(errorText(e)) }
                                local++
                            }
                        }) { Text("Reject") }
                    }
                }
            }
            Text("Steps", fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
            r.steps.forEach { s ->
                SectionCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(s.name + if (s.requiresApproval) " (needs approval)" else "", modifier = Modifier.weight(1f))
                        Badge(s.status, statusColor(if (s.status == "ok") "ok" else s.status), dark = false)
                    }
                    s.output?.takeIf { it.isNotBlank() }?.let { Mono(it) }
                }
            }
            r.incidentId?.let { TextButton(onClick = { onOpenIncident(it) }) { Text("Incident timeline →") } }
            Spacer(Modifier.height(16.dp))
        }
    }
}

// ======================================================================== incidents + timeline
@Composable
fun IncidentsScreen(api: TileOpsBackend, refreshKey: Int, onOpen: (Long) -> Unit) {
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(refreshKey, local) { api.incidents() }
    LoadView(state, onRetry = { local++ }) { list ->
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            item { Spacer(Modifier.height(6.dp)) }
            if (list.isEmpty()) item { SectionCard { Text("No incidents yet.", color = Palette.muted) } }
            items(list, key = { it.id }) { i ->
                SectionCard(Modifier.clickable { onOpen(i.id) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(i.title, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Badge(i.status, Palette.muted, dark = false)
                    }
                    Text("${i.server} · updated ${ago(i.updatedAt)}", color = Palette.muted, fontSize = 13.sp)
                }
            }
            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

@Composable
fun IncidentScreen(api: TileOpsBackend, id: Long, onOpenAlert: (Long) -> Unit, onOpenRun: (Long) -> Unit) {
    var local by remember { mutableIntStateOf(0) }
    val state by rememberLoad(id, local) { api.incident(id) }
    LoadView(state, onRetry = { local++ }) { inc ->
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            item {
                SectionCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(inc.title, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        Badge(inc.status, Palette.muted, dark = false)
                    }
                    Text("${inc.server} · opened ${whenText(inc.createdAt)}", color = Palette.muted, fontSize = 13.sp)
                    inc.alertId?.let { TextButton(onClick = { onOpenAlert(it) }) { Text("View alert #$it →") } }
                }
                Text("Timeline", fontWeight = FontWeight.Bold, modifier = Modifier.padding(vertical = 8.dp))
            }
            items(inc.events, key = { it.id }) { e ->
                Row(Modifier.fillMaxWidth()) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(18.dp)) {
                        Spacer(Modifier.height(6.dp))
                        Dot(eventColor(e.kind))
                        Box(Modifier.width(2.dp).height(48.dp).background(Palette.card2))
                    }
                    Column(Modifier.padding(start = 8.dp, bottom = 8.dp).weight(1f)) {
                        Text(e.message, fontSize = 14.sp)
                        Text("${whenText(e.ts)} · ${e.kind}", color = Palette.muted, fontSize = 12.sp)
                        val runId = (e.data as? JsonObject)?.get("run_id")?.jsonPrimitive?.content?.toLongOrNull()
                        if (e.kind == "approval_requested" && runId != null) {
                            TextButton(onClick = { onOpenRun(runId) }) { Text("Open approval →") }
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

private fun eventColor(kind: String): Color = when {
    kind.contains("failed") || kind.contains("locked") || kind == "alert_raised" -> Palette.critical
    kind.contains("verified") || kind.endsWith("_ok") || kind == "baseline_accepted" -> Palette.ok
    kind.contains("approval") -> Palette.medium
    else -> Palette.accent
}

@Suppress("unused")
private fun Modifier.fullHeight() = this.fillMaxHeight()
