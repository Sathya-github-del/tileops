package dev.tileops.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.tileops.app.data.AccessTest
import dev.tileops.app.data.TileOpsBackend
import dev.tileops.app.data.CompanionAbout
import dev.tileops.app.data.HostKeyInfo
import dev.tileops.app.data.Server
import dev.tileops.app.data.ServerInput
import dev.tileops.app.work.StatusCache
import kotlinx.coroutines.launch

private val NAME_RE = Regex("^[A-Za-z0-9._-]{1,64}$")
private val SERVICE_RE = Regex("^[A-Za-z0-9@._-]{1,64}$")
private val USER_RE = Regex("^[a-z_][a-z0-9_-]{0,31}$")

private fun splitList(s: String) = s.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.distinct()

private fun copy(ctx: Context, label: String, text: String) {
    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(label, text))
}

private fun share(ctx: Context, title: String, text: String) {
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    ctx.startActivity(Intent.createChooser(send, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

// ======================================================================== add / edit
@Composable
fun ServerFormScreen(api: TileOpsBackend, editName: String?, onToast: (String) -> Unit, onDone: (String, Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var loaded by remember { mutableStateOf(editName == null) }
    var name by remember { mutableStateOf("") }
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("22") }
    var user by remember { mutableStateOf("tileops") }
    var roots by remember { mutableStateOf("/var/www") }
    var services by remember { mutableStateOf("") }
    val health = remember { mutableStateMapOf<String, String>() }
    var vpn by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(editName) {
        if (editName != null) {
            try {
                val s: Server = api.servers().first { it.name == editName }
                name = s.name; host = s.host; port = s.port.toString(); user = s.user
                roots = s.webRoots.joinToString(", "); services = s.services.joinToString(", ")
                health.clear(); health.putAll(s.healthUrls)
                vpn = s.vpnRequired
                loaded = true
            } catch (e: Exception) {
                error = errorText(e)
            }
        }
    }

    val svcList = splitList(services)
    val portInt = port.toIntOrNull()
    val problems = buildList {
        if (editName == null && !NAME_RE.matches(name)) add("Name: letters, digits, . _ - (max 64)")
        if (host.isBlank() || host.any { it.isWhitespace() }) add("Host: hostname or IP")
        if (portInt == null || portInt !in 1..65535) add("Port: 1-65535")
        if (!USER_RE.matches(user)) add("User: lowercase, e.g. tileops")
        if (splitList(roots).isEmpty() || splitList(roots).any { !it.startsWith("/") || ".." in it }) add("Web roots: absolute paths")
        svcList.filterNot { SERVICE_RE.matches(it) }.forEach { add("Service name not allowed: $it") }
        svcList.forEach { s -> health[s]?.takeIf { it.isNotBlank() && !it.matches(Regex("^https?://\\S+$")) }?.let { add("Health URL for $s must start with http(s)://") } }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp)) {
        Text(if (editName == null) "Add a server" else "Edit $editName", fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Text(
            "TileOps logs in over SSH with its own key as an unprivileged user and only runs fixed, read-only checks. " +
                "You'll get a setup command for the server on the next screen. No password is ever sent to TileOps.",
            color = Palette.muted, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp),
        )
        if (!loaded) { Text("Loading…", color = Palette.muted); return@Column }
        SectionCard {
            OutlinedTextField(name, { name = it.trim() }, label = { Text("Name (e.g. web1)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                enabled = editName == null, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(host, { host = it.trim() }, label = { Text("Host (domain or IP)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false), modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                OutlinedTextField(port, { port = it.filter(Char::isDigit).take(5) }, label = { Text("SSH port") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.weight(1f))
                OutlinedTextField(user, { user = it.trim() }, label = { Text("Login user") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false), modifier = Modifier.weight(1.4f))
            }
            Text("Keep 'tileops' unless your host forces a user. The setup creates it.", color = Palette.muted, fontSize = 12.sp)
        }
        SectionCard {
            Text("How to reach this server", fontWeight = FontWeight.Bold)
            if (api.isLocal) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text("Only reachable over a VPN")
                        Text("Turn on if you must connect a VPN (e.g. OpenVPN Connect) before you can reach this server.",
                            color = Palette.muted, fontSize = 12.sp)
                    }
                    Switch(checked = vpn, onCheckedChange = { vpn = it })
                }
                if (vpn) Text("TileOps then checks this server only while your VPN is connected, and skips it quietly " +
                    "otherwise (no false \"unreachable\" alarms). Connect the VPN in your VPN app; TileOps' connection " +
                    "goes through it automatically.", color = Palette.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
            } else {
                Text("Behind a VPN? Your companion's own device must be connected to that VPN, since the companion does the checking.",
                    color = Palette.muted, fontSize = 13.sp)
            }
        }
        SectionCard {
            Text("What to watch", fontWeight = FontWeight.Bold)
            OutlinedTextField(roots, { roots = it }, label = { Text("Web roots (comma separated)") },
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(services, { services = it }, label = { Text("Services you may restart (e.g. nginx)") },
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
            svcList.forEach { s ->
                OutlinedTextField(health[s] ?: "", { health[s] = it.trim() }, label = { Text("Health URL for $s (optional)") },
                    singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
            }
            Text("A restart only counts as done when the health URL returns HTTP 200.", color = Palette.muted, fontSize = 12.sp)
        }
        problems.forEach { Text("• $it", color = Palette.medium, fontSize = 13.sp) }
        error?.let { SectionCard { Text(it, color = Palette.critical) } }
        Button(enabled = problems.isEmpty() && !busy, modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp), onClick = {
            busy = true; error = null
            val input = ServerInput(
                name = if (editName == null) name else null, host = host, port = portInt ?: 22, user = user,
                webRoots = splitList(roots), services = svcList,
                healthUrls = svcList.mapNotNull { s -> health[s]?.takeIf { it.isNotBlank() }?.let { s to it } }.toMap(),
                vpnRequired = vpn && api.isLocal,
            )
            scope.launch {
                try {
                    if (editName == null) {
                        val r = api.addServer(input)
                        onDone(r.server.name, true)
                    } else {
                        val r = api.updateServer(editName, input)
                        onToast("Saved")
                        onDone(r.name, r.status == "needs_setup")
                    }
                } catch (e: Exception) {
                    error = errorText(e)
                }
                busy = false
            }
        }) { Text(if (busy) "Saving…" else if (editName == null) "Add & set up" else "Save") }
        Spacer(Modifier.height(16.dp))
    }
}

// ======================================================================== guided setup
@Composable
fun ServerSetupScreen(api: TileOpsBackend, name: String, onToast: (String) -> Unit, onFinished: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var reload by remember { mutableIntStateOf(0) }
    val state by rememberLoad(name, reload) { api.serverSetup(name) to api.servers().first { it.name == name } }
    var showScript by remember { mutableStateOf(false) }
    var hostKey by remember { mutableStateOf<HostKeyInfo?>(null) }
    var test by remember { mutableStateOf<AccessTest?>(null) }
    var busy by remember { mutableStateOf<String?>(null) }
    var note by remember { mutableStateOf<String?>(null) }

    fun step(label: String, block: suspend () -> Unit) {
        busy = label; note = null
        scope.launch {
            try { block() } catch (e: Exception) { note = errorText(e) }
            busy = null
        }
    }

    LoadView(state, onRetry = { reload++ }) { (setup, server) ->
        val trusted = server.hostKey != null
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp)) {
            Text("Set up ${server.name}", fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text("${server.user}@${server.host}:${server.port}", color = Palette.muted)
            if (server.vpnRequired) {
                val vpnOn = Vpn.isActive(ctx)
                SectionCard {
                    Text(if (vpnOn) "🔒 VPN connected" else "🔒 This server needs your VPN", fontWeight = FontWeight.Bold,
                        color = if (vpnOn) Palette.ok else Palette.medium)
                    Text(if (vpnOn) "Good: TileOps and your SSH app can reach ${server.host} now."
                        else "Connect your VPN first. Your SSH app needs it too, to run the setup command.",
                        fontSize = 13.sp, color = Palette.muted, modifier = Modifier.padding(vertical = 6.dp))
                    if (!vpnOn) ConnectVpnButton(onMessage = onToast)
                    TextButton(onClick = { reload++ }) { Text("I've connected: check again") }
                }
            }

            // ---- step 1
            SectionCard {
                StepTitle(1, "Run the setup command on the server", done = test?.ok == true || server.status == "ok")
                Text(
                    "Open any SSH app (Termux, JuiceSSH, ConnectBot…), log in to ${server.host} as root or a sudo user " +
                        "with your own password, paste this command and run it. It should end with TILEOPS SETUP OK.",
                    fontSize = 13.sp, color = Palette.muted,
                )
                Mono(setup.setupCommand.take(140) + if (setup.setupCommand.length > 140) " …" else "")
                @OptIn(ExperimentalLayoutApi::class)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { copy(ctx, "TileOps setup", setup.setupCommand); onToast("Setup command copied") }) { Text("Copy command") }
                    OutlinedButton(onClick = { share(ctx, "Send setup command to…", setup.setupCommand) }) { Text("Share") }
                    TextButton(onClick = { showScript = !showScript }) { Text(if (showScript) "Hide script" else "What does it do?") }
                }
                if (showScript) {
                    Text("The command is this script, base64-encoded so it pastes as one line:", color = Palette.muted, fontSize = 12.sp)
                    Mono(setup.setupScript)
                }
                Text("No root access (shared hosting)?", fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 8.dp))
                Text("Add this public key for user '${setup.user}' (e.g. your hosting panel's SSH keys page). " +
                    "TileOps will then run in degraded (read-only) mode.", fontSize = 13.sp, color = Palette.muted)
                Mono(setup.publicKey)
                TextButton(onClick = { copy(ctx, "TileOps public key", setup.publicKey); onToast("Public key copied") }) { Text("Copy public key") }
            }

            // ---- step 2
            SectionCard {
                StepTitle(2, "Confirm the server's identity", done = trusted)
                Text("The setup printed this server's host key fingerprints. Fetch the key TileOps sees and check that it " +
                    "matches the line with the same type. A mismatch means you're not talking to your server.",
                    fontSize = 13.sp, color = Palette.muted)
                OutlinedButton(enabled = busy == null, onClick = { step("hostkey") { hostKey = api.hostKey(name) } }) {
                    Text(if (busy == "hostkey") "Fetching…" else "Fetch host key")
                }
                val hk = hostKey
                if (hk != null) {
                    KV("Key type", hk.keyType.removePrefix("ssh-").uppercase())
                    KV("Fingerprint", hk.fingerprint)
                    when (hk.matchesPin) {
                        true -> Text("✓ Matches the trusted key", color = Palette.ok)
                        false -> Text("✗ DIFFERENT from the key you trusted before!", color = Palette.critical, fontWeight = FontWeight.Bold)
                        null -> Button(enabled = busy == null, onClick = {
                            step("trust") {
                                api.trustHostKey(name, hk.fingerprint)
                                hostKey = hk.copy(pinned = hk.fingerprint, matchesPin = true)
                                onToast("Host key trusted")
                                reload++
                            }
                        }) { Text("It matches: trust this key") }
                    }
                } else if (trusted) {
                    KV("Trusted key", server.hostKey, Palette.ok)
                }
            }

            // ---- step 3
            SectionCard {
                StepTitle(3, "Test the connection", done = test?.ok == true)
                OutlinedButton(enabled = busy == null && trusted, onClick = { step("test") { test = api.testServer(name) } }) {
                    Text(if (busy == "test") "Testing…" else "Test connection")
                }
                if (!trusted) Text("Trust the host key first.", color = Palette.muted, fontSize = 12.sp)
                test?.let { t ->
                    Text(t.message, color = if (!t.ok) Palette.critical else if (t.sudoOk == false) Palette.medium else Palette.ok,
                        modifier = Modifier.padding(top = 4.dp))
                    if (t.ok) KV("Logged in as", t.user ?: "")
                }
            }

            // ---- step 4
            SectionCard {
                StepTitle(4, "First scan (records the baseline)", done = false)
                Text("The first scan records what's normal on this server; later changes raise alerts.",
                    fontSize = 13.sp, color = Palette.muted)
                Button(enabled = busy == null && test?.ok == true, onClick = {
                    step("scan") {
                        val r = api.scan(name)
                        if (r.ok) {
                            onToast("Baseline recorded for $name")
                            runCatching { StatusCache.save(ctx, api.status()) }
                            StatusCache.refreshSurfaces(ctx)
                            onFinished()
                        } else note = "Scan failed: ${r.error}"
                    }
                }) { Text(if (busy == "scan") "Scanning…" else "Run first scan") }
            }
            note?.let { SectionCard { Text(it, color = Palette.critical) } }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun StepTitle(n: Int, title: String, done: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 4.dp)) {
        Badge(if (done) "✓" else "$n", if (done) Palette.ok else Palette.accent)
        Text(title, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 10.dp))
    }
}

// ======================================================================== about
@Composable
fun AboutScreen(api: TileOpsBackend, onLicenses: () -> Unit = {}) {
    val ctx = LocalContext.current
    val appVersion = remember {
        runCatching { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName }.getOrNull() ?: "?"
    }
    val companion by rememberLoad(Unit) { api.about() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("TileOps", fontSize = 28.sp, fontWeight = FontWeight.Bold)
        Text("Agentless server security + ops monitor", color = Palette.muted)
        SectionCard {
            Text("Author", color = Palette.muted, fontSize = 12.sp)
            Text("Sathya Prakash J", fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text("Creator & lead developer", color = Palette.fg)
            Text("Concept, architecture and product direction of TileOps.", color = Palette.muted, fontSize = 13.sp,
                modifier = Modifier.padding(top = 4.dp))
        }
        SectionCard {
            KV("App version", appVersion)
            val c = (companion as? Load.Ok<CompanionAbout>)?.value
            if (api.isLocal) KV("Mode", "Phone only: this phone checks your servers")
            else KV("Companion", if (c != null && c.version.isNotEmpty()) "${c.name} ${c.version} · ${api.label}" else api.label)
            KV("Built with", "Kotlin · Jetpack Compose · Material 3 · FastAPI · asyncssh")
            KV("Source code", "github.com/Sathya-github-del/tileops (GPL-3.0)")
        }
        SectionCard {
            Text("How it works", fontWeight = FontWeight.Bold)
            Text("TileOps (on this phone or on your always-on companion) logs in to each server over SSH with its own key as an unprivileged user, runs a fixed " +
                "set of read-only checks, and alerts you when something changes: new users, SSH keys, " +
                "cron jobs, listening ports, CPU-hungry unknown processes, web files and systemd units. Restarts need " +
                "your PIN and only count as done when the health check passes. No accounts, no cloud.",
                fontSize = 13.sp, color = Palette.muted, modifier = Modifier.padding(top = 4.dp))
        }
        TextButton(onClick = onLicenses, modifier = Modifier.padding(top = 4.dp)) { Text("Open-source licences") }
        Text("© 2026 Sathya Prakash J. TileOps is free software under the GNU GPL v3 (or later).", color = Palette.muted, fontSize = 12.sp,
            modifier = Modifier.padding(top = 4.dp))
        Spacer(Modifier.height(16.dp))
    }
}

@Suppress("unused")
private val unusedColor = Color.Unspecified


// ======================================================================== licences
@Composable
fun LicensesScreen() {
    val ctx = LocalContext.current
    val text = remember {
        runCatching { ctx.assets.open("licenses.txt").bufferedReader().use { it.readText() } }.getOrDefault("Licences unavailable.")
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("Open-source licences", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text(text, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 11.sp,
            color = Palette.fg, modifier = Modifier.padding(top = 10.dp))
        Spacer(Modifier.height(16.dp))
    }
}
