package dev.tileops.app.ui

import android.Manifest
import android.content.ClipboardManager
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.TextButton
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.withStyle
import dev.tileops.app.data.ApiException
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import dev.tileops.app.data.ApiClient
import dev.tileops.app.data.Pairing
import dev.tileops.app.data.PairingUri
import kotlinx.coroutines.launch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

// ======================================================================== onboarding / pairing
/** First run (or after unpairing): explain TileOps, then connect to the user's companion. */
@Composable
fun PairScreen(prefill: Pairing?, onPaired: suspend (Pairing) -> Unit, onUsePhone: () -> Unit) {
    var page by rememberSaveable { mutableStateOf(if (prefill != null) "connect" else "welcome") }
    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
        if (page == "welcome") WelcomePage(onConnect = { page = "connect" }, onUsePhone = onUsePhone)
        else ConnectPage(prefill, onBack = { page = "welcome" }, onPaired = onPaired)
    }
}

@Composable
private fun WelcomePage(onConnect: () -> Unit, onUsePhone: () -> Unit) {
    var noCompanion by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("TileOps", fontSize = 30.sp, fontWeight = FontWeight.Bold)
        Text("Know the moment something changes on your servers.", color = Palette.muted, fontSize = 16.sp)

        SectionCard {
            Feature("Alerts", "when a new user, SSH key, open port, scheduled task, web file or system service appears on a server, or an unknown program eats the CPU.")
            Feature("Evidence, not guesses", "see exactly what changed and when, then mark it as expected or act on it.")
            Feature("Safe fixes", "restart a service only after your PIN, and TileOps checks the site really came back.")
            Feature("Yours only", "no account, no cloud. TileOps logs in with its own limited user and only reads.")
        }

        Text("How do you want to run TileOps?", fontWeight = FontWeight.Bold, fontSize = 18.sp,
            modifier = Modifier.padding(top = 14.dp, bottom = 2.dp))
        Text("You can switch later from the ⋮ menu.", color = Palette.muted, fontSize = 13.sp)

        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("📱", fontSize = 24.sp, modifier = Modifier.padding(end = 10.dp))
                Column {
                    Text("Just this phone", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    Text("Easiest · nothing else to install", color = Palette.ok, fontSize = 13.sp)
                }
            }
            Text("This app logs in to your servers itself. It checks when you open TileOps and in the background " +
                "when Android allows (about every 15 minutes, less often while the phone sleeps), so an alert can " +
                "arrive late. Your server keys stay encrypted on this phone.",
                fontSize = 14.sp, color = Palette.muted, modifier = Modifier.padding(top = 6.dp))
            Button(onClick = onUsePhone, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) { Text("Use this phone") }
        }

        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("🖥", fontSize = 24.sp, modifier = Modifier.padding(end = 10.dp))
                Column {
                    Text("Always-on companion", fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    Text("24/7 · checks every 5 minutes", color = Palette.accent, fontSize = 13.sp)
                }
            }
            Text("A small program on an always-on device (a spare phone, a Raspberry Pi, a home server or a small VPS) " +
                "checks your servers around the clock and alerts you even when this phone is off or out of signal. " +
                "Several phones can share it.",
                fontSize = 14.sp, color = Palette.muted, modifier = Modifier.padding(top = 6.dp))
            OutlinedButton(onClick = onConnect, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) { Text("Connect a companion") }
            TextButton(onClick = { noCompanion = !noCompanion }) { Text("How do I get a companion?") }
            if (noCompanion) {
                Step(1, "Pick an always-on device that can reach your servers: a spare phone, a Raspberry Pi, a home server or a small VPS.")
                Step(2, "Install the TileOps companion on it: follow the guide at github.com/Sathya-github-del/tileops (docs/companion-setup.md), or ask whoever set up TileOps for you.")
                Step(3, "When it starts, it shows a QR code, a pairing link and a pairing code.")
                Step(4, "Come back here, tap \"Connect a companion\" and use any one of them.")
            }
        }
        Text("Not sure? Start with \"Just this phone\". You can add a companion later.",
            color = Palette.muted, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun Feature(title: String, text: String) {
    Row(Modifier.padding(vertical = 5.dp)) {
        Text("✓", color = Palette.ok, fontWeight = FontWeight.Bold, modifier = Modifier.padding(end = 10.dp))
        Text(buildAnnotatedString {
            withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(title) }
            append(": $text")
        }, fontSize = 14.sp)
    }
}



@Composable
private fun Step(n: Int, text: String) {
    Row(Modifier.padding(top = 6.dp)) {
        Badge("$n", Palette.accent)
        Text(text, fontSize = 14.sp, modifier = Modifier.padding(start = 10.dp))
    }
}

/** Adds the default companion port when the user typed just an IP or host name. */
internal fun friendlyAddress(raw: String): String {
    val t = raw.trim()
    // Companions serve HTTPS by default, so a bare address means https://
    val u = ApiClient.normalizeUrl(if (t.startsWith("http://") || t.startsWith("https://")) t else "https://$t")
    val authority = u.substringAfter("://").substringBefore('/')
    val hasPort = if (authority.startsWith("[")) authority.contains("]:") else authority.contains(':')
    return if (hasPort) u else u.replaceFirst(authority, "$authority:8800")
}

private fun pairingError(e: Throwable, address: String): String = when {
    e is javax.net.ssl.SSLHandshakeException || e.cause is java.security.cert.CertificateException ->
        "The companion's security certificate doesn't match the one in your pairing link or the one you confirmed. " +
            "If the companion was reinstalled or reset, pair again with its new QR code or link."
    e is javax.net.ssl.SSLException && address.startsWith("https://") ->
        "$address doesn't answer over HTTPS. If your companion runs without TLS (tls: false), type http:// in front of the address."
    e is ApiException && e.code == 401 ->
        "Your companion answered, but the pairing code is wrong. Copy it again from the companion's screen (or run \"python -m companion pair\" on it)."
    e is ApiException && e.code == 404 -> "Something answered at $address, but it isn't a TileOps companion. Check the address and port."
    e is ApiException -> "The companion answered with an error (${e.message}). Try again in a moment."
    e is java.net.UnknownHostException -> "Can't find \"${address.substringAfter("://").substringBefore(':')}\". Check the address for typos."
    e is java.net.ConnectException || e is java.net.NoRouteToHostException || e is java.net.SocketTimeoutException ->
        "Can't reach $address. Check that this phone is on the same network (Wi-Fi) as the companion, that the companion is running, and that the address and port are right."
    e is kotlinx.serialization.SerializationException -> "Something answered at $address, but it isn't a TileOps companion."
    else -> "Couldn't connect: ${e.message ?: e.javaClass.simpleName}"
}

@Composable
private fun ConnectPage(prefill: Pairing?, onBack: () -> Unit, onPaired: suspend (Pairing) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var manual by rememberSaveable { mutableStateOf(false) }
    var address by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var showCode by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var source by remember { mutableStateOf("") } // which option the status/error belongs to
    var linkFound by remember { mutableStateOf(prefill) }
    var confirmCert by remember { mutableStateOf<Pairing?>(null) }

    val camPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) scanning = true
        else { source = "qr"; error = "TileOps needs the camera only to scan the QR code. You can paste the pairing link or enter it yourself instead." }
    }

    /** "Connecting…" / error shown inside the card the user just used, so it's always in view. */
    @Composable
    fun Status(forSource: String) {
        if (source != forSource) return
        busy?.let {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 10.dp)) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                Text("Connecting to $it…", modifier = Modifier.padding(start = 10.dp))
            }
        }
        error?.let { Text(it, color = Palette.critical, modifier = Modifier.padding(top = 10.dp)) }
    }

    fun connect(p: Pairing, from: String) {
        val addr = friendlyAddress(p.baseUrl)
        source = from
        busy = addr
        error = null
        scope.launch {
            try {
                ApiClient(addr, p.token, p.certPin).status() // proves the address, certificate and code all work
                onPaired(Pairing(addr, p.token, p.certPin))
            } catch (e: Exception) {
                error = pairingError(e, addr)
            } finally {
                busy = null
            }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        TextButton(onClick = onBack, modifier = Modifier.padding(bottom = 4.dp)) { Text("← Back") }
        Text("Connect to your companion", fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text(
            "When your TileOps companion starts, it shows a QR code, a pairing link and a pairing code. Use whichever is easiest.",
            color = Palette.muted, modifier = Modifier.padding(vertical = 6.dp),
        )

        linkFound?.let { p ->
            SectionCard {
                Text("Pairing link received", fontWeight = FontWeight.Bold)
                Text("Connect this app to the companion at ${friendlyAddress(p.baseUrl)}? Only continue if you trust this link.",
                    fontSize = 14.sp, modifier = Modifier.padding(vertical = 6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = busy == null, onClick = { connect(p, "link") }) { Text("Connect") }
                    TextButton(onClick = { linkFound = null }) { Text("Not now") }
                }
                Status("link")
            }
        }


        // ---- option 1: QR
        SectionCard {
            OptionTitle(1, "Scan QR code")
            Text("Point the camera at the QR code on the companion's screen.", color = Palette.muted, fontSize = 14.sp)
            if (scanning) {
                QrScanner(
                    modifier = Modifier.fillMaxWidth().aspectRatio(1f).padding(top = 8.dp),
                    onCode = { raw ->
                        val p = PairingUri.extract(raw)
                        if (p != null) { scanning = false; connect(p, "qr"); true }
                        else { source = "qr"; error = "That QR code isn't a TileOps pairing code."; false }
                    },
                )
                TextButton(onClick = { scanning = false }) { Text("Stop scanning") }
            } else {
                Button(enabled = busy == null, modifier = Modifier.padding(top = 8.dp), onClick = {
                    error = null; source = "qr"
                    if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) scanning = true
                    else camPermission.launch(Manifest.permission.CAMERA)
                }) { Text("Scan QR code") }
            }
            Status("qr")
        }

        // ---- option 2: paste link
        SectionCard {
            OptionTitle(2, "Paste pairing link")
            Text("Best when the companion's screen is on this same phone (for example in an SSH app). " +
                "Copy the line that starts with tileops://pair, then tap Paste.", color = Palette.muted, fontSize = 14.sp)
            OutlinedButton(enabled = busy == null, modifier = Modifier.padding(top = 8.dp), onClick = {
                error = null; source = "paste"
                val clip = ctx.getSystemService(ClipboardManager::class.java).primaryClip
                val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
                val p = PairingUri.extract(text)
                if (p != null) connect(p, "paste")
                else error = "There's no pairing link in your clipboard. Copy the whole line that starts with tileops://pair and tap Paste again."
            }) { Text("Paste pairing link") }
            Status("paste")
        }

        // ---- option 3: manual
        SectionCard {
            OptionTitle(3, "Enter it myself")
            if (!manual) {
                Text("Type the Address and Pairing code shown by the companion.", color = Palette.muted, fontSize = 14.sp)
                TextButton(onClick = { manual = true }) { Text("Enter address and pairing code") }
            } else {
                OutlinedTextField(
                    value = address, onValueChange = { address = it.trim() }, singleLine = true,
                    label = { Text("Address") }, placeholder = { Text("https://192.168.1.20:8800") },
                    supportingText = { Text("The \"Address\" line, e.g. https://192.168.1.20:8800") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                )
                OutlinedTextField(
                    value = code, onValueChange = { code = it.trim() }, singleLine = true,
                    label = { Text("Pairing code") },
                    supportingText = { Text("The \"Pairing code\" line (a long code of letters and numbers)") },
                    visualTransformation = if (showCode) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = { TextButton(onClick = { showCode = !showCode }) { Text(if (showCode) "Hide" else "Show") } },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                )
                val addrOk = address.isNotBlank() && PairingUri.validUrl(friendlyAddress(address))
                Button(
                    enabled = busy == null && addrOk && code.length >= 16,
                    onClick = {
                        val addr = friendlyAddress(address)
                        if (!addr.startsWith("https://")) connect(Pairing(addr, code), "manual")
                        else {
                            // typed by hand: show the certificate's fingerprint and let the user compare it first
                            source = "manual"; busy = addr; error = null; confirmCert = null
                            scope.launch {
                                try { confirmCert = Pairing(addr, code, ApiClient.fetchCertPin(addr)) }
                                catch (e: Exception) { error = pairingError(e, addr) }
                                finally { busy = null }
                            }
                        }
                    },
                    modifier = Modifier.padding(top = 6.dp),
                ) { Text("Connect") }
                if (address.isNotBlank() && !addrOk) Text("That address doesn't look right. It should look like https://192.168.1.20:8800",
                    color = Palette.medium, fontSize = 13.sp)
                confirmCert?.let { pc ->
                    Text("Check the companion's certificate", fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp))
                    Text("Compare this with the \"Certificate\" line your companion printed. Only continue if they match: " +
                        "this is how TileOps knows it's talking to your companion and not to someone in between.",
                        color = Palette.muted, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp))
                    Mono(ApiClient.humanPin(pc.certPin!!).chunked(24).joinToString("\n"))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(enabled = busy == null, onClick = { confirmCert = null; connect(pc, "manual") }) { Text("It matches: connect") }
                        TextButton(onClick = { confirmCert = null }) { Text("Cancel") }
                    }
                }
                Status("manual")
            }
        }

        Text("Your pairing code is stored encrypted on this phone only. Anyone with it can use your companion, so keep it private.",
            color = Palette.muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun OptionTitle(n: Int, title: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 4.dp)) {
        Badge("$n", Palette.accent)
        Text(title, fontWeight = FontWeight.Bold, fontSize = 16.sp, modifier = Modifier.padding(start = 10.dp))
    }
}

/** CameraX preview + ML Kit QR detection. [onCode] returns true to stop scanning. */
@androidx.annotation.OptIn(ExperimentalGetImage::class)
@Composable
fun QrScanner(modifier: Modifier, onCode: (String) -> Boolean) {
    val ctx = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val done = remember { AtomicBoolean(false) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember {
        BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
    }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    DisposableEffect(Unit) {
        onDispose {
            provider?.unbindAll()
            scanner.close()
            executor.shutdown()
        }
    }
    AndroidView(modifier = modifier, factory = { c ->
        val view = PreviewView(c)
        val future = ProcessCameraProvider.getInstance(c)
        future.addListener({
            val p = future.get()
            provider = p
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
            val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
            analysis.setAnalyzer(executor) { proxy ->
                val media = proxy.image
                if (media == null || done.get()) {
                    proxy.close()
                    return@setAnalyzer
                }
                scanner.process(InputImage.fromMediaImage(media, proxy.imageInfo.rotationDegrees))
                    .addOnSuccessListener { codes ->
                        val raw = codes.firstNotNullOfOrNull { it.rawValue }
                        if (raw != null && done.compareAndSet(false, true)) {
                            if (!onCode(raw)) done.set(false)
                        }
                    }
                    .addOnCompleteListener { proxy.close() }
            }
            runCatching {
                p.unbindAll()
                p.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }
        }, ContextCompat.getMainExecutor(c))
        view
    })
}
