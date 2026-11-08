package dev.tileops.app.ui

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch

/**
 * TileOps doesn't run a VPN itself: the user's VPN app (e.g. OpenVPN Connect) connects the phone
 * system-wide and TileOps' SSH then goes through it. This helper detects that and opens the app.
 */
object Vpn {
    /** Known VPN apps, in order of preference. */
    val APPS = listOf(
        "net.openvpn.openvpn" to "OpenVPN Connect",
        "de.blinkt.openvpn" to "OpenVPN for Android",
    )

    fun isActive(ctx: Context): Boolean {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return false
        val n = cm.activeNetwork ?: return false
        return cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    fun installedApp(ctx: Context): Pair<String, String>? =
        APPS.firstOrNull { (pkg, _) -> ctx.packageManager.getLaunchIntentForPackage(pkg) != null }

    /** Opens the VPN app (or Android's VPN settings). Returns what was opened, for messages. */
    fun open(ctx: Context): String {
        val app = installedApp(ctx)
        val intent = app?.let { ctx.packageManager.getLaunchIntentForPackage(it.first) }
            ?: Intent(Settings.ACTION_VPN_SETTINGS)
        ctx.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return app?.second ?: "VPN settings"
    }
}

/**
 * "Connect VPN": asks for the phone owner's PIN/pattern/fingerprint, then opens the VPN app.
 * If the phone has no screen lock at all, it says so and opens the app anyway.
 */
@Composable
fun ConnectVpnButton(primary: Boolean = true, onMessage: (String) -> Unit = {}) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val app = remember { Vpn.installedApp(ctx) }
    val label = "Connect VPN" + (app?.let { " (${it.second})" } ?: "")
    val onClick: () -> Unit = {
        busy = true
        scope.launch {
            val act = ctx.findFragmentActivity()
            val auth = if (act != null) confirmWithBiometric(act, "Connect VPN", "Confirm it's you to open ${app?.second ?: "your VPN app"}")
            else AuthResult.UNAVAILABLE
            when (auth) {
                AuthResult.FAILED -> onMessage("VPN not opened: confirmation cancelled")
                AuthResult.UNAVAILABLE -> {
                    onMessage("This phone has no screen lock, so TileOps can't confirm it's you. Set one in Android settings to protect this.")
                    Vpn.open(ctx)
                }
                AuthResult.OK -> {
                    val opened = Vpn.open(ctx)
                    onMessage("Connect in $opened, then come back to TileOps")
                }
            }
            busy = false
        }
    }
    if (primary) Button(enabled = !busy, onClick = onClick) { Text(label) }
    else OutlinedButton(enabled = !busy, onClick = onClick) { Text(label) }
    if (app == null) Text("No OpenVPN app found: this opens Android's VPN settings. Install OpenVPN Connect from the Play Store to use .ovpn profiles.",
        color = Palette.muted, fontSize = androidx.compose.ui.unit.TextUnit(12f, androidx.compose.ui.unit.TextUnitType.Sp),
        modifier = Modifier)
}
