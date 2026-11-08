package dev.tileops.app.ui

import android.content.Context
import android.content.ContextWrapper
import android.text.format.DateUtils
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.tileops.app.data.ApiException
import kotlinx.coroutines.CancellationException
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

// ---------------------------------------------------------------- theme
object Palette {
    val bg = Color(0xFF0F1115)
    val card = Color(0xFF181B22)
    val card2 = Color(0xFF1F232C)
    val fg = Color(0xFFE6E8EE)
    val muted = Color(0xFF9AA3B2)
    val accent = Color(0xFF6EA8FE)
    val ok = Color(0xFF3ECF8E)
    val critical = Color(0xFFFF5C6C)
    val high = Color(0xFFFF9F43)
    val medium = Color(0xFFF7D154)
    val low = Color(0xFF7BD88F)
    val info = Color(0xFF8AB4F8)
}

fun severityColor(sev: String): Color = when (sev) {
    "critical" -> Palette.critical
    "high" -> Palette.high
    "medium" -> Palette.medium
    "low" -> Palette.low
    else -> Palette.info
}

/** Plain-language names for tripwire ids (never show internal ids to users). */
fun tripwireName(id: String): String = when (id) {
    "new_user" -> "User accounts"
    "ssh_key" -> "SSH login keys"
    "cron" -> "Scheduled tasks (cron)"
    "listening_port" -> "Open network ports"
    "cpu_process" -> "Unknown CPU-heavy program"
    "webroot_file" -> "Website files"
    "systemd_unit" -> "System services"
    "host_key" -> "Server identity (host key)"
    else -> id.replace('_', ' ')
}

fun statusColor(status: String): Color = when (status) {
    "ok", "verified" -> Palette.ok
    "alert", "unreachable", "failed", "locked" -> Palette.critical
    "awaiting_approval", "running", "needs_vpn", "needs_setup" -> Palette.medium
    else -> Palette.muted
}

@Composable
fun TileOpsTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Palette.accent, onPrimary = Color(0xFF0B1020),
            background = Palette.bg, onBackground = Palette.fg,
            surface = Palette.bg, onSurface = Palette.fg,
            surfaceVariant = Palette.card2, onSurfaceVariant = Palette.muted,
            surfaceContainer = Palette.card, surfaceContainerHigh = Palette.card2,
            error = Palette.critical,
        ),
        content = content,
    )
}

// ---------------------------------------------------------------- loading
sealed interface Load<out T> {
    data object Loading : Load<Nothing>
    data class Ok<T>(val value: T) : Load<T>
    data class Err(val message: String, val unauthorized: Boolean = false) : Load<Nothing>
}

fun errorText(e: Throwable): String = when (e) {
    is ApiException -> if (e.code == 401) "Not authorised: the token was rejected. Re-pair the app." else (e.message ?: "HTTP ${e.code}")
    is java.net.ConnectException, is java.net.SocketTimeoutException, is java.net.NoRouteToHostException ->
        "Can't reach the companion (${e.javaClass.simpleName}). Is the Lava on and on Wi-Fi?"
    else -> e.message ?: e.javaClass.simpleName
}

@Composable
fun <T> rememberLoad(vararg keys: Any?, block: suspend () -> T): State<Load<T>> =
    produceState<Load<T>>(Load.Loading, *keys) {
        value = try {
            Load.Ok(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Load.Err(errorText(e), e is ApiException && e.code == 401)
        }
    }

@Composable
fun <T> LoadView(state: Load<T>, onRetry: () -> Unit, content: @Composable (T) -> Unit) {
    when (state) {
        is Load.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        is Load.Err -> Column(Modifier.padding(16.dp)) {
            SectionCard { Text(state.message, color = Palette.critical) }
            OutlinedButton(onClick = onRetry, modifier = Modifier.padding(top = 8.dp)) { Text("Retry") }
        }
        is Load.Ok -> content(state.value)
    }
}

// ---------------------------------------------------------------- small widgets
@Composable
fun SectionCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth().padding(vertical = 5.dp),
        colors = CardDefaults.cardColors(containerColor = Palette.card),
        shape = RoundedCornerShape(12.dp),
    ) { Column(Modifier.padding(14.dp)) { content() } }
}

@Composable
fun Badge(text: String, color: Color, dark: Boolean = true) {
    Text(
        text.replace('_', ' ').uppercase(),
        color = if (dark) Color(0xFF111111) else color,
        fontSize = 11.sp, fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(6.dp))
            .background(if (dark) color else Palette.card2).padding(horizontal = 7.dp, vertical = 2.dp),
    )
}

@Composable
fun Dot(color: Color) {
    Box(Modifier.size(10.dp).clip(CircleShape).background(color))
}

@Composable
fun Mono(text: String) {
    Box(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(8.dp))
            .background(Color(0xFF0A0C10)).horizontalScroll(rememberScrollState()).padding(10.dp)
    ) { Text(text, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Palette.fg) }
}

@Composable
fun KV(k: String, v: String, color: Color = Palette.fg) {
    Column(Modifier.padding(vertical = 3.dp)) {
        Text(k, color = Palette.muted, fontSize = 12.sp)
        Text(v, color = color, fontSize = 14.sp)
    }
}

fun ago(ts: Double?): String =
    if (ts == null || ts <= 0) "never"
    else DateUtils.getRelativeTimeSpanString((ts * 1000).toLong(), System.currentTimeMillis(), DateUtils.SECOND_IN_MILLIS).toString()

fun whenText(ts: Double?): String =
    if (ts == null || ts <= 0) "-" else java.text.DateFormat.getDateTimeInstance().format(java.util.Date((ts * 1000).toLong()))

// ---------------------------------------------------------------- biometric
tailrec fun Context.findFragmentActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
}

/** Result of asking for biometric / device-credential confirmation. */
enum class AuthResult { OK, FAILED, UNAVAILABLE }

suspend fun confirmWithBiometric(activity: FragmentActivity, title: String, subtitle: String): AuthResult {
    val authenticators = BIOMETRIC_STRONG or DEVICE_CREDENTIAL
    if (BiometricManager.from(activity).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
        return AuthResult.UNAVAILABLE
    }
    return suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(AuthResult.OK)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (cont.isActive) cont.resume(AuthResult.FAILED)
                }
            })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title).setSubtitle(subtitle)
                .setAllowedAuthenticators(authenticators)
                .setConfirmationRequired(true)
                .build()
        )
    }
}
