package dev.tileops.app

import android.app.Application
import android.content.Context
import androidx.datastore.preferences.preferencesDataStore
import dev.tileops.app.core.LocalEngine
import dev.tileops.app.core.LocalStore
import dev.tileops.app.core.SetupScript
import dev.tileops.app.data.ApiClient
import dev.tileops.app.data.KeystoreTokenCipher
import dev.tileops.app.data.TileOpsBackend
import dev.tileops.app.data.TokenStore
import dev.tileops.app.work.Notifications
import dev.tileops.app.work.PollWorker
import kotlinx.coroutines.flow.first
import java.io.File

private val Context.pairingStore by preferencesDataStore(name = "pairing")

class TileOpsApp : Application() {
    lateinit var tokens: TokenStore
        private set

    /** Phone-only mode engine: state encrypted with its own Keystore key in app-private storage. */
    val localEngine: LocalEngine by lazy {
        val version = runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull() ?: ""
        LocalEngine(
            store = LocalStore(File(filesDir, "local"), KeystoreTokenCipher("tileops_local_key")),
            setup = SetupScript(
                assets.open("setup.sh.tmpl").bufferedReader().use { it.readText() },
                assets.open("tileops-read").bufferedReader().use { it.readText() },
            ),
            appVersion = version,
            onNewAlert = { Notifications.alert(this, it, primary = true) },
            vpnActive = { dev.tileops.app.ui.Vpn.isActive(this) },
        )
    }

    override fun onCreate() {
        super.onCreate()
        tokens = TokenStore(pairingStore, KeystoreTokenCipher())
        Notifications.createChannels(this)
        PollWorker.schedule(this)
    }
}

val Context.tileOps: TileOpsApp get() = applicationContext as TileOpsApp

/** The backend for the current mode, or null when nothing is set up yet. */
suspend fun Context.backend(): TileOpsBackend? {
    val app = tileOps
    return when (app.tokens.mode.first()) {
        "local" -> app.localEngine
        else -> app.tokens.get()?.let { ApiClient(it.baseUrl, it.token, it.certPin) }
    }
}
