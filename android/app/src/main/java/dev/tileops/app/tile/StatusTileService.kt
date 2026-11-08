package dev.tileops.app.tile

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.tileops.app.MainActivity
import dev.tileops.app.R
import dev.tileops.app.backend
import dev.tileops.app.data.OverallStatus
import dev.tileops.app.work.StatusCache
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Quick Settings tile "TileOps". Overall status: green check = all OK, red warning = alerts or a
 * server unreachable (Android tints tile icons itself, so the state is shown by icon + subtitle).
 * Tap = scan all servers now.
 */
class StatusTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var scanning = false

    override fun onStartListening() {
        super.onStartListening()
        StatusCache.load(this)?.let { render(it.first) }
        scope.launch { refresh() }
    }

    override fun onClick() {
        super.onClick()
        if (scanning) return
        scope.launch {
            val api = backend()
            if (api == null) {
                openApp()
                return@launch
            }
            scanning = true
            update(Tile.STATE_ACTIVE, R.drawable.ic_tile_unknown, "Scanning…")
            runCatching { api.scanAll() }
            scanning = false
            refresh()
        }
    }

    private suspend fun refresh() {
        val api = backend()
        if (api == null) {
            update(Tile.STATE_INACTIVE, R.drawable.ic_tile_unknown, "Not paired")
            return
        }
        try {
            val s = api.status()
            StatusCache.save(this, s)
            render(s)
        } catch (e: Exception) {
            update(Tile.STATE_INACTIVE, R.drawable.ic_tile_unknown, "Companion offline")
        }
        StatusCache.refreshSurfaces(this)
    }

    private fun render(s: OverallStatus) {
        if (s.ok) update(Tile.STATE_ACTIVE, R.drawable.ic_tile_ok, "All OK")
        else {
            val down = s.servers.count { it.status == "unreachable" }
            val sub = when {
                s.openAlerts > 0 -> "${s.openAlerts} alert${if (s.openAlerts == 1) "" else "s"}"
                down > 0 -> "$down unreachable"
                else -> "Check status"
            }
            update(Tile.STATE_ACTIVE, R.drawable.ic_tile_alert, sub)
        }
    }

    private fun update(state: Int, icon: Int, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = state
        tile.icon = Icon.createWithResource(this, icon)
        tile.label = getString(R.string.tile_label)
        tile.subtitle = subtitle
        tile.contentDescription = "TileOps: $subtitle"
        tile.updateTile()
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            // Android 13: the PendingIntent overload only exists from Android 14 (API 34)
            @Suppress("DEPRECATION")
            @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
            startActivityAndCollapse(intent)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
