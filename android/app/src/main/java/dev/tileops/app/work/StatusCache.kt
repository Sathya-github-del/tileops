package dev.tileops.app.work

import android.content.ComponentName
import android.content.Context
import android.service.quicksettings.TileService
import androidx.glance.appwidget.updateAll
import dev.tileops.app.data.ApiClient
import dev.tileops.app.data.OverallStatus
import dev.tileops.app.tile.StatusTileService
import dev.tileops.app.widget.StatusWidget

/** Last known overall status (no secrets) so the tile/widget can render instantly or offline. */
object StatusCache {
    private const val PREFS = "status_cache"

    fun save(ctx: Context, s: OverallStatus) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("json", ApiClient.json.encodeToString(OverallStatus.serializer(), s))
            .putLong("at", System.currentTimeMillis())
            .apply()
    }

    fun load(ctx: Context): Pair<OverallStatus, Long>? {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val raw = p.getString("json", null) ?: return null
        return runCatching { ApiClient.json.decodeFromString(OverallStatus.serializer(), raw) to p.getLong("at", 0) }.getOrNull()
    }

    fun clear(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()

    /** Ask the QS tile and the home-screen widget to redraw. */
    suspend fun refreshSurfaces(ctx: Context) {
        runCatching { TileService.requestListeningState(ctx, ComponentName(ctx, StatusTileService::class.java)) }
        runCatching { StatusWidget().updateAll(ctx) }
    }
}
