package dev.tileops.app.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.tileops.app.backend
import dev.tileops.app.data.ApiException
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Every ~15 min (Android decides; longer while the phone sleeps):
 *  - phone-only mode: scan all servers on the phone;
 *  - companion mode: backup to ntfy, fetch status + open alerts and notify new ones.
 * Then refresh the tile/widget.
 */
class PollWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val api = ctx.backend() ?: return Result.success()
        return try {
            if (api.isLocal) {
                // phone-only mode: this IS the scan; new alerts notify via the engine's callback
                api.scanAll()
                StatusCache.save(ctx, api.status())
                StatusCache.refreshSurfaces(ctx)
                return Result.success()
            }
            StatusCache.save(ctx, api.status())
            val open = api.alerts("open")
            val prefs = ctx.getSharedPreferences("poll", Context.MODE_PRIVATE)
            val firstRun = !prefs.contains("seen")
            val seen = prefs.getStringSet("seen", emptySet()).orEmpty()
            if (!firstRun) open.filter { it.id.toString() !in seen }.forEach { Notifications.alert(ctx, it) }
            val keep = (seen + open.map { it.id.toString() }).sortedBy { it.toLongOrNull() ?: 0 }.takeLast(500).toSet()
            prefs.edit().putStringSet("seen", keep).apply()
            StatusCache.refreshSurfaces(ctx)
            Result.success()
        } catch (e: ApiException) {
            if (e.code == 401) Result.success() else Result.retry()
        } catch (e: IOException) {
            Result.retry()
        }
    }

    companion object {
        private const val NAME = "tileops-poll"

        fun schedule(ctx: Context) {
            val req = PeriodicWorkRequestBuilder<PollWorker>(15, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, req)
        }
    }
}
