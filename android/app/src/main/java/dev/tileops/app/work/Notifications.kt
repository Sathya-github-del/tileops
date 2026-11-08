package dev.tileops.app.work

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import dev.tileops.app.MainActivity
import dev.tileops.app.R
import dev.tileops.app.data.Alert

/** Backup notifications from WorkManager polling (ntfy is the primary channel). */
object Notifications {
    const val CHANNEL = "alerts_backup"
    const val CHANNEL_PRIMARY = "alerts"

    fun createChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL_PRIMARY, "Server alerts", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "New TileOps alerts found by this phone (phone-only mode)"
        })
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Alerts (backup polling)", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "New alerts from your companion found by background polling, in case ntfy missed one"
        })
    }

    fun alert(ctx: Context, a: Alert, primary: Boolean = false) {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        if (!NotificationManagerCompat.from(ctx).areNotificationsEnabled()) return
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("tileops://alert/${a.id}"), ctx, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pi = PendingIntent.getActivity(ctx, a.id.toInt(), intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        // Same minimal text as ntfy: no evidence in notifications.
        val n = NotificationCompat.Builder(ctx, if (primary) CHANNEL_PRIMARY else CHANNEL)
            .setSmallIcon(R.drawable.ic_tile_alert)
            .setContentTitle("TileOps")
            .setContentText("[${a.severity}] ${a.title} on ${a.server}")
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(ctx).notify(a.id.toInt(), n) }
    }
}
