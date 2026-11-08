package dev.tileops.app.widget

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.action.actionStartActivity
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.cornerRadius
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.color.ColorProvider
import androidx.glance.layout.Column
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import dev.tileops.app.MainActivity
import dev.tileops.app.backend
import dev.tileops.app.data.OverallStatus
import dev.tileops.app.work.StatusCache
import kotlinx.coroutines.withTimeoutOrNull

/** Home-screen widget: server name + status + open alert count. Tap opens the app. */
class StatusWidget : GlanceAppWidget() {

    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val paired = context.backend()
        val fresh = paired?.let { api -> withTimeoutOrNull(8_000) { runCatching { api.status() }.getOrNull() } }
        if (fresh != null) StatusCache.save(context, fresh)
        val status = fresh ?: StatusCache.load(context)?.first
        provideContent { Content(paired != null, status) }
    }

    @Composable
    private fun Content(paired: Boolean, s: OverallStatus?) {
        val white = ColorProvider(day = Color.White, night = Color.White)
        val muted = ColorProvider(day = Color(0xFF9AA3B2), night = Color(0xFF9AA3B2))
        val (label, color) = when {
            !paired -> "Not paired" to Color(0xFF9AA3B2)
            s == null -> "Offline" to Color(0xFF9AA3B2)
            s.ok -> "OK" to Color(0xFF3ECF8E)
            s.servers.any { it.status == "unreachable" } && s.openAlerts == 0 -> "Unreachable" to Color(0xFFFF5C6C)
            else -> "ALERT" to Color(0xFFFF5C6C)
        }
        val server = s?.servers?.firstOrNull()?.name ?: "TileOps"
        val more = (s?.servers?.size ?: 0) - 1
        Column(
            modifier = GlanceModifier.fillMaxSize().cornerRadius(16.dp).background(Color(0xFF181B22))
                .padding(12.dp).clickable(actionStartActivity<MainActivity>())
        ) {
            Text(
                if (more > 0) "$server +$more" else server,
                style = TextStyle(color = white, fontSize = 15.sp, fontWeight = FontWeight.Bold), maxLines = 1,
            )
            Spacer(GlanceModifier.height(4.dp))
            Text(label, style = TextStyle(color = ColorProvider(day = color, night = color), fontSize = 20.sp, fontWeight = FontWeight.Bold))
            Text(
                "${s?.openAlerts ?: 0} open alert${if ((s?.openAlerts ?: 0) == 1) "" else "s"}",
                style = TextStyle(color = muted, fontSize = 13.sp),
            )
        }
    }
}

class StatusWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = StatusWidget()
}
