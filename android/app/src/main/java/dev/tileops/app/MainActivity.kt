package dev.tileops.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.fragment.app.FragmentActivity
import dev.tileops.app.ui.AppRoot
import dev.tileops.app.ui.Palette
import dev.tileops.app.ui.TileOpsTheme

/** FragmentActivity (not plain ComponentActivity) because BiometricPrompt needs one. */
class MainActivity : FragmentActivity() {
    private val link = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (savedInstanceState == null) link.value = intent?.dataString
        setContent {
            TileOpsTheme {
                Surface(color = Palette.bg) {
                    AppRoot(link = link.value, onLinkHandled = { link.value = null })
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        link.value = intent.dataString
    }
}
