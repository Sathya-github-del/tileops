package dev.tileops.app.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import dev.tileops.app.R
import dev.tileops.app.data.ApiClient
import dev.tileops.app.data.TileOpsBackend
import dev.tileops.app.data.Pairing
import dev.tileops.app.data.PairingUri
import dev.tileops.app.tileOps
import dev.tileops.app.work.StatusCache
import kotlinx.coroutines.launch

private sealed interface AppState {
    data object Loading : AppState
    data object Onboarding : AppState
    data object Local : AppState
    data class Companion(val pairing: Pairing) : AppState
}

private const val LOADING = "\u0000loading"

/** Root: onboarding (choose mode / connect), then the tabbed app. [link] is a pending tileops:// deep link. */
@Composable
fun AppRoot(link: String?, onLinkHandled: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.tileOps
    val tokens = app.tokens
    val scope = rememberCoroutineScope()
    val mode by tokens.mode.collectAsState(initial = LOADING)
    val pairing by tokens.pairing.collectAsState(initial = Unit)
    val p = pairing
    val state: AppState = when {
        mode == LOADING || p == Unit -> AppState.Loading
        mode == "local" -> AppState.Local
        p is Pairing -> AppState.Companion(p)
        else -> AppState.Onboarding
    }

    // A pairing deep link (tileops://pair?...) prefills onboarding, or asks before replacing/switching.
    val linkPairing = PairingUri.parse(link)
    var replaceWith by remember { mutableStateOf<Pairing?>(null) }
    var confirmSwitch by remember { mutableStateOf(false) }
    LaunchedEffect(link, state) {
        if (linkPairing != null && (state is AppState.Local || state is AppState.Companion)) {
            onLinkHandled()
            if (!(state is AppState.Companion && state.pairing == linkPairing)) replaceWith = linkPairing
        }
    }

    suspend fun refreshSurfaces() {
        StatusCache.clear(ctx)
        StatusCache.refreshSurfaces(ctx)
    }

    suspend fun pairCompanion(p: Pairing) {
        tokens.save(p)
        tokens.setMode("companion")
        refreshSurfaces()
    }

    when (state) {
        AppState.Loading -> Box(Modifier.fillMaxSize())
        AppState.Onboarding -> PairScreen(
            prefill = linkPairing,
            onPaired = { p ->
                onLinkHandled() // clear first: once saved, the paired branch must not see the link again
                pairCompanion(p)
            },
            onUsePhone = { scope.launch { tokens.setMode("local"); refreshSurfaces() } },
        )
        AppState.Local -> MainScaffold(
            api = app.localEngine,
            alertLink = PairingUri.alertId(link),
            onLinkHandled = onLinkHandled,
            onUnpair = null,
            onSwitchMode = { confirmSwitch = true },
        )
        is AppState.Companion -> MainScaffold(
            api = remember(state.pairing) { ApiClient(state.pairing.baseUrl, state.pairing.token, state.pairing.certPin) },
            alertLink = PairingUri.alertId(link),
            onLinkHandled = onLinkHandled,
            onUnpair = { scope.launch { tokens.clearPairing(); tokens.setMode(null); refreshSurfaces() } },
            onSwitchMode = { confirmSwitch = true },
        )
    }

    if (confirmSwitch) {
        val toLocal = state is AppState.Companion
        AlertDialog(
            onDismissRequest = { confirmSwitch = false },
            title = { Text(if (toLocal) "Use this phone only?" else "Use an always-on companion?") },
            text = {
                Text(
                    (if (toLocal) "This phone will check your servers itself. Checks run when you open TileOps and in the " +
                        "background when Android allows, so alerts can be late while the phone sleeps."
                    else "A companion on an always-on device checks your servers every 5 minutes and alerts you even " +
                        "when this phone is off.") +
                        "\n\nServers you added in one mode aren't copied to the other. Nothing is deleted; you can switch back any time."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmSwitch = false
                    scope.launch { tokens.setMode(if (toLocal) "local" else "companion"); refreshSurfaces() }
                }) { Text("Switch") }
            },
            dismissButton = { TextButton(onClick = { confirmSwitch = false }) { Text("Cancel") } },
        )
    }

    replaceWith?.let { np ->
        AlertDialog(
            onDismissRequest = { replaceWith = null },
            title = { Text(if (state is AppState.Local) "Connect a companion?" else "Replace pairing?") },
            text = { Text("Connect this app to the companion at ${np.baseUrl}? Only continue if you trust this link.") },
            confirmButton = {
                TextButton(onClick = {
                    replaceWith = null
                    scope.launch { runCatching { ApiClient(np.baseUrl, np.token, np.certPin).status(); pairCompanion(np) } }
                }) { Text("Connect") }
            },
            dismissButton = { TextButton(onClick = { replaceWith = null }) { Text("Cancel") } },
        )
    }
}

private data class Tab(val route: String, val label: String, val icon: Int)

private val TABS = listOf(
    Tab("alerts", "Alerts", R.drawable.ic_nav_alerts),
    Tab("servers", "Servers", R.drawable.ic_nav_servers),
    Tab("incidents", "Timeline", R.drawable.ic_nav_timeline),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScaffold(
    api: TileOpsBackend, alertLink: Long?, onLinkHandled: () -> Unit, onUnpair: (() -> Unit)?, onSwitchMode: () -> Unit,
) {
    val ctx = LocalContext.current
    val nav = rememberNavController()
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var refresh by remember { mutableIntStateOf(0) }
    var menu by remember { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    var confirmUnpair by remember { mutableStateOf(false) }
    val backStackForStatus by nav.currentBackStackEntryAsState()
    // refresh the status dot on every navigation too, so actions inside screens (scan on a card,
    // mark as expected…) are reflected as soon as you move on
    val overall by rememberLoad(refresh, backStackForStatus?.destination?.route) { api.status().also { StatusCache.save(ctx, it) } }
    val toast: (String) -> Unit = { msg -> scope.launch { snackbar.showSnackbar(msg); refresh++ } }

    // ntfy "Open in app" / backup notification deep link
    LaunchedEffect(alertLink) {
        if (alertLink != null) {
            nav.navigate("alert/$alertLink") { launchSingleTop = true }
            onLinkHandled()
        }
    }

    // Back from the VPN app (or anywhere): refresh, and in phone-only mode check VPN-only servers
    // that are waiting, now that the VPN may be connected.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        refresh++
        val engine = api as? dev.tileops.app.core.LocalEngine ?: return@LifecycleEventEffect
        scope.launch {
            val due = runCatching { engine.vpnServersDue() }.getOrDefault(emptyList())
            if (due.isEmpty()) return@launch
            toast("VPN connected: checking ${due.joinToString()}…")
            val n = due.sumOf { runCatching { engine.scan(it).newAlerts.size }.getOrDefault(0) }
            toast("Checked ${due.joinToString()}: $n new alert(s)")
            StatusCache.refreshSurfaces(ctx)
        }
    }

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    val backStack by nav.currentBackStackEntryAsState()
    val route = backStack?.destination?.route ?: "alerts"

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
                        val o = (overall as? Load.Ok)?.value
                        Dot(when { o == null -> Palette.muted; o.ok -> Palette.ok; else -> Palette.critical })
                        Text("  TileOps", fontWeight = FontWeight.Bold)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Palette.bg),
                actions = {
                    TextButton(enabled = !scanning, onClick = {
                        scanning = true
                        scope.launch {
                            try {
                                val n = api.scanAll().sumOf { it.newAlerts.size }
                                toast("Scan done: $n new alert(s)")
                            } catch (e: Exception) {
                                toast(errorText(e))
                            }
                            StatusCache.refreshSurfaces(ctx)
                            scanning = false
                            refresh++
                        }
                    }) { Text(if (scanning) "Scanning…" else "Scan now") }
                    TextButton(onClick = { refresh++ }) { Text("Refresh") }
                    TextButton(onClick = { menu = true }) { Text("⋮") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(
                            text = { Text(if (api.isLocal) "Mode: this phone only" else "Companion: ${api.label}", color = Palette.muted) },
                            onClick = { menu = false },
                        )
                        DropdownMenuItem(
                            text = { Text(if (api.isLocal) "Use an always-on companion…" else "Use this phone only…") },
                            onClick = { menu = false; onSwitchMode() },
                        )
                        DropdownMenuItem(text = { Text("About TileOps") }, onClick = { menu = false; nav.navigate("about") })
                        if (onUnpair != null) DropdownMenuItem(text = { Text("Unpair…") }, onClick = { menu = false; confirmUnpair = true })
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Palette.card) {
                TABS.forEach { t ->
                    val selected = route == t.route || (t.route == "alerts" && route.startsWith("alert/")) ||
                        (t.route == "servers" && route.startsWith("server-")) ||
                        (t.route == "incidents" && (route.startsWith("incident/") || route.startsWith("run/")))
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            // tapping the tab you're in goes back to its top level (Material behaviour)
                            if (selected && route != t.route && nav.popBackStack(t.route, inclusive = false)) return@NavigationBarItem
                            nav.navigate(t.route) {
                                popUpTo("alerts") { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(painterResource(t.icon), contentDescription = t.label) },
                        label = { Text(t.label) },
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { pad ->
        Box(Modifier.padding(pad)) { Routes(nav, api, refresh, toast) }
    }
    if (confirmUnpair) AlertDialog(
        onDismissRequest = { confirmUnpair = false },
        title = { Text("Unpair this app?") },
        text = { Text("This phone forgets the companion at ${api.label} and its pairing code. Monitoring keeps running " +
            "on the companion; you'll need the pairing QR or token to connect again.") },
        confirmButton = { TextButton(onClick = { confirmUnpair = false; onUnpair?.invoke() }) { Text("Unpair", color = Palette.critical) } },
        dismissButton = { TextButton(onClick = { confirmUnpair = false }) { Text("Cancel") } },
    )
}

@Composable
private fun Routes(nav: NavHostController, api: TileOpsBackend, refresh: Int, toast: (String) -> Unit) {
    val idArg = listOf(navArgument("id") { type = NavType.LongType })
    NavHost(nav, startDestination = "alerts") {
        composable("alerts") { AlertsScreen(api, refresh) { nav.navigate("alert/$it") } }
        composable("servers") {
            ServersScreen(api, refresh, toast, onOpenRun = { nav.navigate("run/$it") },
                onAdd = { nav.navigate("server-new") },
                onEdit = { nav.navigate("server-edit/$it") },
                onSetup = { nav.navigate("server-setup/$it") })
        }
        composable("server-new") {
            ServerFormScreen(api, null, toast) { name, _ ->
                nav.navigate("server-setup/$name") { popUpTo("servers") }
            }
        }
        composable("server-edit/{name}", arguments = listOf(navArgument("name") { type = NavType.StringType })) { e ->
            ServerFormScreen(api, e.arguments!!.getString("name"), toast) { name, needsSetup ->
                if (needsSetup) nav.navigate("server-setup/$name") { popUpTo("servers") } else nav.popBackStack()
            }
        }
        composable("server-setup/{name}", arguments = listOf(navArgument("name") { type = NavType.StringType })) { e ->
            ServerSetupScreen(api, e.arguments!!.getString("name")!!, toast) {
                nav.navigate("servers") { popUpTo("servers") { inclusive = true } }
            }
        }
        composable("about") { AboutScreen(api) { nav.navigate("licenses") } }
        composable("licenses") { LicensesScreen() }
        composable("incidents") { IncidentsScreen(api, refresh) { nav.navigate("incident/$it") } }
        composable("alert/{id}", arguments = idArg) { e ->
            AlertDetailScreen(api, e.arguments!!.getLong("id"), toast,
                onOpenRun = { nav.navigate("run/$it") }, onOpenIncident = { nav.navigate("incident/$it") })
        }
        composable("run/{id}", arguments = idArg) { e ->
            RunScreen(api, e.arguments!!.getLong("id"), toast) { nav.navigate("incident/$it") }
        }
        composable("incident/{id}", arguments = idArg) { e ->
            IncidentScreen(api, e.arguments!!.getLong("id"),
                onOpenAlert = { nav.navigate("alert/$it") }, onOpenRun = { nav.navigate("run/$it") })
        }
    }
}
