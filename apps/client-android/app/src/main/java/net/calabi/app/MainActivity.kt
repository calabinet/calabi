package net.calabi.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import net.calabi.app.ui.CalabiTheme
import net.calabi.app.ui.HomeScreen
import net.calabi.app.ui.LoginScreen
import net.calabi.app.ui.Palette
import net.calabi.app.ui.SelfHostedScreen
import net.calabi.app.ui.Styles
import net.calabi.app.ui.toast
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    /** A calabi://join invite the app was opened with, until the screens take it. */
    private val inviteLink = mutableStateOf<String?>(null)

    // The system's "allow this app to set up a VPN" dialog, shown once.
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) CalabiVpnService.connect(this)
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The design is light only, so the bar icons stay dark even when the system is in dark mode.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT),
        )
        inviteLink.value = inviteIn(intent)
        setContent {
            CalabiTheme {
                AppRoot(
                    onConnect = ::connect, onDisconnect = { CalabiVpnService.disconnect(this) },
                    invite = inviteLink.value, onInviteTaken = { inviteLink.value = null },
                )
            }
        }
    }

    // singleTask: an invite opened while the app runs arrives here.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        inviteIn(intent)?.let { inviteLink.value = it }
    }

    private fun inviteIn(intent: Intent?): String? =
        intent?.data?.takeIf { it.scheme == "calabi" && it.host == "join" }?.toString()

    private fun connect() {
        // Android 13+: without it the "connected" notification is hidden, and the
        // VPN still works — so ask, but never block on the answer.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else CalabiVpnService.connect(this)
    }
}

@Composable
private fun AppRoot(onConnect: () -> Unit, onDisconnect: () -> Unit, invite: String?, onInviteTaken: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var signedIn by remember { mutableStateOf<Boolean?>(null) }
    // Which network the phone is on: the signed-in screens are rebuilt when it
    // changes, or they would keep the one they started with (its organizations,
    // its account, its tabs) after joining a self-hosted server.
    var network by remember { mutableStateOf("") }
    var refresh by remember { mutableStateOf(0) }
    // Signed out: the calabi.net sign-in, or joining a self-hosted server.
    var selfHosted by remember { mutableStateOf(false) }
    LaunchedEffect(refresh) {
        while (true) {
            val st = CoreClient.call("GET", "/v1/state").json()
            signedIn = st.optBoolean("signed_in")
            network = st.optString("mode") + "|" + st.optString("server")
            delay(3000)
        }
    }
    val joinFailed = stringResource(R.string.sh_failed)
    when (signedIn) {
        null -> Box(Modifier.fillMaxSize().background(Palette.ground), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = Palette.accent)
        }
        false -> if (selfHosted || invite != null) {
            SelfHostedScreen(
                link = invite,
                onBack = { selfHosted = false; onInviteTaken() },
                onJoined = { selfHosted = false; onInviteTaken(); refresh++ },
            )
        } else {
            LoginScreen(onSignedIn = { refresh++ }, onSelfHosted = { selfHosted = true })
        }
        true -> {
            key(network) { HomeScreen(onConnect = onConnect, onDisconnect = onDisconnect, onSignedOut = { refresh++ }) }
            // An invite opened while signed in somewhere: one network at a time, so ask.
            invite?.let { link ->
                AlertDialog(
                    onDismissRequest = onInviteTaken,
                    containerColor = Palette.surface,
                    title = { Text(stringResource(R.string.sh_switch_title), style = Styles.section) },
                    text = {
                        val server = android.net.Uri.parse(link).getQueryParameter("s").orEmpty()
                        Text(stringResource(R.string.sh_switch_body, server), style = Styles.row.copy(color = Palette.muted))
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            onInviteTaken()
                            scope.launch {
                                onDisconnect()
                                val r = CoreClient.call("POST", "/v1/selfhosted/join", JSONObject().put("link", link).put("replace", true))
                                if (!r.ok) toast(context, r.error(joinFailed))
                                refresh++
                            }
                        }) { Text(stringResource(R.string.sh_switch_yes), color = Palette.danger, fontWeight = FontWeight.Bold) }
                    },
                    dismissButton = {
                        TextButton(onClick = onInviteTaken) { Text(stringResource(R.string.settings_cancel), color = Palette.ink) }
                    },
                )
            }
        }
    }
}
