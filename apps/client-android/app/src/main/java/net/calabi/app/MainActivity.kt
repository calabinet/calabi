package net.calabi.app

import android.Manifest
import android.app.Activity
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import net.calabi.app.ui.CalabiTheme
import net.calabi.app.ui.HomeScreen
import net.calabi.app.ui.LoginScreen
import net.calabi.app.ui.Palette

class MainActivity : ComponentActivity() {

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
        setContent {
            CalabiTheme {
                AppRoot(onConnect = ::connect, onDisconnect = { CalabiVpnService.disconnect(this) })
            }
        }
    }

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
private fun AppRoot(onConnect: () -> Unit, onDisconnect: () -> Unit) {
    var signedIn by remember { mutableStateOf<Boolean?>(null) }
    var refresh by remember { mutableStateOf(0) }
    LaunchedEffect(refresh) {
        while (true) {
            val st = CoreClient.call("GET", "/v1/state")
            signedIn = st.json().optBoolean("signed_in")
            delay(3000)
        }
    }
    when (signedIn) {
        null -> Box(Modifier.fillMaxSize().background(Palette.ground), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = Palette.accent)
        }
        false -> LoginScreen(onSignedIn = { refresh++ })
        true -> HomeScreen(onConnect = onConnect, onDisconnect = onDisconnect, onSignedOut = { refresh++ })
    }
}
