package net.calabi.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * Connects after the phone restarts, when the user turned that on. The system's
 * always-on VPN does the same, but some ROMs (EMUI) offer no way to turn it on
 * for a third-party app.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!AppPrefs.connectOnBoot(context)) return
        // Always-on may have started it already; starting again is harmless, but
        // there is nothing to do.
        if (CalabiApp.instance.vpnService != null) return
        // Consent and sign-in both need a screen, which a restart does not have.
        if (VpnService.prepare(context) != null) {
            Log.i(TAG, "not connecting after restart: VPN consent was withdrawn")
            return
        }
        if (!CoreClient.signedIn()) {
            Log.i(TAG, "not connecting after restart: signed out")
            return
        }
        Log.i(TAG, "connecting after restart")
        CalabiVpnService.connect(context)
    }

    private companion object {
        const val TAG = "calabi-vpn"
    }
}
