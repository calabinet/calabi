package net.calabi.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import net.calabi.core.mobile.Core
import net.calabi.core.mobile.Mobile
import org.json.JSONObject

/**
 * Holds the one Go core for the process. The core owns sign-in, the control plane
 * and the WireGuard datapath (apps/client/mobile); the app draws screens and owns
 * the VPN.
 */
class CalabiApp : Application() {

    lateinit var core: Core
        private set

    /** The running VPN service, if any. Set by the service itself. */
    @Volatile
    var vpnService: CalabiVpnService? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        val config = JSONObject()
            .put("state_dir", filesDir.absolutePath)
            .put("bff_url", BuildConfig.BFF_URL)
            .put("device_name", Build.MODEL ?: "")
            .put("coord_plaintext", BuildConfig.COORD_PLAINTEXT)
        core = Mobile.new_(config.toString(), AppPlatform(this))
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_VPN,
            getString(R.string.notification_channel_vpn),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        const val CHANNEL_VPN = "vpn"

        lateinit var instance: CalabiApp
            private set
    }
}
