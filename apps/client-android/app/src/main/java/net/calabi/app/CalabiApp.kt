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
            .put("file_transfer_p0", BuildConfig.DEBUG)
            .put("file_transfer_v1", BuildConfig.FILE_TRANSFER_ENABLED)
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
        if (BuildConfig.FILE_TRANSFER_ENABLED) {
            val manager = getSystemService(NotificationManager::class.java)
            val legacy = manager.getNotificationChannel("files")
            // A dedicated request channel enables banners without overriding user-muted alerts.
            val importance = if (legacy != null && (Build.VERSION.SDK_INT < 29 || legacy.hasUserSetImportance())) legacy.importance else NotificationManager.IMPORTANCE_HIGH
            val requests = NotificationChannel(CHANNEL_FILES, getString(R.string.files_pending), importance)
            if (legacy != null) {
                requests.setSound(legacy.sound, legacy.audioAttributes)
                requests.enableVibration(legacy.shouldVibrate())
                requests.vibrationPattern = legacy.vibrationPattern
                requests.lockscreenVisibility = legacy.lockscreenVisibility
            }
            manager.createNotificationChannel(requests)
        }
    }

    companion object {
        const val CHANNEL_VPN = "vpn"
        const val CHANNEL_FILES = "file_requests"

        lateinit var instance: CalabiApp
            private set
    }
}
