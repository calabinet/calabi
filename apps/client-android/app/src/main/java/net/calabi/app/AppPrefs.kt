package net.calabi.app

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.os.SystemClock

/** The app's own choices; the core keeps everything the meshnet needs. */
object AppPrefs {
    private const val FILE = "calabi"
    private const val CONNECT_ON_BOOT = "connect_on_boot"
    private const val REPLACE_DISMISSED = "replace_dismissed"
    private const val VPN_UP_AT = "vpn_up_at"

    private fun prefs(context: Context) = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun connectOnBoot(context: Context): Boolean = prefs(context).getBoolean(CONNECT_ON_BOOT, false)

    fun setConnectOnBoot(context: Context, on: Boolean) {
        prefs(context).edit().putBoolean(CONNECT_ON_BOOT, on).apply()
    }

    /** The VPN came up. It stays "left on" until [markVpnDown], across process deaths. */
    fun markVpnUp(context: Context) {
        prefs(context).edit().putLong(VPN_UP_AT, System.currentTimeMillis()).apply()
    }

    /** The user turned the VPN off, the system settings did, or it failed to connect. */
    fun markVpnDown(context: Context) {
        prefs(context).edit().remove(VPN_UP_AT).apply()
    }

    /**
     * The VPN was left on and is not running, and neither a restart nor an update
     * explains it: something stopped the app. On some phones that is the maker's
     * power manager, soon after the screen goes off (EMUI's PowerGenie force-stops
     * it, so the service cannot restart itself).
     */
    fun vpnStoppedFromOutside(context: Context): Boolean {
        val upAt = prefs(context).getLong(VPN_UP_AT, 0L)
        if (upAt == 0L || CalabiApp.instance.vpnService != null) return false
        // Asked every couple of seconds while the screen is up; the answer only
        // changes when the VPN comes up again.
        if (upAt != checkedUpAt) {
            checkedUpAt = upAt
            checkedStopped = stoppedSince(context, upAt)
        }
        return checkedStopped
    }

    private var checkedUpAt = 0L
    private var checkedStopped = false

    private fun stoppedSince(context: Context, upAt: Long): Boolean {
        val bootedAt = System.currentTimeMillis() - SystemClock.elapsedRealtime()
        val updatedAt = context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime
        if (upAt <= bootedAt || upAt <= updatedAt) return false
        // Android 11+ says how the last process ended: a crash is ours to fix,
        // not something the user can allow.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val last = context.getSystemService(ActivityManager::class.java)
                .getHistoricalProcessExitReasons(context.packageName, 0, 1).firstOrNull()
            if (last != null && last.timestamp > upAt && last.reason in CRASHES) return false
        }
        return true
    }

    private val CRASHES = setOf(
        ApplicationExitInfo.REASON_CRASH,
        ApplicationExitInfo.REASON_CRASH_NATIVE,
        ApplicationExitInfo.REASON_ANR,
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE,
    )

    /** Old devices the user said this phone is not replacing: not offered again. */
    fun replaceDismissed(context: Context): Set<Long> =
        prefs(context).getStringSet(REPLACE_DISMISSED, emptySet()).orEmpty().mapNotNull { it.toLongOrNull() }.toSet()

    fun dismissReplace(context: Context, ids: Collection<Long>) {
        val all = replaceDismissed(context) + ids
        prefs(context).edit().putStringSet(REPLACE_DISMISSED, all.map { it.toString() }.toSet()).apply()
    }
}
