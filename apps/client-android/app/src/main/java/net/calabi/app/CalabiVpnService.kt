package net.calabi.app

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The VPN. It keeps the process in the foreground while connected, lends the Go
 * core the VpnService calls only it may make (establish, protect), and tells the
 * core when the device's network changes.
 *
 * The core decides WHEN to establish: as soon as the coordinator assigns this
 * phone an address, and again whenever routes change (a peer's subnet, an exit
 * device). Each establish yields a new descriptor, which the core switches to.
 */
class CalabiVpnService : VpnService() {

    private val app get() = application as CalabiApp
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var watchingSince = 0L

    /** Whether the VPN interface currently exists (establish succeeded). */
    @Volatile
    var established = false
        private set

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        // Started by the app, by the tile, or by the system for always-on VPN
        // (intent action android.net.VpnService, or no intent at all).
        goForeground()
        app.vpnService = this
        AppPrefs.markVpnUp(this)
        watchNetworks()
        worker.execute {
            try {
                app.core.connect()
            } catch (e: Exception) {
                Log.w(TAG, "connect failed: ${e.message}")
                main.post { disconnect() }
            }
        }
        ConnectTileService.refresh(this)
        return START_STICKY
    }

    /** Called by the core (AppPlatform.applyNetwork) on its own thread. */
    fun establish(settingsJSON: String): Int {
        val s = JSONObject(settingsJSON)
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(s.optInt("mtu", 1280))
            .setBlocking(false)
            .setConfigureIntent(openAppIntent())
        val addresses = s.getJSONArray("addresses")
        for (i in 0 until addresses.length()) {
            val (ip, bits) = splitPrefix(addresses.getString(i))
            builder.addAddress(ip, bits)
        }
        val routes = s.getJSONArray("routes")
        for (i in 0 until routes.length()) {
            val (ip, bits) = splitPrefix(routes.getString(i))
            builder.addRoute(ip, bits)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        val pfd = builder.establish()
            ?: throw IllegalStateException("VPN permission is not granted")
        established = true
        return pfd.detachFd()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user turned this one off in Settings.
        Log.i(TAG, "VPN revoked by the system")
        disconnect()
    }

    override fun onDestroy() {
        stopWatchingNetworks()
        if (app.vpnService === this) app.vpnService = null
        worker.shutdown()
        ConnectTileService.refresh(this)
        super.onDestroy()
    }

    private fun disconnect() {
        AppPrefs.markVpnDown(this)
        stopWatchingNetworks()
        established = false
        worker.execute {
            app.core.disconnect()
            main.post {
                if (app.vpnService === this) app.vpnService = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                ConnectTileService.refresh(this)
            }
        }
    }

    private fun goForeground() {
        val notification = Notification.Builder(this, CalabiApp.CHANNEL_VPN)
            .setSmallIcon(R.drawable.ic_tile)
            .setContentTitle(getString(R.string.notification_connected_title))
            .setContentIntent(openAppIntent())
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** Wi-Fi to cellular, a new network, a network coming back: tell the core. */
    private fun watchNetworks() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        // A default request already asks for NOT_VPN: these are the device's own
        // networks, which is what changes when the phone roams.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = changed()
            override fun onLost(network: Network) = changed()
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = changed()
        }
        watchingSince = SystemClock.elapsedRealtime()
        cm.registerNetworkCallback(request, cb)
        networkCallback = cb
    }

    private fun stopWatchingNetworks() {
        val cb = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb)
        } catch (_: IllegalArgumentException) {
        }
    }

    // Callbacks come in bursts (available, then link properties, then
    // capabilities); one repair is enough.
    private val networkChanged = Runnable { worker.execute { app.core.networkChanged() } }

    private fun changed() {
        // Registering replays the networks that already exist; that is the
        // network the core is connecting on, not a change.
        if (SystemClock.elapsedRealtime() - watchingSince < INITIAL_REPLAY_MS) return
        main.removeCallbacks(networkChanged)
        main.postDelayed(networkChanged, 500)
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun splitPrefix(s: String): Pair<String, Int> {
        val slash = s.indexOf('/')
        return s.substring(0, slash) to s.substring(slash + 1).toInt()
    }

    companion object {
        private const val TAG = "calabi-vpn"
        private const val NOTIFICATION_ID = 1
        private const val INITIAL_REPLAY_MS = 1500L
        private const val ACTION_DISCONNECT = "net.calabi.app.DISCONNECT"

        /** Starts the VPN. The caller has already obtained VpnService.prepare consent. */
        fun connect(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, CalabiVpnService::class.java))
        }

        fun disconnect(context: Context) {
            context.startService(Intent(context, CalabiVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }
}
