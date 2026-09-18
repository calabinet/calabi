package net.calabi.app

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import net.calabi.core.mobile.Platform
import org.json.JSONArray
import org.json.JSONObject

/**
 * What the Go core asks of Android (net.calabi.core.mobile.Platform). Called from
 * the core's own threads.
 */
class AppPlatform(private val app: CalabiApp) : Platform {

    override fun applyNetwork(settingsJSON: String): Int {
        val service = app.vpnService
            ?: throw IllegalStateException("the VPN service is not running")
        return service.establish(settingsJSON)
    }

    override fun protect(fd: Int): Boolean {
        // No VPN running: nothing to keep the socket out of.
        val service = app.vpnService ?: return true
        if (service.protect(fd)) return true
        // Before the VPN interface exists nothing can loop into it, so a refusal
        // then must not stop the core from reaching the control plane.
        if (!service.established) {
            Log.w(TAG, "protect($fd) refused before the VPN was established; continuing")
            return true
        }
        return false
    }

    /**
     * The device's own networks — never the VPN — as the core expects them:
     * [{"name": "wlan0", "up": true, "loopback": false, "addrs": ["192.168.1.7/24"]}].
     */
    override fun interfaces(): String {
        val cm = app.getSystemService(ConnectivityManager::class.java)
        val out = JSONArray()
        @Suppress("DEPRECATION")
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val props = cm.getLinkProperties(network) ?: continue
            val addrs = JSONArray()
            for (la in props.linkAddresses) {
                val host = la.address.hostAddress ?: continue
                addrs.put("${host.substringBefore('%')}/${la.prefixLength}")
            }
            out.put(
                JSONObject()
                    .put("name", props.interfaceName ?: "")
                    .put("up", true)
                    .put("loopback", false)
                    .put("addrs", addrs)
            )
        }
        return out.toString()
    }

    override fun log(level: Int, msg: String) {
        when {
            level >= 8 -> Log.e(TAG, msg)
            level >= 4 -> Log.w(TAG, msg)
            level >= 0 -> Log.i(TAG, msg)
            else -> Log.d(TAG, msg)
        }
    }

    private companion object {
        const val TAG = "calabi-core"
    }
}
