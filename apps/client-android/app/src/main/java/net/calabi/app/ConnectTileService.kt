package net.calabi.app

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import java.lang.ref.WeakReference

/** The Quick Settings tile: connect or disconnect without opening the app. */
class ConnectTileService : TileService() {

    private val app get() = application as CalabiApp

    override fun onStartListening() {
        super.onStartListening()
        listening = WeakReference(this)
        render()
    }

    override fun onStopListening() {
        if (listening?.get() === this) listening = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (app.vpnService != null) {
            CalabiVpnService.disconnect(this)
            return
        }
        // Consent and sign-in both need a screen; the tile cannot ask for either.
        if (VpnService.prepare(this) != null || !CoreClient.signedIn()) {
            val open = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // Android 14+ refuses a bare Intent here.
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(open)
            }
            return
        }
        CalabiVpnService.connect(this)
    }

    private fun render() {
        val tile = qsTile ?: return
        tile.state = if (app.vpnService != null) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        tile.updateTile()
    }

    companion object {
        // The tile while the panel shows it. requestListeningState is ignored for a
        // tile that is already listening, so a change made with the panel open (a
        // tap on the tile itself) has to be drawn on the live instance directly.
        // Found on a real phone: after tapping to disconnect the tile stayed on.
        @Volatile
        private var listening: WeakReference<ConnectTileService>? = null

        /** Redraws the tile after the VPN started or stopped. Call on the main thread. */
        fun refresh(context: Context) {
            val live = listening?.get()
            if (live != null) {
                live.render()
                return
            }
            requestListeningState(context, ComponentName(context, ConnectTileService::class.java))
        }
    }
}
