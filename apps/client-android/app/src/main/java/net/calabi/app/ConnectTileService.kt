package net.calabi.app

import android.annotation.SuppressLint
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

    override fun onTileAdded() {
        super.onTileAdded()
        AppPrefs.setTileAdded(this, true)
        refresh(this)
    }

    override fun onTileRemoved() {
        AppPrefs.setTileAdded(this, false)
        super.onTileRemoved()
    }

    override fun onStartListening() {
        super.onStartListening()
        // Only a tile in the panel listens: this also catches one added before
        // onTileAdded was recorded.
        AppPrefs.setTileAdded(this, true)
        listening = WeakReference(this)
        render()
    }

    override fun onStopListening() {
        if (listening?.get() === this) listening = null
        super.onStopListening()
    }

    override fun onDestroy() {
        if (listening?.get() === this) listening = null
        super.onDestroy()
    }

    // The legacy overload is needed only below API 34; the branch below guards it.
    @SuppressLint("StartActivityAndCollapseDeprecated")
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
        // Redraw a listening tile immediately, and also request a fresh callback:
        // active tiles stop listening after an update, asynchronously. A retained
        // instance alone does not guarantee the system still accepts its updates.
        @Volatile
        private var listening: WeakReference<ConnectTileService>? = null

        /** Redraws the tile after the VPN started or stopped. Call on the main thread. */
        fun refresh(context: Context) {
            listening?.get()?.render()
            requestListeningState(context, ComponentName(context, ConnectTileService::class.java))
        }
    }
}
