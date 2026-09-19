package net.calabi.app

import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Context
import android.graphics.drawable.Icon
import android.os.Build
import androidx.annotation.StringRes

/**
 * Getting the Quick Settings tile into the panel.
 *
 * An app cannot put it there itself. Android 13 added one call that asks the
 * system to, which shows the user a one-tap dialog; before that the only way is
 * the panel's own edit mode, so all the app can do is say where it is.
 */
object QuickTile {

    /** Where to add it by hand on this phone. */
    @StringRes
    fun steps(): Int = if (Build.MANUFACTURER.lowercase() in setOf("huawei", "honor")) {
        R.string.tile_steps_huawei
    } else {
        R.string.tile_steps
    }

    /**
     * Adds the tile: the system's dialog where there is one, else [showSteps].
     * [onAdded] runs once it is in the panel. A "no" in the dialog does nothing
     * more: asking again, or showing the manual route, would be arguing with it.
     */
    fun add(context: Context, showSteps: () -> Unit, onAdded: () -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            showSteps()
            return
        }
        context.getSystemService(StatusBarManager::class.java).requestAddTileService(
            ComponentName(context, ConnectTileService::class.java),
            context.getString(R.string.app_name),
            Icon.createWithResource(context, R.drawable.ic_tile),
            context.mainExecutor,
        ) { result ->
            when {
                result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED ||
                    result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED -> {
                    AppPrefs.setTileAdded(context, true)
                    onAdded()
                }
                // 1000+ are the system refusing to ask (not in the foreground, a
                // request already open, ...), not the user saying no.
                result >= 1000 -> showSteps()
            }
        }
    }
}
