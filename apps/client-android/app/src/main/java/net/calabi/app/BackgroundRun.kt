package net.calabi.app

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.annotation.StringRes

/**
 * Keeping the VPN up with the screen off, and starting it after a restart.
 *
 * Stock Android leaves a VPN's foreground service alone. Some phone makers' power
 * managers do not: EMUI's PowerGenie force-stops an app that has sat in the
 * background a while once the phone is on battery with the screen off (ELS-AN00,
 * 2026-09-18: 51 minutes in the background, stopped 3 s after unplugging; 5
 * minutes was not enough to set it off). The app was already on "manage
 * manually" there, with only auto-launch allowed; "run in background" was off.
 * A force-stopped app cannot restart itself, so the only fix is the user
 * allowing it, in the maker's own settings.
 */
object BackgroundRun {

    /**
     * Whether there may be something left to allow. The makers' switches cannot
     * be read, so on their phones this stays true.
     */
    fun mayNeedAllowing(context: Context): Boolean = makerSettings().isNotEmpty() || !batteryExempt(context)

    /** What the user has to do, for the settings row and the stopped notice. */
    @StringRes
    fun hint(): Int = when {
        isHuawei() -> R.string.background_hint_huawei
        makerSettings().isNotEmpty() -> R.string.background_hint_maker
        else -> R.string.background_hint
    }

    /** Opens the one place this phone lets the user allow it. */
    fun allow(context: Context) {
        when {
            makerSettings().isNotEmpty() -> openMakerSettings(context)
            !batteryExempt(context) -> requestBatteryExemption(context)
            else -> open(context, appDetails(context))
        }
    }

    private fun batteryExempt(context: Context): Boolean =
        context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName)

    // Android's own switch, for phones without a maker switch. Not asked for on
    // the phones that have one: on EMUI the maker switch is the one found to
    // matter, and one place to go is easier to follow than two.
    @SuppressLint("BatteryLife")
    private fun requestBatteryExemption(context: Context) {
        val ask = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.fromParts("package", context.packageName, null))
        if (!open(context, ask)) open(context, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    private fun openMakerSettings(context: Context) {
        for (intent in makerSettings()) {
            if (open(context, intent)) return
        }
        open(context, appDetails(context))
    }

    private fun open(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: ActivityNotFoundException) {
        false
    } catch (_: SecurityException) {
        false
    }

    private fun appDetails(context: Context) =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))

    private fun maker() = Build.MANUFACTURER.lowercase()

    private fun isHuawei() = maker() in setOf("huawei", "honor")

    // Where a maker hides "let this app start by itself and keep running". Only
    // Huawei's is verified on a real phone (ELS-AN00, EMUI 10: App launch. The
    // three switches only show when an app's switch is turned off, so an app
    // already managed manually has to be switched on and off again).
    private fun makerSettings(): List<Intent> = when {
        isHuawei() -> listOf(
            Intent("huawei.intent.action.HSM_STARTUPAPP_MANAGER"),
            Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
        )
        maker() in setOf("xiaomi", "redmi") -> listOf(
            Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
        )
        else -> emptyList()
    }
}
