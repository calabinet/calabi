package net.calabi.app

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.widget.Toast
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

    /** Optional device-specific instructions, kept out of the short summary. */
    @StringRes
    fun details(): Int? = if (isHuawei()) R.string.background_steps_huawei else null

    /** Opens the one place this phone lets the user allow it. */
    fun allow(context: Context) {
        val hasMakerSettings = makerSettings().isNotEmpty()
        val opened = when {
            hasMakerSettings -> openMakerSettings(context)
            !batteryExempt(context) -> requestBatteryExemption(context)
            else -> false
        }
        if (opened) return
        if (hasMakerSettings) {
            // App details is not App launch on Huawei. Make the fallback clear
            // and prefer the settings search entry instead of the wrong page.
            Toast.makeText(context, if (isHuawei()) R.string.background_manual_huawei else hint(), Toast.LENGTH_LONG).show()
            if (open(context, Intent(Settings.ACTION_SETTINGS))) return
        }
        if (open(context, appDetails(context)) || open(context, Intent(Settings.ACTION_SETTINGS))) return
        Toast.makeText(context, hint(), Toast.LENGTH_LONG).show()
    }

    private fun batteryExempt(context: Context): Boolean =
        context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName)

    // Android's own switch, for phones without a maker switch. Not asked for on
    // the phones that have one: on EMUI the maker switch is the one found to
    // matter, and one place to go is easier to follow than two.
    @SuppressLint("BatteryLife")
    private fun requestBatteryExemption(context: Context): Boolean {
        val ask = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.fromParts("package", context.packageName, null))
        return open(context, ask) || open(context, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    private fun openMakerSettings(context: Context): Boolean {
        for (intent in makerSettings()) {
            if (open(context, intent)) return true
        }
        return false
    }

    @Suppress("DEPRECATION")
    private fun open(context: Context, intent: Intent): Boolean {
        // Some OEMs open an empty resolver without throwing when an implicit
        // settings action has no handler. Launch only real, accessible pages,
        // and pin the component so a resolver is never mistaken for success.
        val targets = context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        if (targets.isEmpty()) Log.w("BackgroundRun", "No settings page for ${intent.component ?: intent.action}")
        for (target in targets) {
            val info = target.activityInfo ?: continue
            if (!info.enabled || !info.applicationInfo.enabled || !info.exported) {
                Log.w("BackgroundRun", "Settings page is disabled or not exported: ${info.name}")
                continue
            }
            if (info.permission != null && context.checkSelfPermission(info.permission) != PackageManager.PERMISSION_GRANTED) {
                Log.w("BackgroundRun", "Settings permission unavailable: ${info.permission} for ${info.name}")
                continue
            }
            val launch = Intent(intent).setComponent(ComponentName(info.packageName, info.name))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                context.startActivity(launch)
                return true
            } catch (error: ActivityNotFoundException) {
                Log.w("BackgroundRun", "Background settings page is unavailable: ${info.name}", error)
            } catch (error: SecurityException) {
                Log.w("BackgroundRun", "Background settings page denied access: ${info.name}", error)
            }
        }
        return false
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
            Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
            Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")),
            Intent("huawei.intent.action.HSM_STARTUPAPP_MANAGER").setPackage("com.huawei.systemmanager"),
        )
        maker() in setOf("xiaomi", "redmi") -> listOf(
            Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
        )
        else -> emptyList()
    }
}
