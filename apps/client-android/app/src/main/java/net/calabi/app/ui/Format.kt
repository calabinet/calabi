package net.calabi.app.ui

import android.content.Context
import android.text.format.DateFormat
import net.calabi.app.R
import java.time.Instant
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** 1.2 GB, 830 MB, 12 KB: binary units, like the web console. */
fun formatBytes(n: Long): String {
    val v = n.toDouble()
    fun fmt(x: Double, unit: String) = if (x >= 100) "%.0f %s".format(Locale.ROOT, x, unit) else "%.1f %s".format(Locale.ROOT, x, unit)
    return when {
        n >= 1L shl 40 -> fmt(v / (1L shl 40), "TB")
        n >= 1L shl 30 -> fmt(v / (1L shl 30), "GB")
        n >= 1L shl 20 -> fmt(v / (1L shl 20), "MB")
        n >= 1L shl 10 -> "%.0f KB".format(Locale.ROOT, v / (1L shl 10))
        else -> "$n B"
    }
}

/** An RFC 3339 timestamp from the control plane, or null. */
fun parseInstant(s: String): Instant? = try {
    if (s.isBlank()) null else OffsetDateTime.parse(s).toInstant()
} catch (_: Exception) {
    null
}

/** A calendar date in the viewer's zone and language: "Sep 12, 2026", "2026年9月12日". */
fun formatDate(context: Context, instant: Instant): String {
    val locale = context.resources.configuration.locales[0]
    val pattern = DateFormat.getBestDateTimePattern(locale, "yMMMd")
    return DateTimeFormatter.ofPattern(pattern, locale).format(instant.atZone(ZoneId.systemDefault()))
}

/** "Today 14:00", "Yesterday 09:00", "Sep 15 22:00" in the viewer's zone. */
fun formatRecent(context: Context, instant: Instant): String {
    val locale = context.resources.configuration.locales[0]
    val zone = ZoneId.systemDefault()
    val at = instant.atZone(zone)
    val time = DateTimeFormatter.ofPattern(DateFormat.getBestDateTimePattern(locale, if (DateFormat.is24HourFormat(context)) "Hm" else "hm"), locale).format(at)
    val today = LocalDate.now(zone)
    return when (at.toLocalDate()) {
        today -> context.getString(R.string.today_at, time)
        today.minusDays(1) -> context.getString(R.string.yesterday_at, time)
        else -> DateTimeFormatter.ofPattern(DateFormat.getBestDateTimePattern(locale, "MMMd"), locale).format(at) + " " + time
    }
}
