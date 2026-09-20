package net.calabi.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import net.calabi.app.R
import java.time.ZoneId
import java.time.format.TextStyle as DateTextStyle

/** The settings tab's usage card: this month against the cap, the last week, device seats. */
@Composable
fun UsageSection(model: AppModel) {
    LaunchedEffect(model.activeOrgId) {
        while (true) {
            model.refreshUsage()
            delay(60_000)
        }
    }
    SectionLabel(stringResource(R.string.usage_title))
    val u = model.usage
    when {
        u == null && model.usageError != null ->
            Text(model.usageError!!, color = Palette.danger, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 8.dp))
        u == null -> Group { Loading() }
        else -> {
            Group {
                u.month?.let { MonthBlock(it, u.plan, u.relayNotRecorded) }
                if (u.month == null && u.unavailable.isNotBlank()) {
                    Text(
                        stringResource(R.string.usage_unavailable_no_database), style = Styles.hint.copy(fontSize = 14.sp),
                        modifier = Modifier.padding(16.dp),
                    )
                }
                if (u.days.isNotEmpty()) {
                    if (u.month != null) RowDivider()
                    WeekChart(u.days)
                }
                u.devices?.let {
                    if (u.month != null || u.days.isNotEmpty() || u.unavailable.isNotBlank()) RowDivider()
                    DevicesRow(it)
                }
            }
            // A self-hosted server's month is this phone's; only calabi.net's runs on UTC.
            if (u.month != null && u.plan != "self_hosted") {
                Text(stringResource(R.string.usage_month_utc), style = Styles.hint, modifier = Modifier.padding(horizontal = 8.dp))
            }
        }
    }
}

@Composable
private fun MonthBlock(m: MonthUsage, plan: String, relayNotRecorded: Boolean) {
    Column(Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.usage_month), style = Styles.rowTitle, modifier = Modifier.weight(1f))
            planLabel(plan)?.let {
                Text(
                    it, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink,
                    modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(Palette.sunken).padding(horizontal = 8.dp, vertical = 3.dp),
                )
            }
        }
        val fraction = if (m.limitBytes > 0) m.usedBytes.toFloat() / m.limitBytes else 0f
        val tone = when {
            fraction >= 1f -> Palette.danger
            fraction >= 0.8f -> Palette.relayDot
            else -> Palette.accent
        }
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                formatBytes(m.usedBytes), fontFamily = Fonts.display, fontSize = 28.sp, fontWeight = FontWeight.Bold,
                letterSpacing = (-0.5).sp, color = Palette.ink,
            )
            val limit = when {
                m.limitBytes > 0 -> formatBytes(m.limitBytes)
                m.limitBytes < 0 -> stringResource(R.string.usage_unlimited)
                else -> null
            }
            limit?.let { Text(" / $it", fontSize = 15.sp, color = Palette.muted, modifier = Modifier.padding(start = 2.dp, bottom = 5.dp)) }
            Spacer(Modifier.weight(1f))
            if (m.limitBytes > 0) {
                Text("${(fraction * 100).toInt()}%", style = Styles.monoValue.copy(color = if (fraction >= 0.8f) tone else Palette.ink), modifier = Modifier.padding(bottom = 5.dp))
            }
        }
        if (m.limitBytes > 0) Meter(fraction, tone)
        if (m.limitBytes == 0L) Text(stringResource(R.string.usage_limit_unknown), style = Styles.hint)
        val relay = if (relayNotRecorded) stringResource(R.string.usage_relay_not_recorded) else stringResource(R.string.usage_relay, formatBytes(m.relayBytes))
        Text(
            stringResource(R.string.usage_tunnels, formatBytes(m.tunnelBytes)) + " · " + relay,
            style = Styles.hint.copy(fontSize = 13.sp),
        )
        if (m.selfHostedBytes > 0) Text(stringResource(R.string.usage_self_hosted, formatBytes(m.selfHostedBytes)), style = Styles.hint)
    }
}

@Composable
private fun Meter(fraction: Float, tone: Color) {
    Box(Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)).background(Palette.sunken)) {
        Box(Modifier.fillMaxWidth(fraction.coerceIn(0.015f, 1f)).fillMaxHeight().clip(RoundedCornerShape(4.dp)).background(tone))
    }
}

@Composable
private fun WeekChart(days: List<DayUsage>) {
    val context = LocalContext.current
    val locale = context.resources.configuration.locales[0]
    val max = days.maxOf { it.bytes }.coerceAtLeast(1)
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.usage_week), style = Styles.sectionLabel, modifier = Modifier.weight(1f))
            Text(formatBytes(days.sumOf { it.bytes }), style = Styles.mono)
        }
        Row(Modifier.fillMaxWidth().height(86.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            days.forEachIndexed { i, d ->
                val today = i == days.lastIndex
                Column(Modifier.weight(1f).fillMaxHeight(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.BottomCenter) {
                        val bar = if (d.bytes == 0L) 4.dp else (62f * d.bytes / max).dp.coerceAtLeast(6.dp)
                        Box(
                            Modifier.fillMaxWidth().height(bar).clip(RoundedCornerShape(6.dp))
                                .background(
                                    when {
                                        d.bytes == 0L -> Palette.divider
                                        today -> Palette.accent
                                        else -> Palette.accentSoft
                                    },
                                ),
                        )
                    }
                    val day = parseInstant(d.start)?.atZone(ZoneId.systemDefault())?.dayOfWeek?.getDisplayName(DateTextStyle.SHORT, locale).orEmpty()
                    Text(
                        day, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp),
                        fontWeight = if (today) FontWeight.Bold else FontWeight.Normal, color = if (today) Palette.ink else Palette.muted,
                    )
                }
            }
        }
    }
}

@Composable
private fun DevicesRow(d: SeatUsage) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(if (d.own) R.string.usage_devices_own else R.string.usage_devices), style = Styles.row)
            if (d.disabled > 0) Text(stringResource(R.string.usage_devices_disabled, d.disabled.toInt()), style = Styles.hint)
        }
        val value = when {
            d.limit > 0 -> "${d.used} / ${d.limit}"
            d.limit < 0 -> "${d.used} / " + stringResource(R.string.usage_unlimited)
            else -> "${d.used}"
        }
        Text(value, style = Styles.monoValue)
    }
}

@Composable
private fun planLabel(code: String): String? = when (code) {
    "free" -> stringResource(R.string.plan_free)
    "basic" -> stringResource(R.string.plan_basic)
    "pro" -> stringResource(R.string.plan_pro)
    "business" -> stringResource(R.string.plan_business)
    "enterprise" -> stringResource(R.string.plan_enterprise)
    "pro_gift" -> stringResource(R.string.plan_pro_gift)
    "self_hosted" -> stringResource(R.string.plan_self_hosted)
    else -> null
}
