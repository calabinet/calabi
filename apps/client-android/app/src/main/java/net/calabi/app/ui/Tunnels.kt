package net.calabi.app.ui

import android.content.Intent
import android.net.Uri
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONObject
import java.time.Instant

/**
 * A tunnel's state as the user should read it. A port of the web console's
 * effectiveState (web/console/src/lib/tunnelState.ts): the first rule that
 * matches wins. Keep the two in step.
 */
enum class TunnelState(@StringRes val label: Int) {
    AdminDisabled(R.string.tunnel_state_admin_disabled),
    Disabled(R.string.tunnel_state_disabled),
    Error(R.string.tunnel_state_error),
    Pending(R.string.tunnel_state_pending),
    Offline(R.string.tunnel_state_offline),
    Mismatch(R.string.tunnel_state_mismatch),
    UpstreamDown(R.string.tunnel_state_upstream_down),
    Unverified(R.string.tunnel_state_unverified),
    Active(R.string.tunnel_state_active);

    val color: Color
        get() = when (this) {
            Active -> Palette.accent
            Pending, Mismatch -> Palette.relayText
            Error, UpstreamDown, AdminDisabled -> Palette.danger
            // Unverified is "not checked", not a fault.
            Offline, Disabled, Unverified -> Palette.muted
        }

    val dot: Color get() = if (this == Pending || this == Mismatch) Palette.relayDot else if (color == Palette.muted) Palette.radioLine else color
}

/** A row of GET /v1/tunnels. */
data class Tunnel(
    val id: Long,
    val name: String,
    val type: String,
    val domain: String,
    val remotePort: Int,
    val edgeHost: String,
    val localAddr: String,
    val state: TunnelState,
    val statusReason: String,
    val edgeNodeId: Long,
    val edgeRegion: String,
    val edgeOwned: Boolean,
    val creatorEmail: String,
    val createdByMe: Boolean,
    val traffic30d: Long,
    val createdAt: String,
    /** On a self-hosted server: the device whose daemon serves it. */
    val deviceName: String = "",
    val selfHosted: Boolean = false,
) {
    /** How a visitor reaches it, formatted as the web console's list does; "" before an edge assigns one. */
    val address: String
        get() = when {
            domain.isNotBlank() -> if (type == "http" || type == "https") "https://$domain" else domain
            remotePort > 0 -> if (edgeHost.isNotBlank()) "$edgeHost:$remotePort" else ":$remotePort"
            else -> ""
        }

    val openable: Boolean get() = domain.isNotBlank() && (type == "http" || type == "https")
}

fun parseTunnel(o: JSONObject): Tunnel {
    val status = o.optString("status")
    val edge = o.optLong("edge_node_id")
    val clientId = o.optLong("client_id")
    val clientOnline = o.optBoolean("client_online")
    val clientEdge = o.optLong("client_edge_node_id")
    val upstream = o.optString("upstream_state")
    val selfHosted = o.optBoolean("self_hosted")
    val state = when {
        // A self-hosted server's tunnels are what their daemon last reported;
        // nobody there checks the upstream, so reported online is as far as it goes.
        selfHosted -> when (status) {
            "online" -> TunnelState.Active
            "pending" -> TunnelState.Pending
            else -> TunnelState.Offline
        }
        o.optBoolean("disabled_by_admin") -> TunnelState.AdminDisabled
        status == "disabled" -> TunnelState.Disabled
        status == "error" -> TunnelState.Error
        edge == 0L -> TunnelState.Pending
        status == "offline" -> TunnelState.Offline
        clientId != 0L && !clientOnline -> TunnelState.Offline
        clientId != 0L && clientOnline && clientEdge != 0L && clientEdge != edge -> TunnelState.Mismatch
        clientOnline && upstream == "unhealthy" -> TunnelState.UpstreamDown
        upstream != "healthy" -> TunnelState.Unverified
        else -> TunnelState.Active
    }
    return Tunnel(
        id = o.optLong("id"), name = o.optString("name"), type = o.optString("type").lowercase(),
        domain = o.optString("domain"), remotePort = o.optInt("remote_port"), edgeHost = o.optString("edge_host"),
        localAddr = o.optString("local_addr"), state = state, statusReason = o.optString("status_reason"),
        edgeNodeId = edge, edgeRegion = o.optString("edge_region"), edgeOwned = o.optBoolean("edge_owned"),
        creatorEmail = o.optString("creator_email"), createdByMe = o.optBoolean("created_by_me"),
        traffic30d = o.optLong("traffic_30d"), createdAt = o.optString("created_at"),
        deviceName = o.optString("device_name"), selfHosted = selfHosted,
    )
}

@Composable
fun TunnelsTab(model: AppModel, onOpen: (Tunnel) -> Unit) {
    LaunchedEffect(model.activeOrgId) {
        while (true) {
            model.refreshTunnels()
            delay(15_000)
        }
    }
    val tunnels = model.tunnels
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 20.dp)) {
        item {
            Row(Modifier.fillMaxWidth().padding(start = 6.dp, end = 6.dp), verticalAlignment = Alignment.Bottom) {
                Text(stringResource(R.string.tunnels_title), style = Styles.screenTitle, modifier = Modifier.weight(1f))
                if (!tunnels.isNullOrEmpty()) {
                    Text(
                        stringResource(R.string.devices_online, tunnels.count { it.state == TunnelState.Active }, tunnels.size),
                        fontSize = 13.sp, color = Palette.muted, modifier = Modifier.padding(bottom = 6.dp),
                    )
                }
            }
        }
        if (model.seesOnlyOwnTunnels) {
            item { Text(stringResource(R.string.tunnels_scope_own), style = Styles.hint, modifier = Modifier.padding(start = 6.dp, top = 2.dp)) }
        }
        if (model.selfHosted) {
            item { Text(stringResource(R.string.tunnels_scope_self_hosted), style = Styles.hint, modifier = Modifier.padding(start = 6.dp, top = 2.dp)) }
        }
        item { Spacer(Modifier.height(14.dp)) }
        model.tunnelsError?.let { err ->
            item { Text(err, color = Palette.danger, fontSize = 13.sp, modifier = Modifier.padding(start = 6.dp, bottom = 8.dp)) }
        }
        when {
            // Said in full on the devices tab, so here it is only why this list
            // is empty — never a second copy of the same error.
            model.unreachable -> item {
                Group {
                    Text(
                        stringResource(R.string.unreachable_short), style = Styles.hint.copy(fontSize = 14.sp),
                        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(24.dp),
                    )
                }
            }
            tunnels == null && model.tunnelsError == null -> item { Loading() }
            tunnels != null && tunnels.isEmpty() -> item {
                Group {
                    Text(
                        stringResource(if (model.selfHosted) R.string.tunnels_empty_self_hosted else R.string.tunnels_empty),
                        style = Styles.hint.copy(fontSize = 14.sp),
                        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(24.dp),
                    )
                }
            }
        }
        itemsIndexed(tunnels.orEmpty(), key = { _, t -> t.id }) { i, t ->
            TunnelRow(t, first = i == 0, last = i == tunnels!!.lastIndex) { onOpen(t) }
        }
    }
}

@Composable
private fun TunnelRow(t: Tunnel, first: Boolean, last: Boolean, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(groupRowShape(first, last))
            .background(Palette.surface)
            .padding(top = if (first) 4.dp else 0.dp, bottom = if (last) 4.dp else 0.dp),
    ) {
        Row(
            Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TypeBadge(t.type, dim = t.state != TunnelState.Active)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    t.name, style = Styles.rowTitle.copy(color = if (t.state == TunnelState.Active) Palette.ink else Palette.muted),
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Text(
                    t.address.ifBlank { t.localAddr }, style = Styles.mono, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                StateLabel(t.state)
                if (t.traffic30d > 0) Text(formatBytes(t.traffic30d), style = Styles.mono.copy(fontSize = 11.sp))
            }
        }
        if (!last) RowDivider(start = 68.dp)
    }
}

@Composable
private fun TypeBadge(type: String, dim: Boolean) {
    Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(Palette.sunken),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            type.uppercase().ifBlank { "—" }, fontFamily = Fonts.mono, fontSize = 10.sp, fontWeight = FontWeight.SemiBold,
            color = if (dim) Palette.muted else Palette.ink, maxLines = 1,
        )
    }
}

@Composable
private fun StateLabel(state: TunnelState) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Dot(state.dot, 6.dp)
        Text(stringResource(state.label), fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = state.color, maxLines = 1)
    }
}

@Composable
fun TunnelDetailScreen(model: AppModel, opened: Tunnel, onBack: () -> Unit, onAccess: () -> Unit) {
    val context = LocalContext.current
    // The list keeps refreshing underneath; show its latest copy of this tunnel.
    val t = model.tunnels?.firstOrNull { it.id == opened.id } ?: opened
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        TopBar(onBack)
        Column(Modifier.padding(start = 6.dp, end = 6.dp, top = 6.dp, bottom = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(t.name, style = Styles.screenTitle, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Tag(t.type.uppercase(), Palette.ink, Palette.avatar, mono = true)
                Tag(stringResource(t.state.label), t.state.color, t.state.dot.copy(alpha = 0.16f))
            }
            reasonText(t)?.let { Text(it, style = Styles.hint.copy(fontSize = 13.sp, color = t.state.color)) }
        }

        Group {
            Column(Modifier.padding(16.dp)) {
                Text(stringResource(R.string.tunnel_address), style = Styles.sectionLabel)
                SelectionContainer {
                    Text(
                        t.address.ifBlank { stringResource(R.string.tunnel_no_address) },
                        style = if (t.address.isBlank()) Styles.row.copy(color = Palette.muted) else Styles.monoValue.copy(fontSize = 16.sp),
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
                if (t.address.isNotBlank()) {
                    Row(Modifier.padding(top = 14.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Pill(onClick = { copyToClipboard(context, t.address) }) {
                            Glyph(R.drawable.ic_copy, Palette.ink, 14.dp)
                            Text(stringResource(R.string.action_copy), style = Styles.chip)
                        }
                        Pill(onClick = {
                            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, t.address)
                            context.startActivity(Intent.createChooser(send, null))
                        }) {
                            Glyph(R.drawable.ic_share, Palette.ink, 14.dp)
                            Text(stringResource(R.string.action_share), style = Styles.chip)
                        }
                        if (t.openable) {
                            Pill(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(t.address))) }) {
                                Glyph(R.drawable.ic_open, Palette.ink, 14.dp)
                                Text(stringResource(R.string.action_open), style = Styles.chip)
                            }
                        }
                    }
                }
            }
        }

        Group {
            InfoRow(stringResource(R.string.tunnel_local), t.localAddr.ifBlank { "—" }, mono = true)
            RowDivider()
            InfoRow(stringResource(R.string.tunnel_served_by), servedBy(t))
            if (t.deviceName.isNotBlank()) {
                RowDivider()
                InfoRow(stringResource(R.string.tunnel_device), t.deviceName)
            }
            RowDivider()
            InfoRow(stringResource(R.string.tunnel_traffic_30d), formatBytes(t.traffic30d), mono = true)
            if (t.createdByMe || t.creatorEmail.isNotBlank()) {
                RowDivider()
                InfoRow(stringResource(R.string.tunnel_creator), if (t.createdByMe) stringResource(R.string.tunnel_creator_me) else t.creatorEmail)
            }
            parseInstant(t.createdAt)?.let {
                RowDivider()
                InfoRow(stringResource(R.string.tunnel_created), formatDate(context, it))
            }
        }

        // A self-hosted server keeps no access log.
        if (!t.selfHosted) {
            Group {
                ActionRow(stringResource(R.string.access_title), onClick = onAccess) {
                    Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
                }
            }
        }
    }
}

@Composable
private fun reasonText(t: Tunnel): String? {
    val r = t.statusReason
    return when {
        r.isBlank() || t.state == TunnelState.Active -> null
        r.startsWith("port_in_use:") -> stringResource(R.string.tunnel_port_in_use, r.substringAfter(':'))
        else -> r
    }
}

@Composable
private fun servedBy(t: Tunnel): String = when {
    t.edgeNodeId == 0L -> "—"
    t.edgeRegion.isNotBlank() -> regionNames[t.edgeRegion]?.let { stringResource(it) } ?: t.edgeRegion
    t.edgeOwned -> stringResource(R.string.served_self_hosted)
    else -> stringResource(R.string.served_platform)
}

/** One hour's count of connections from one address with one outcome. */
private data class AccessRow(val hour: Instant, val visitor: String, val outcome: String, val conns: Long)

private data class AccessLog(val rows: List<AccessRow>, val recordsDisabled: Boolean, val retentionDays: Int)

private const val ACCESS_LIMIT = 1000

@Composable
fun TunnelAccessScreen(tunnel: Tunnel, onBack: () -> Unit) {
    val context = LocalContext.current
    var hours by rememberSaveable { mutableIntStateOf(24) }
    var reload by remember { mutableIntStateOf(0) }
    var log by remember { mutableStateOf<AccessLog?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val failed = stringResource(R.string.load_failed)

    // Loaded when asked, never on a timer: every read is audited upstream.
    LaunchedEffect(hours, reload) {
        log = null
        error = null
        val from = Instant.now().minusSeconds(hours * 3600L).toString()
        val r = CoreClient.call("GET", "/v1/tunnels/${tunnel.id}/access?from=$from&limit=$ACCESS_LIMIT")
        if (!r.ok) {
            error = r.error(failed)
            return@LaunchedEffect
        }
        val o = r.json()
        val items = o.optJSONArray("items")
        val rows = ArrayList<AccessRow>()
        if (items != null) for (i in 0 until items.length()) {
            val it = items.getJSONObject(i)
            val hour = parseInstant(it.optString("hour")) ?: continue
            rows += AccessRow(hour, it.optString("visitor_ip"), it.optString("outcome"), it.optLong("conns"))
        }
        log = AccessLog(rows, o.optBoolean("records_disabled"), o.optInt("retention_days"))
    }

    val current = log
    val byHour = current?.rows.orEmpty().groupBy { it.hour }.toSortedMap(compareByDescending { it })
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 20.dp)) {
        item {
            TopBar(onBack) {
                CircleButton(R.drawable.ic_refresh, stringResource(R.string.refresh)) { reload++ }
            }
        }
        item {
            Column(Modifier.padding(start = 6.dp, end = 6.dp, top = 16.dp, bottom = 14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.access_title), style = Styles.screenTitle)
                Text(tunnel.name, style = Styles.hint.copy(fontSize = 13.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Segment(stringResource(R.string.access_range_24h), hours == 24) { hours = 24 }
                Segment(stringResource(R.string.access_range_7d), hours == 168) { hours = 168 }
            }
        }
        item { Spacer(Modifier.height(12.dp)) }
        when {
            error != null -> item { Text(error!!, color = Palette.danger, fontSize = 13.sp, modifier = Modifier.padding(start = 6.dp)) }
            current == null -> item { Loading() }
            current.recordsDisabled -> item { Notice(stringResource(R.string.access_records_off)) }
            else -> {
                item {
                    val rows = current.rows
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Tile(stringResource(R.string.access_conns), rows.sumOf { it.conns }.toString(), Palette.ink, Modifier.weight(1f))
                        val blocked = rows.filter { it.outcome != "allowed" }.sumOf { it.conns }
                        Tile(stringResource(R.string.access_blocked), blocked.toString(), if (blocked > 0) Palette.danger else Palette.ink, Modifier.weight(1f))
                        Tile(
                            stringResource(R.string.access_visitors),
                            rows.mapNotNull { it.visitor.ifBlank { null } }.toSet().size.toString(), Palette.ink, Modifier.weight(1f),
                        )
                    }
                }
                item {
                    val notes = buildList {
                        add(stringResource(R.string.access_note))
                        if (current.retentionDays > 0) add(stringResource(R.string.access_retention, current.retentionDays))
                        if (current.rows.size >= ACCESS_LIMIT) add(stringResource(R.string.access_truncated, ACCESS_LIMIT))
                    }
                    Text(notes.joinToString(" "), style = Styles.hint, modifier = Modifier.padding(start = 6.dp, end = 6.dp, top = 10.dp))
                }
                if (current.rows.isEmpty()) {
                    item { Spacer(Modifier.height(12.dp)) }
                    item { Notice(stringResource(R.string.access_empty)) }
                }
                byHour.forEach { (hour, rows) ->
                    item(key = "h$hour") {
                        Text(
                            formatRecent(context, hour), style = Styles.sectionLabel,
                            modifier = Modifier.padding(start = 6.dp, top = 18.dp, bottom = 8.dp),
                        )
                    }
                    itemsIndexed(rows, key = { i, r -> "$hour/${r.visitor}/${r.outcome}/$i" }) { i, r ->
                        AccessItem(r, first = i == 0, last = i == rows.lastIndex)
                    }
                }
            }
        }
    }
}

@Composable
private fun AccessItem(r: AccessRow, first: Boolean, last: Boolean) {
    val allowed = r.outcome == "allowed"
    Column(
        Modifier
            .fillMaxWidth()
            .clip(groupRowShape(first, last))
            .background(Palette.surface)
            .padding(top = if (first) 2.dp else 0.dp, bottom = if (last) 2.dp else 0.dp),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Dot(if (allowed) Palette.accent else Palette.danger, 6.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                if (r.visitor.isBlank()) {
                    Text(stringResource(R.string.access_other), style = Styles.row.copy(color = Palette.muted))
                } else {
                    Text(r.visitor, style = Styles.mono.copy(fontSize = 14.sp, color = Palette.ink), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                if (!allowed) Text(stringResource(outcomeLabel(r.outcome)), fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = Palette.danger)
            }
            Text(r.conns.toString(), style = Styles.monoValue)
        }
        if (!last) RowDivider(start = 32.dp)
    }
}

@StringRes
private fun outcomeLabel(outcome: String): Int = when (outcome) {
    "denied_ip" -> R.string.access_outcome_denied_ip
    "denied_auth" -> R.string.access_outcome_denied_auth
    "denied_rate" -> R.string.access_outcome_denied_rate
    else -> R.string.access_outcome_allowed
}

@Composable
private fun Tile(label: String, value: String, color: Color, modifier: Modifier) {
    Column(
        modifier.clip(RoundedCornerShape(18.dp)).background(Palette.surface).padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(value, fontFamily = Fonts.display, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = color, maxLines = 1)
        Text(label, style = Styles.hint, maxLines = 1)
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = Styles.row.copy(color = Palette.muted))
        Text(
            value, style = if (mono) Styles.mono.copy(fontSize = 14.sp, color = Palette.ink) else Styles.row,
            textAlign = TextAlign.End, maxLines = 2, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 16.dp).weight(1f),
        )
    }
}

/** A small rounded label: a tunnel's type or state. */
@Composable
private fun Tag(text: String, fg: Color, bg: Color, mono: Boolean = false) {
    Text(
        text, color = fg, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, fontFamily = if (mono) Fonts.mono else Fonts.display,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(bg).padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

/** Rounded corners at the ends of a group drawn row by row in a lazy list. */
fun groupRowShape(first: Boolean, last: Boolean): Shape = when {
    first && last -> RoundedCornerShape(22.dp)
    first -> RoundedCornerShape(topStart = 22.dp, topEnd = 22.dp)
    last -> RoundedCornerShape(bottomStart = 22.dp, bottomEnd = 22.dp)
    else -> RectangleShape
}

@Composable
fun Loading() {
    Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.size(28.dp), color = Palette.accent, strokeWidth = 3.dp)
    }
}

@Composable
private fun Notice(text: String) {
    Group {
        Text(
            text, style = Styles.hint.copy(fontSize = 14.sp), textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth().padding(24.dp),
        )
    }
}
