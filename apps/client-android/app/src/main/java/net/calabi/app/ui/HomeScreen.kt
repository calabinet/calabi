package net.calabi.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import net.calabi.app.R
import org.json.JSONObject

private enum class Sheet { Exit, Org, Replace }

/** A screen opened from a tab, drawn in its place with a back button. */
private sealed interface Route {
    data class TunnelDetail(val tunnel: Tunnel) : Route
    data class TunnelAccess(val tunnel: Tunnel) : Route
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(onConnect: () -> Unit, onDisconnect: () -> Unit, onSignedOut: () -> Unit) {
    val model = remember { AppModel() }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var sheet by remember { mutableStateOf<Sheet?>(null) }
    var route by remember { mutableStateOf<Route?>(null) }

    LaunchedEffect(Unit) { model.refreshAccount() }
    // Live state every 2s while the screen is up; the org's device list less often.
    LaunchedEffect(Unit) {
        var tick = 0
        while (true) {
            model.refreshLive()
            if (tick % 5 == 0) model.refreshNodes()
            if (tick % 30 == 0) model.refreshReplaceable()
            tick++
            delay(2000)
        }
    }

    BackHandler(enabled = route != null) {
        route = when (val r = route) {
            is Route.TunnelAccess -> Route.TunnelDetail(r.tunnel)
            else -> null
        }
    }

    Scaffold(containerColor = Palette.ground, bottomBar = { if (route == null) BottomNav(tab) { tab = it } }) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (val r = route) {
                is Route.TunnelDetail -> TunnelDetailScreen(
                    model, r.tunnel, onBack = { route = null }, onAccess = { route = Route.TunnelAccess(r.tunnel) },
                )
                is Route.TunnelAccess -> TunnelAccessScreen(r.tunnel, onBack = { route = Route.TunnelDetail(r.tunnel) })
                null -> when (tab) {
                    0 -> DevicesTab(
                        model, onConnect, onDisconnect,
                        onPickExit = { sheet = Sheet.Exit }, onPickOrg = { sheet = Sheet.Org }, onAccount = { tab = 2 },
                        onReplace = { sheet = Sheet.Replace },
                    )
                    1 -> TunnelsTab(model) { route = Route.TunnelDetail(it) }
                    else -> SettingsTab(model, onSignedOut, onReplace = { sheet = Sheet.Replace })
                }
            }
        }
    }

    if (sheet != null) {
        ModalBottomSheet(onDismissRequest = { sheet = null }, containerColor = Palette.ground) {
            Column(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                when (sheet) {
                    Sheet.Exit -> {
                        SheetTitle(stringResource(R.string.settings_exit), stringResource(R.string.settings_exit_hint))
                        ExitChoices(model) { sheet = null }
                    }
                    Sheet.Org -> {
                        SheetTitle(stringResource(R.string.settings_org), stringResource(R.string.settings_org_hint))
                        Group { OrgChoices(model) { sheet = null } }
                    }
                    Sheet.Replace -> {
                        SheetTitle(stringResource(R.string.replace_title), stringResource(R.string.replace_hint))
                        ReplaceChoices(model) { sheet = null }
                    }
                    null -> {}
                }
            }
        }
    }
}

@Composable
private fun SheetTitle(title: String, hint: String) {
    Column(Modifier.padding(horizontal = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = Styles.section)
        Text(hint, style = Styles.hint.copy(fontSize = 13.sp))
    }
}

@Composable
private fun DevicesTab(
    model: AppModel,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onPickExit: () -> Unit,
    onPickOrg: () -> Unit,
    onAccount: () -> Unit,
    onReplace: () -> Unit,
) {
    val devices = model.devices
    val inUseExit = model.connection?.exitNode.orEmpty().ifBlank { model.exitNode }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 20.dp)) {
        item { Header(model, onPickOrg, onAccount) }
        item { Hero(model, onConnect, onDisconnect, onPickExit) }
        item { StoppedPrompt(model) }
        item { ReplacePrompt(model, onReplace) }
        item { CertChangedPrompt(model) }
        item { ApprovalPrompt(model) }
        item { TilePrompt(model) }
        if (model.nodes != null || model.nodesError != null) {
            item {
                Row(
                    Modifier.fillMaxWidth().padding(start = 22.dp, end = 22.dp, top = 6.dp, bottom = 10.dp),
                    verticalAlignment = Alignment.Bottom,
                ) {
                    Text(stringResource(R.string.devices_title), style = Styles.section, modifier = Modifier.weight(1f))
                    if (devices.isNotEmpty()) {
                        Text(
                            stringResource(R.string.devices_online, devices.count { it.online }, devices.size),
                            fontSize = 13.sp, color = Palette.muted,
                        )
                    }
                }
            }
        }
        if (model.nodesNeedConnection) {
            item {
                Group(Modifier.padding(horizontal = 16.dp)) {
                    Text(
                        stringResource(R.string.devices_connect_to_see), style = Styles.hint.copy(fontSize = 14.sp),
                        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(24.dp),
                    )
                }
            }
        }
        model.nodesError?.let { err ->
            item { Text(err, color = Palette.danger, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 22.dp, vertical = 4.dp)) }
        }
        if (model.nodes != null && devices.isEmpty()) {
            item {
                Group(Modifier.padding(horizontal = 16.dp)) {
                    Text(
                        stringResource(R.string.devices_empty), style = Styles.hint.copy(fontSize = 14.sp),
                        textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(24.dp),
                    )
                }
            }
        }
        itemsIndexed(devices, key = { _, d -> d.overlay + d.name }) { i, d ->
            DeviceRow(d, first = i == 0, last = i == devices.lastIndex, isExit = d.name == inUseExit || d.overlay == inUseExit)
        }
    }
}

@Composable
private fun Header(model: AppModel, onPickOrg: () -> Unit, onAccount: () -> Unit) {
    val org = model.activeOrg
    val orgLabel = when {
        // The self-hosted server stands where the organization would.
        model.selfHosted -> model.server.substringBeforeLast(':')
        org == null -> ""
        org.personal -> stringResource(R.string.settings_org_personal)
        else -> org.name
    }
    val canSwitch = model.orgs.size > 1
    Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        if (orgLabel.isNotBlank()) {
            val shape = RoundedCornerShape(22.dp)
            Row(
                Modifier
                    .height(44.dp)
                    .clip(shape)
                    .background(Palette.surface)
                    .border(1.dp, Palette.line, shape)
                    // The server has no switcher; it opens the settings that say where this phone is.
                    .clickable(
                        enabled = canSwitch || model.selfHosted, role = Role.Button,
                        onClick = if (model.selfHosted) onAccount else onPickOrg,
                    )
                    .padding(start = 6.dp, end = if (canSwitch) 12.dp else 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(Modifier.size(32.dp).background(Palette.ink, CircleShape), contentAlignment = Alignment.Center) {
                    if (model.selfHosted) {
                        Glyph(R.drawable.ic_server, Palette.ground, 16.dp)
                    } else {
                        Text(orgLabel.take(1).uppercase(), color = Palette.ground, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    }
                }
                Text(
                    orgLabel, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 200.dp),
                )
                if (canSwitch) Glyph(R.drawable.ic_chevron_down, Palette.ink, 16.dp)
            }
        }
        Spacer(Modifier.weight(1f))
        // No account on a self-hosted server: the chip above is all there is to say.
        if (!model.selfHosted) {
            val account = stringResource(R.string.account)
            Box(
                Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(Palette.avatar)
                    .clickable(role = Role.Button, onClick = onAccount)
                    .semantics { contentDescription = account },
                contentAlignment = Alignment.Center,
            ) {
                Text(model.email.take(1).uppercase(), fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Palette.ink)
            }
        }
    }
}

private enum class Phase { Off, Busy, On, Problem }

@Composable
private fun Hero(model: AppModel, onConnect: () -> Unit, onDisconnect: () -> Unit, onPickExit: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val c = model.connection
    val phase = when {
        !model.connected -> Phase.Off
        c?.state == "connected" -> Phase.On
        c?.state in setOf("not_enrolled", "signed_out", "needs_invite", "disabled", "cert_changed") -> Phase.Problem
        else -> Phase.Busy
    }
    val title = when (phase) {
        Phase.Off -> stringResource(R.string.state_stopped)
        Phase.On -> stringResource(R.string.state_connected)
        Phase.Problem -> stringResource(
            when (c?.state) {
                "signed_out" -> R.string.state_signed_out_short
                "needs_invite" -> R.string.state_needs_invite_short
                "disabled" -> R.string.state_disabled_short
                "cert_changed" -> R.string.state_cert_changed_short
                else -> R.string.state_not_enrolled_short
            },
        )
        Phase.Busy -> stringResource(if (c?.state == "retrying") R.string.state_retrying else R.string.state_connecting)
    }
    val subtitle = when (phase) {
        Phase.Off -> stringResource(R.string.hero_tap_to_connect)
        Phase.On -> "${c?.name.orEmpty()} · ${c?.overlay.orEmpty()}"
        Phase.Problem -> stringResource(
            when (c?.state) {
                "signed_out" -> R.string.state_signed_out
                "needs_invite" -> R.string.state_needs_invite
                "disabled" -> R.string.state_disabled
                "cert_changed" -> R.string.state_cert_changed
                else -> R.string.state_not_enrolled
            },
        )
        Phase.Busy -> c?.error.orEmpty()
    }
    val action = stringResource(if (phase == Phase.Off) R.string.action_connect else R.string.action_disconnect)

    Column(
        Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 28.dp, bottom = 18.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        val ring = when (phase) {
            Phase.Off -> Palette.offRing
            Phase.Problem -> Palette.dangerSoft
            else -> Palette.accentSoft
        }
        Box(
            Modifier
                .size(152.dp)
                .clip(CircleShape)
                .background(ring)
                .clickable(role = Role.Button, onClick = { if (phase == Phase.Off) onConnect() else onDisconnect() })
                .semantics { contentDescription = action },
            contentAlignment = Alignment.Center,
        ) {
            if (phase == Phase.Busy) {
                CircularProgressIndicator(Modifier.size(136.dp), color = Palette.accent, strokeWidth = 3.dp, trackColor = Color.Transparent)
            }
            val inner = Modifier.size(118.dp)
            when (phase) {
                Phase.On -> Box(
                    inner.shadow(14.dp, CircleShape, ambientColor = Palette.accent, spotColor = Palette.accent)
                        .background(Palette.accent, CircleShape),
                    contentAlignment = Alignment.Center,
                ) { Glyph(R.drawable.ic_power, Color.White, 44.dp) }
                Phase.Off -> Box(
                    inner.background(Palette.surface, CircleShape).border(1.dp, Palette.fieldLine, CircleShape),
                    contentAlignment = Alignment.Center,
                ) { Glyph(R.drawable.ic_power, Palette.ink, 44.dp) }
                Phase.Busy -> Box(inner.background(Palette.surface, CircleShape), contentAlignment = Alignment.Center) {
                    Glyph(R.drawable.ic_power, Palette.accent, 44.dp)
                }
                Phase.Problem -> Box(inner.background(Palette.surface, CircleShape), contentAlignment = Alignment.Center) {
                    Glyph(R.drawable.ic_power, Palette.danger, 44.dp)
                }
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = Styles.heroState, color = if (phase == Phase.Problem) Palette.danger else Palette.ink)
            // Always laid out, so the chips below do not jump while connecting.
            Text(
                subtitle,
                style = if (phase == Phase.On) Styles.mono.copy(fontSize = 13.sp) else Styles.hint.copy(fontSize = 13.sp),
                textAlign = TextAlign.Center, maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
        val candidates = model.devices.filter { it.offersExit }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (model.exitNode.isNotBlank() || candidates.isNotEmpty()) {
                Pill(onClick = onPickExit) {
                    Glyph(R.drawable.ic_globe, if (model.exitNode.isNotBlank()) Palette.accent else Palette.muted, 16.dp)
                    Text(
                        if (model.exitNode.isNotBlank()) stringResource(R.string.chip_exit, model.exitNode)
                        else stringResource(R.string.chip_exit_none),
                        style = Styles.chip, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 160.dp),
                    )
                    Glyph(R.drawable.ic_chevron_right, Palette.ink, 14.dp)
                }
            }
            val routesOn = stringResource(R.string.routes_on)
            val routesOff = stringResource(R.string.routes_off)
            val failed = stringResource(R.string.settings_save_failed)
            Pill(onClick = {
                val next = !model.acceptRoutes
                scope.launch {
                    val r = model.saveSettings(JSONObject().put("accept_routes", next))
                    toast(context, if (r.ok) (if (next) routesOn else routesOff) else r.error(failed))
                }
            }) {
                Dot(if (model.acceptRoutes) Palette.accent else Palette.radioLine)
                Text(stringResource(R.string.chip_routes), style = Styles.chip)
            }
        }
    }
}

@Composable
private fun DeviceRow(d: Device, first: Boolean, last: Boolean, isExit: Boolean) {
    val context = LocalContext.current
    val shape = groupRowShape(first, last)
    Column(
        Modifier
            .padding(horizontal = 16.dp)
            .fillMaxWidth()
            .clip(shape)
            .background(Palette.surface)
            .padding(top = if (first) 4.dp else 0.dp, bottom = if (last) 4.dp else 0.dp),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .clickable { copyToClipboard(context, d.overlay) }
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(Palette.sunken),
                contentAlignment = Alignment.Center,
            ) { Glyph(osIcon(d.os), if (d.online) Palette.ink else Palette.muted, 20.dp) }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        d.name, style = Styles.rowTitle.copy(color = if (d.online) Palette.ink else Palette.muted),
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false),
                    )
                    if (isExit) {
                        Text(
                            stringResource(R.string.badge_exit), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Palette.accent,
                            modifier = Modifier.background(Palette.accentSoft, RoundedCornerShape(6.dp)).padding(horizontal = 6.dp, vertical = 1.dp),
                        )
                    }
                }
                val os = osName(d.os)
                Text(if (os.isBlank()) d.overlay else "${d.overlay} · $os", style = Styles.mono, maxLines = 1)
            }
            Trailing(d)
        }
        if (!last) RowDivider(start = 68.dp)
    }
}

@Composable
private fun Trailing(d: Device) {
    if (!d.online) {
        Text(stringResource(R.string.device_offline), fontSize = 12.sp, color = Palette.muted)
        return
    }
    val relay = d.path == "relay"
    val label = when (d.path) {
        "direct" -> stringResource(R.string.path_direct)
        "relay" -> stringResource(R.string.path_relay)
        else -> stringResource(R.string.device_online)
    }
    Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        if (d.path != null && d.rttMicros > 0) {
            Text(stringResource(R.string.rtt_ms, (d.rttMicros / 1000).toInt()), style = Styles.monoValue)
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            Dot(if (relay) Palette.relayDot else Palette.accent, 6.dp)
            Text(
                label, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
                color = when {
                    relay -> Palette.relayText
                    d.path == null -> Palette.muted
                    else -> Palette.accent
                },
            )
        }
    }
}

/** The exit-device choices, shared by the sheet and the settings tab. */
@Composable
fun ExitChoices(model: AppModel, onPicked: () -> Unit = {}) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val failed = stringResource(R.string.settings_save_failed)
    val candidates = model.devices.filter { it.offersExit }
    fun pick(value: String) {
        scope.launch {
            val r = model.saveSettings(JSONObject().put("exit_node", value))
            if (!r.ok) toast(context, r.error(failed))
            onPicked()
        }
    }
    Group {
        ChoiceRow(stringResource(R.string.settings_exit_none), selected = model.exitNode.isBlank()) { pick("") }
        candidates.forEach { d ->
            RowDivider()
            ChoiceRow(d.name, selected = model.exitNode == d.name || model.exitNode == d.overlay, detail = pathDetail(d)) { pick(d.name) }
        }
    }
    if (candidates.isEmpty()) {
        val empty = when {
            // A self-hosted server's devices come from the live session.
            model.selfHosted && model.nodesNeedConnection -> R.string.settings_exit_connect
            model.selfHosted -> R.string.settings_exit_empty_server
            else -> R.string.settings_exit_empty
        }
        Text(stringResource(empty), style = Styles.hint, modifier = Modifier.padding(horizontal = 8.dp))
    }
}

/** The organization choices, shared by the sheet and the settings tab. */
@Composable
fun OrgChoices(model: AppModel, onPicked: () -> Unit = {}) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val failed = stringResource(R.string.settings_save_failed)
    val personal = stringResource(R.string.settings_org_personal)
    model.orgs.forEach { org ->
        ChoiceRow(if (org.personal) personal else org.name, selected = org.id == model.activeOrgId) {
            scope.launch {
                val r = model.switchOrg(org.id)
                if (!r.ok) toast(context, r.error(failed))
                onPicked()
            }
        }
    }
}

@Composable
private fun pathDetail(d: Device): String? {
    val ms = (d.rttMicros / 1000).toInt()
    return when {
        !d.online -> stringResource(R.string.device_offline)
        d.path == "direct" -> if (ms > 0) stringResource(R.string.path_rtt, stringResource(R.string.path_direct), ms) else stringResource(R.string.path_direct)
        d.path == "relay" -> if (ms > 0) stringResource(R.string.path_rtt, stringResource(R.string.path_relay), ms) else stringResource(R.string.path_relay)
        else -> null
    }
}

private fun osIcon(os: String): Int = when (os) {
    "windows" -> R.drawable.ic_monitor
    "darwin" -> R.drawable.ic_laptop
    "android", "ios" -> R.drawable.ic_phone
    else -> R.drawable.ic_server
}

private fun osName(os: String): String = when (os) {
    "linux" -> "Linux"
    "windows" -> "Windows"
    "darwin" -> "macOS"
    "android" -> "Android"
    "ios" -> "iOS"
    else -> os
}

/** Joined, and waiting for the server's administrator to approve this phone. */
@Composable
private fun ApprovalPrompt(model: AppModel) {
    if (!model.selfHosted || !model.awaitingApproval) return
    Group(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.approval_title), style = Styles.rowTitle)
            Text(stringResource(R.string.approval_body), style = Styles.hint.copy(fontSize = 13.sp))
        }
    }
}
