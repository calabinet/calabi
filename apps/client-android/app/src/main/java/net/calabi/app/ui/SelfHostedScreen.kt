package net.calabi.app.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import net.calabi.app.ApiResult
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONObject

/**
 * Joining a self-hosted server instead of calabi.net
 * (docs/runbook/self-hosted-sign-in-plan.md §6.1): scan the invite its
 * administrator made with `calabi-coord invite`, or type the address and key.
 * [link] is an invite that arrived as a calabi://join link; it is joined as soon
 * as the screen opens.
 */
@Composable
fun SelfHostedScreen(link: String?, onBack: () -> Unit, onJoined: () -> Unit) {
    val scope = rememberCoroutineScope()
    var server by rememberSaveable { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    var pin by rememberSaveable { mutableStateOf("") }
    var plaintext by rememberSaveable { mutableStateOf(false) }
    var advanced by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // The certificate a person has to compare before the key is sent (§3.3).
    var confirm by remember { mutableStateOf<Confirm?>(null) }

    val messages = JoinMessages(
        failed = stringResource(R.string.sh_failed),
        keyRefused = stringResource(R.string.sh_key_refused),
        disabled = stringResource(R.string.sh_disabled),
        full = stringResource(R.string.sh_full),
        noTLS = stringResource(R.string.sh_no_tls),
        pinMismatch = stringResource(R.string.sh_pin_mismatch),
        unreachable = stringResource(R.string.sh_unreachable),
        notAnInvite = stringResource(R.string.sh_not_an_invite),
    )

    fun join(body: JSONObject) {
        if (busy) return
        busy = true
        error = null
        scope.launch {
            val r = CoreClient.call("POST", "/v1/selfhosted/join", body)
            busy = false
            if (r.ok) {
                onJoined()
                return@launch
            }
            val o = r.json()
            if (o.optString("code") == "untrusted") {
                confirm = Confirm(body, o.optString("pin"), o.optString("subject"))
            } else {
                error = messages.explain(r)
            }
        }
    }

    fun joinTyped() = join(
        JSONObject().put("server", server.trim()).put("key", key.trim()).put("pin", pin.trim()).put("plaintext", plaintext),
    )

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        if (text.startsWith("calabi://join")) join(JSONObject().put("link", text)) else error = messages.notAnInvite
    }
    val scanPrompt = stringResource(R.string.sh_scan_prompt)

    LaunchedEffect(link) { if (link != null) join(JSONObject().put("link", link)) }
    BackHandler(onBack = onBack)

    Column(
        Modifier
            .fillMaxSize()
            .background(Palette.ground)
            .safeDrawingPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp),
    ) {
        Spacer(Modifier.height(12.dp))
        Row(
            Modifier
                .heightIn(min = 44.dp)
                .clip(RoundedCornerShape(22.dp))
                .clickable(role = Role.Button, onClick = onBack)
                .padding(end = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Glyph(R.drawable.ic_chevron_left, Palette.ink, 22.dp)
            Text(stringResource(R.string.login_back), fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink)
        }
        Spacer(Modifier.height(28.dp))
        Text(stringResource(R.string.sh_title), style = Styles.screenTitle, color = Palette.ink)
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.sh_subtitle), fontSize = 15.sp, color = Palette.muted)
        Spacer(Modifier.height(28.dp))

        ScanButton(enabled = !busy) {
            scanner.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt(scanPrompt)
                    .setBeepEnabled(false)
                    .setOrientationLocked(false),
            )
        }

        Spacer(Modifier.height(28.dp))
        Text(stringResource(R.string.sh_or_type), style = Styles.section)
        Spacer(Modifier.height(14.dp))
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            LabeledField(
                label = stringResource(R.string.sh_server), value = server, onValueChange = { server = it },
                keyboardType = KeyboardType.Uri,
            )
            LabeledField(
                label = stringResource(R.string.sh_key), value = key, onValueChange = { key = it },
                keyboardType = KeyboardType.Password, password = true, imeAction = ImeAction.Done,
                onImeAction = { if (server.isNotBlank() && key.isNotBlank()) joinTyped() },
            )
            Text(
                stringResource(if (advanced) R.string.sh_advanced_hide else R.string.sh_advanced),
                fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Palette.accent,
                modifier = Modifier.clickable(role = Role.Button) { advanced = !advanced }.padding(vertical = 6.dp),
            )
            if (advanced) {
                LabeledField(
                    label = stringResource(R.string.sh_pin), value = pin, onValueChange = { pin = it },
                )
                Text(stringResource(R.string.sh_pin_hint), style = Styles.hint.copy(fontSize = 13.sp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(stringResource(R.string.sh_plaintext), style = Styles.rowTitle)
                        Text(stringResource(R.string.sh_plaintext_hint), style = Styles.hint.copy(fontSize = 13.sp))
                    }
                    Switch(checked = plaintext, onCheckedChange = { plaintext = it }, colors = calabiSwitchColors())
                }
            }
            error?.let { Text(it, fontSize = 14.sp, color = Palette.danger) }
            PrimaryButton(
                text = stringResource(if (busy) R.string.sh_joining else R.string.sh_join),
                enabled = !busy && server.isNotBlank() && key.isNotBlank(),
                onClick = ::joinTyped,
            )
        }
        Spacer(Modifier.height(32.dp))
    }

    confirm?.let { c ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            containerColor = Palette.surface,
            title = { Text(stringResource(R.string.sh_confirm_title), style = Styles.section) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.sh_confirm_body), style = Styles.row.copy(color = Palette.muted))
                    Text(groupPin(c.pin), style = Styles.mono.copy(fontSize = 13.sp))
                    if (c.subject.isNotBlank()) Text(c.subject, style = Styles.hint.copy(fontSize = 12.sp))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    join(JSONObject(c.body.toString()).put("pin", c.pin))
                }) { Text(stringResource(R.string.sh_confirm_yes), color = Palette.accent, fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = null }) { Text(stringResource(R.string.settings_cancel), color = Palette.ink) }
            },
        )
    }
}

private data class Confirm(val body: JSONObject, val pin: String, val subject: String)

private class JoinMessages(
    val failed: String,
    val keyRefused: String,
    val disabled: String,
    val full: String,
    val noTLS: String,
    val pinMismatch: String,
    val unreachable: String,
    val notAnInvite: String,
) {
    /** What a refused join means, in the person's words. */
    fun explain(r: ApiResult): String {
        val o = r.json()
        return when (o.optString("code")) {
            "key_refused" -> keyRefused
            "disabled" -> disabled
            "full" -> full
            "no_tls" -> noTLS
            "pin_mismatch" -> pinMismatch.format(groupPin(o.optString("pin")))
            "unreachable" -> unreachable.format(o.optString("error"))
            "bad_link" -> notAnInvite
            else -> r.error(failed)
        }
    }
}

/**
 * The self-hosted server presents a certificate other than the one this phone
 * trusts (state cert_changed): its administrator made a new one, or something
 * else answers at its address. The two fingerprints side by side, and the new one
 * trusted only on a person's say-so (docs/runbook/self-hosted-sign-in-plan.md §3.2).
 */
@Composable
fun CertChangedPrompt(model: AppModel) {
    val c = model.connection
    if (!model.connected || c?.state != "cert_changed" || c.certPresented.isBlank()) return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val again = stringResource(R.string.cert_changed_again)
    val failed = stringResource(R.string.settings_save_failed)
    Group(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
        Row(Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(40.dp).background(Palette.dangerSoft, CircleShape), contentAlignment = Alignment.Center) {
                Glyph(R.drawable.ic_server, Palette.danger, 20.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.cert_changed_title), style = Styles.rowTitle)
                    Text(stringResource(R.string.cert_changed_body), style = Styles.hint.copy(fontSize = 13.sp))
                }
                if (c.certPinned.isNotBlank()) Fingerprint(stringResource(R.string.cert_changed_was), c.certPinned, Palette.muted)
                Fingerprint(stringResource(R.string.cert_changed_now), c.certPresented, Palette.ink)
            }
        }
        Row(Modifier.fillMaxWidth().padding(start = 68.dp, end = 16.dp, top = 12.dp, bottom = 14.dp)) {
            Pill(onClick = {
                if (!busy) {
                    busy = true
                    scope.launch {
                        val r = CoreClient.call("POST", "/v1/selfhosted/trust", JSONObject().put("pin", c.certPresented))
                        busy = false
                        if (!r.ok) toast(context, if (r.json().optString("code") == "pin_mismatch") again else r.error(failed))
                        model.refreshLive()
                    }
                }
            }) { Text(stringResource(R.string.cert_changed_trust), style = Styles.chip) }
        }
    }
}

@Composable
private fun Fingerprint(label: String, pin: String, color: Color) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = Styles.hint.copy(fontSize = 12.sp))
        Text(groupPin(pin), style = Styles.mono.copy(fontSize = 12.sp, color = color))
    }
}

/** sha256:abcd1234… in groups of four, the way a person compares it by eye. */
fun groupPin(pin: String): String =
    pin.removePrefix("sha256:").chunked(4).chunked(4).joinToString("\n") { it.joinToString(" ") }

@Composable
private fun ScanButton(enabled: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    Row(
        Modifier
            .fillMaxWidth()
            .height(64.dp)
            .clip(shape)
            .background(Palette.surface)
            .border(1.dp, Palette.fieldLine, shape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(Modifier.heightIn(min = 24.dp), contentAlignment = Alignment.Center) { Glyph(R.drawable.ic_scan, Palette.accent, 26.dp) }
        Text(stringResource(R.string.sh_scan), fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Palette.ink)
    }
}
