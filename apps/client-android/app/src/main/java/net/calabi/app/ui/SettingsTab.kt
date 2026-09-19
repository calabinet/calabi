package net.calabi.app.ui

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.currentStateAsState
import kotlinx.coroutines.launch
import net.calabi.app.AppPrefs
import net.calabi.app.BackgroundRun
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONObject

@Composable
fun SettingsTab(model: AppModel, onSignedOut: () -> Unit, onReplace: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var renaming by remember { mutableStateOf(false) }
    var confirmSignOut by remember { mutableStateOf(false) }
    var connectOnBoot by remember { mutableStateOf(AppPrefs.connectOnBoot(context)) }
    // Read again on coming back from the system's settings, where it is changed.
    val lifecycle by LocalLifecycleOwner.current.lifecycle.currentStateAsState()
    val backgroundRow = remember(lifecycle) { BackgroundRun.mayNeedAllowing(context) }
    val failed = stringResource(R.string.settings_save_failed)

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(stringResource(R.string.settings_title), style = Styles.screenTitle, modifier = Modifier.padding(start = 6.dp, bottom = 6.dp))

        if (model.selfHosted) ServerGroup(model) else Group {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Box(Modifier.size(44.dp).background(Palette.avatar, CircleShape), contentAlignment = Alignment.Center) {
                    Text(model.email.take(1).uppercase(), fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Palette.ink)
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(model.email, style = Styles.rowTitle, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (model.orgs.size > 1) Text(stringResource(R.string.settings_org_hint), style = Styles.hint)
                }
            }
            if (model.orgs.size > 1) {
                RowDivider()
                OrgChoices(model)
            }
        }

        UsageSection(model)

        SectionLabel(stringResource(R.string.settings_device))
        Group {
            ActionRow(stringResource(R.string.settings_device_name), onClick = { renaming = true }) {
                Text(model.deviceName, style = Styles.mono.copy(fontSize = 14.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
                Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
            }
            if (model.replaceable.isNotEmpty()) {
                RowDivider()
                ActionRow(stringResource(R.string.settings_replace), onClick = onReplace) {
                    Text(model.replaceable.size.toString(), style = Styles.mono.copy(fontSize = 14.sp))
                    Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
                }
            }
            RowDivider()
            SwitchRow(
                stringResource(R.string.settings_accept_routes), stringResource(R.string.settings_accept_routes_hint),
                checked = model.acceptRoutes,
            ) { on ->
                scope.launch {
                    val r = model.saveSettings(JSONObject().put("accept_routes", on))
                    if (!r.ok) toast(context, r.error(failed))
                }
            }
            RowDivider()
            SwitchRow(
                stringResource(R.string.settings_connect_on_boot), stringResource(R.string.settings_connect_on_boot_hint),
                checked = connectOnBoot,
            ) { on ->
                AppPrefs.setConnectOnBoot(context, on)
                connectOnBoot = on
            }
            RowDivider()
            QuickTileRow()
            if (backgroundRow) {
                RowDivider()
                LinkRow(stringResource(R.string.settings_background), stringResource(BackgroundRun.hint())) {
                    BackgroundRun.allow(context)
                }
            }
        }

        SectionLabel(stringResource(R.string.settings_exit), stringResource(R.string.settings_exit_hint))
        ExitChoices(model)

        SectionLabel(stringResource(R.string.settings_support))
        Group {
            ActionRow(stringResource(R.string.settings_export_logs), icon = R.drawable.ic_share, onClick = {
                scope.launch {
                    val logs = CoreClient.call("GET", "/v1/logs").body
                    val share = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, logs)
                    context.startActivity(Intent.createChooser(share, null))
                }
            })
            RowDivider(start = 46.dp)
            ActionRow(
                stringResource(if (model.selfHosted) R.string.settings_leave_server else R.string.settings_sign_out),
                icon = R.drawable.ic_logout, color = Palette.danger,
                onClick = { confirmSignOut = true },
            )
        }
        Spacer(Modifier.height(8.dp))
    }

    if (renaming) {
        RenameDialog(model.deviceName, onDismiss = { renaming = false }) { name ->
            renaming = false
            scope.launch {
                val r = model.saveSettings(JSONObject().put("device_name", name))
                if (!r.ok) toast(context, r.error(failed))
            }
        }
    }

    if (confirmSignOut) {
        AlertDialog(
            onDismissRequest = { confirmSignOut = false },
            containerColor = Palette.surface,
            title = {
                Text(stringResource(if (model.selfHosted) R.string.settings_leave_server_confirm else R.string.settings_sign_out_confirm), style = Styles.section)
            },
            text = {
                Text(
                    stringResource(if (model.selfHosted) R.string.settings_leave_server_body else R.string.settings_sign_out_body),
                    style = Styles.row.copy(color = Palette.muted),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmSignOut = false
                    scope.launch {
                        CoreClient.call("POST", "/v1/auth/logout")
                        onSignedOut()
                    }
                }) {
                    Text(
                        stringResource(if (model.selfHosted) R.string.settings_leave_server else R.string.settings_sign_out),
                        color = Palette.danger, fontWeight = FontWeight.Bold,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmSignOut = false }) {
                    Text(stringResource(R.string.settings_cancel), color = Palette.ink)
                }
            },
        )
    }
}

@Composable
private fun RenameDialog(current: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var draft by remember { mutableStateOf(current) }
    val valid = draft.isNotBlank() && draft.trim() != current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Palette.ground,
        title = { Text(stringResource(R.string.settings_device_name), style = Styles.section) },
        text = {
            LabeledField(
                label = null, value = draft, onValueChange = { draft = it },
                imeAction = androidx.compose.ui.text.input.ImeAction.Done, onImeAction = { if (valid) onSave(draft.trim()) },
            )
        },
        confirmButton = {
            TextButton(enabled = valid, onClick = { onSave(draft.trim()) }) {
                Text(stringResource(R.string.settings_save), color = if (valid) Palette.accent else Palette.muted, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.settings_cancel), color = Palette.ink) }
        },
    )
}

/** Where the account would be: the self-hosted server this phone joined. */
@Composable
private fun ServerGroup(model: AppModel) {
    Group {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.size(44.dp).background(Palette.avatar, CircleShape), contentAlignment = Alignment.Center) {
                Glyph(R.drawable.ic_server, Palette.ink, 22.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(stringResource(R.string.settings_server), style = Styles.rowTitle)
                Text(model.server, style = Styles.mono.copy(fontSize = 13.sp), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}
