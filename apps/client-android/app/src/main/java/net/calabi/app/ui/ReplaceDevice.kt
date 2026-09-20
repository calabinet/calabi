package net.calabi.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.calabi.app.AppPrefs
import net.calabi.app.R

/**
 * Offered on the devices tab when this user has offline Android devices this
 * phone may be replacing (a reinstall or a new phone). Hidden once dismissed,
 * until a device not seen before turns up.
 */
@Composable
fun ReplacePrompt(model: AppModel, onChoose: () -> Unit) {
    val context = LocalContext.current
    var dismissed by remember(model.activeOrgId) { mutableStateOf(AppPrefs.replaceDismissed(context)) }
    val fresh = model.replaceable.filter { it.id !in dismissed }
    if (fresh.isEmpty()) return
    Group(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
        Row(
            Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.size(40.dp).background(Palette.accentSoft, CircleShape), contentAlignment = Alignment.Center) {
                Glyph(R.drawable.ic_phone, Palette.accent, 20.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.replace_prompt_title), style = Styles.rowTitle)
                Text(stringResource(R.string.replace_prompt_body), style = Styles.hint.copy(fontSize = 13.sp))
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(start = 68.dp, end = 16.dp, top = 12.dp, bottom = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Pill(onClick = onChoose) { Text(stringResource(R.string.replace_choose), style = Styles.chip) }
            TextButton(onClick = {
                AppPrefs.dismissReplace(context, fresh.map { it.id })
                dismissed = AppPrefs.replaceDismissed(context)
            }) { Text(stringResource(R.string.replace_dismiss), style = Styles.chip.copy(color = Palette.muted)) }
        }
    }
}

/** The old devices to choose from, in the replace sheet. */
@Composable
fun ReplaceChoices(model: AppModel, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var confirming by remember { mutableStateOf<OldDevice?>(null) }
    val failed = stringResource(R.string.replace_failed)
    Group {
        model.replaceable.forEachIndexed { i, d ->
            if (i > 0) RowDivider()
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 60.dp)
                    .clickable(role = Role.Button) { confirming = d }
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(d.name, style = Styles.rowTitle, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    val seen = parseInstant(d.lastSeen)?.let { stringResource(R.string.replace_last_seen, formatDate(context, it)) }
                    val detail = listOfNotNull(d.overlay.ifBlank { null }, seen, if (d.disabled) stringResource(R.string.replace_disabled) else null)
                    Text(detail.joinToString(" · "), style = Styles.mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
            }
        }
    }

    confirming?.let { d ->
        AlertDialog(
            onDismissRequest = { confirming = null },
            containerColor = Palette.surface,
            title = { Text(stringResource(R.string.replace_confirm_title, d.name), style = Styles.section) },
            text = { Text(stringResource(R.string.replace_confirm_body, d.name), style = Styles.row.copy(color = Palette.muted)) },
            confirmButton = {
                TextButton(onClick = {
                    confirming = null
                    scope.launch {
                        val r = model.replace(d)
                        toast(context, if (r.ok) context.getString(R.string.replace_done, r.json().optString("device_name", d.name)) else r.error(failed))
                        if (r.ok) onDone()
                    }
                }) { Text(stringResource(R.string.replace_action), color = Palette.danger, fontWeight = FontWeight.Bold) }
            },
            dismissButton = {
                TextButton(onClick = { confirming = null }) { Text(stringResource(R.string.settings_cancel), color = Palette.ink) }
            },
        )
    }
}
