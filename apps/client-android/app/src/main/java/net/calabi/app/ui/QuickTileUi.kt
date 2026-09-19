package net.calabi.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.calabi.app.AppPrefs
import net.calabi.app.QuickTile
import net.calabi.app.R

/**
 * Whether the tile is in the panel, kept current while the screen is up: it is
 * added from the notification shade, which does not pause the app (found on the
 * ELS-AN00: a lifecycle-keyed read stayed on "not added" after the tile was in).
 */
@Composable
private fun rememberTileAdded(): MutableState<Boolean> {
    val context = LocalContext.current
    val state = remember { mutableStateOf(AppPrefs.tileAdded(context)) }
    DisposableEffect(context) {
        state.value = AppPrefs.tileAdded(context)
        val stop = AppPrefs.watchTileAdded(context) { state.value = it }
        onDispose { stop() }
    }
    return state
}

/**
 * Shown on the mesh tab once the phone has connected, until the tile is added or
 * the card is dismissed. Waits for a replace-device notice to be dealt with, so a
 * fresh install does not open with two cards.
 */
@Composable
fun TilePrompt(model: AppModel) {
    val context = LocalContext.current
    var added by rememberTileAdded()
    var dismissed by remember { mutableStateOf(AppPrefs.tileTipDismissed(context)) }
    var steps by remember { mutableStateOf(false) }
    val replacePending = model.replaceable.any { it.id !in AppPrefs.replaceDismissed(context) }

    if (steps) TileStepsDialog { steps = false }
    if (!model.connected || added || dismissed || replacePending) return

    Group(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
        Row(
            Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.size(40.dp).background(Palette.accentSoft, CircleShape), contentAlignment = Alignment.Center) {
                Glyph(R.drawable.ic_tile, Palette.accent, 20.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.tile_prompt_title), style = Styles.rowTitle)
                Text(stringResource(R.string.tile_prompt_body), style = Styles.hint.copy(fontSize = 13.sp))
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(start = 68.dp, end = 16.dp, top = 12.dp, bottom = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Pill(onClick = { QuickTile.add(context, showSteps = { steps = true }, onAdded = { added = true }) }) {
                Text(stringResource(R.string.tile_add), style = Styles.chip)
            }
            TextButton(onClick = {
                AppPrefs.dismissTileTip(context)
                dismissed = true
            }) {
                Text(stringResource(R.string.replace_dismiss), style = Styles.chip.copy(color = Palette.muted))
            }
        }
    }
}

/** Settings → This device: always there, so the card being dismissed is not the end of it. */
@Composable
fun QuickTileRow() {
    val context = LocalContext.current
    var added by rememberTileAdded()
    var steps by remember { mutableStateOf(false) }

    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = !added, role = Role.Button) {
                QuickTile.add(context, showSteps = { steps = true }, onAdded = { added = true })
            }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(R.string.tile_row), style = Styles.row)
            Text(stringResource(if (added) R.string.tile_row_added_hint else R.string.tile_row_hint), style = Styles.hint)
        }
        if (added) {
            Text(stringResource(R.string.tile_added), style = Styles.hint.copy(color = Palette.accent, fontWeight = FontWeight.SemiBold))
        } else {
            Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
        }
    }

    if (steps) TileStepsDialog { steps = false }
}

/** Where the panel's edit mode is, for phones that cannot show the system's dialog. */
@Composable
private fun TileStepsDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Palette.surface,
        title = { Text(stringResource(R.string.tile_steps_title), style = Styles.section) },
        text = { Text(stringResource(QuickTile.steps()), style = Styles.row.copy(color = Palette.muted)) },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.tile_steps_ok), color = Palette.ink, fontWeight = FontWeight.Bold)
            }
        },
    )
}
