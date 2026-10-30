package net.calabi.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.calabi.app.BackgroundRun
import net.calabi.app.R

/**
 * Shown on the devices tab after the phone stopped Calabi while the VPN was on.
 * Only then: on phones that leave a VPN alone there is nothing to allow, so it
 * is never offered up front.
 */
@Composable
fun StoppedPrompt(model: AppModel) {
    if (!model.stoppedInBackground || model.connected) return
    val context = LocalContext.current
    Group(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
        Row(
            Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.size(40.dp).background(Palette.sunken, CircleShape), contentAlignment = Alignment.Center) {
                Glyph(R.drawable.ic_power, Palette.relayText, 20.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.stopped_prompt_title), style = Styles.rowTitle)
                Text(
                    stringResource(R.string.stopped_prompt_body, stringResource(BackgroundRun.hint())),
                    style = Styles.hint.copy(fontSize = 13.sp),
                )
                BackgroundSteps()
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(start = 68.dp, end = 16.dp, top = 12.dp, bottom = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Pill(onClick = { BackgroundRun.allow(context) }) {
                Text(stringResource(R.string.background_allow), style = Styles.chip)
            }
            TextButton(onClick = { model.dismissStopped() }) {
                Text(stringResource(R.string.replace_dismiss), style = Styles.chip.copy(color = Palette.muted))
            }
        }
    }
}

/** Shared by the stopped notice and settings; initially collapsed on each screen. */
@Composable
fun BackgroundSteps(modifier: Modifier = Modifier) {
    val details = BackgroundRun.details() ?: return
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(2.dp)) {
        TextButton(onClick = { expanded = !expanded }, contentPadding = PaddingValues(0.dp)) {
            Text(
                stringResource(if (expanded) R.string.background_steps_hide else R.string.background_steps_show),
                style = Styles.chip.copy(color = Palette.muted),
            )
            Box(Modifier.padding(start = 4.dp).rotate(if (expanded) 180f else 0f)) {
                Glyph(R.drawable.ic_chevron_down, Palette.muted, 14.dp)
            }
        }
        if (expanded) Text(stringResource(details), style = Styles.hint.copy(fontSize = 13.sp))
    }
}
