package net.calabi.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.calabi.app.R

@Composable
fun Glyph(@DrawableRes res: Int, tint: Color = Palette.ink, size: Dp = 20.dp) {
    Icon(painterResource(res), contentDescription = null, modifier = Modifier.size(size), tint = tint)
}

@Composable
fun Dot(color: Color, size: Dp = 8.dp) {
    Box(Modifier.size(size).background(color, CircleShape))
}

/** A white rounded group of rows, the design's list card. */
@Composable
fun Group(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(Palette.surface),
        content = content,
    )
}

@Composable
fun RowDivider(start: Dp = 16.dp) {
    Box(Modifier.padding(start = start).fillMaxWidth().height(1.dp).background(Palette.divider))
}

@Composable
fun SectionLabel(text: String, hint: String? = null) {
    Column(Modifier.padding(start = 8.dp, top = 8.dp, end = 8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(text, style = Styles.sectionLabel)
        hint?.let { Text(it, style = Styles.hint) }
    }
}

/** An empty ring, or a green disc with a check. */
@Composable
fun RadioMark(selected: Boolean) {
    if (selected) {
        Box(Modifier.size(22.dp).background(Palette.accent, CircleShape), contentAlignment = Alignment.Center) {
            Glyph(R.drawable.ic_check, Color.White, 14.dp)
        }
    } else {
        Box(Modifier.size(22.dp).border(2.dp, Palette.radioLine, CircleShape))
    }
}

/** One choice in a group: a title, an optional detail line, a radio mark. */
@Composable
fun ChoiceRow(title: String, selected: Boolean, detail: String? = null, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .selectable(selected = selected, onClick = onClick, role = Role.RadioButton)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = if (selected) Styles.rowTitle else Styles.row, maxLines = 1, overflow = TextOverflow.Ellipsis)
            detail?.let { Text(it, style = Styles.hint) }
        }
        RadioMark(selected)
    }
}

/** A row that performs an action: optional icon, a label, optional trailing content. */
@Composable
fun ActionRow(
    label: String,
    onClick: () -> Unit,
    @DrawableRes icon: Int? = null,
    color: Color = Palette.ink,
    trailing: @Composable RowScope.() -> Unit = {},
) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 54.dp)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        icon?.let { Glyph(it, color, 18.dp) }
        Text(
            label, modifier = Modifier.weight(1f), style = Styles.row.copy(color = color),
            fontWeight = if (color == Palette.ink) FontWeight.Normal else FontWeight.SemiBold,
        )
        trailing()
    }
}

/** A pill-shaped secondary control. */
@Composable
fun Pill(onClick: () -> Unit, modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    val shape = RoundedCornerShape(20.dp)
    Row(
        modifier
            .height(40.dp)
            .clip(shape)
            .background(Palette.surface)
            .border(1.dp, Palette.line, shape)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        content = content,
    )
}

/** A row that opens something: title, hint, chevron. */
@Composable
fun LinkRow(title: String, hint: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(role = Role.Button, onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = Styles.row)
            Text(hint, style = Styles.hint)
        }
        Glyph(R.drawable.ic_chevron_right, Palette.muted, 16.dp)
    }
}

/** A setting that is on or off: title, hint, switch. */
@Composable
fun SwitchRow(title: String, hint: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = Styles.row)
            Text(hint, style = Styles.hint)
        }
        Switch(checked = checked, colors = calabiSwitchColors(), onCheckedChange = onCheckedChange)
    }
}

@Composable
fun calabiSwitchColors(): SwitchColors = SwitchDefaults.colors(
    checkedThumbColor = Color.White,
    checkedTrackColor = Palette.accent,
    checkedBorderColor = Palette.accent,
    uncheckedThumbColor = Color.White,
    uncheckedTrackColor = Palette.avatar,
    uncheckedBorderColor = Palette.avatar,
)

@Composable
fun PrimaryButton(text: String, enabled: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth().height(54.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Palette.ink, contentColor = Color.White,
            disabledContainerColor = Palette.ink.copy(alpha = 0.35f), disabledContentColor = Color.White,
        ),
    ) { Text(text, fontSize = 16.sp, fontWeight = FontWeight.Bold) }
}

/** Label above, white box below; the box turns green while focused. */
@Composable
fun LabeledField(
    label: String?,
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    keyboardType: KeyboardType = KeyboardType.Text,
    password: Boolean = false,
    imeAction: ImeAction = ImeAction.Next,
    onImeAction: () -> Unit = {},
) {
    var focused by remember { mutableStateOf(false) }
    val shape = RoundedCornerShape(14.dp)
    Column(modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        label?.let { Text(it, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Palette.label) }
        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            singleLine = true,
            textStyle = TextStyle(fontFamily = Fonts.display, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Palette.ink),
            keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction),
            keyboardActions = KeyboardActions(onAny = { onImeAction() }),
            visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
            cursorBrush = SolidColor(Palette.accent),
            modifier = Modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused },
            decorationBox = { inner ->
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                        .clip(shape)
                        .background(Palette.surface)
                        .border(if (focused) 2.dp else 1.dp, if (focused) Palette.accent else Palette.fieldLine, shape)
                        .padding(horizontal = 16.dp),
                    contentAlignment = Alignment.CenterStart,
                ) { inner() }
            },
        )
    }
}

/** The tab bar: the selected tab is an ink pill. */
@Composable
fun BottomNav(tab: Int, onTab: (Int) -> Unit) {
    Column(Modifier.fillMaxWidth().background(Palette.ground)) {
        Box(Modifier.fillMaxWidth().height(1.dp).background(Palette.line))
        Row(
            Modifier.fillMaxWidth().navigationBarsPadding().height(76.dp).padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            NavItem(R.drawable.ic_mesh, stringResource(R.string.tab_mesh), tab == 0) { onTab(0) }
            NavItem(R.drawable.ic_tunnel, stringResource(R.string.tab_tunnels), tab == 1) { onTab(1) }
            NavItem(R.drawable.ic_settings, stringResource(R.string.tab_settings), tab == 2) { onTab(2) }
        }
    }
}

@Composable
private fun NavItem(@DrawableRes icon: Int, label: String, selected: Boolean, onClick: () -> Unit) {
    val fg = if (selected) Color.White else Palette.muted
    Row(
        Modifier
            .height(48.dp)
            .clip(RoundedCornerShape(24.dp))
            .background(if (selected) Palette.ink else Color.Transparent)
            .selectable(selected = selected, onClick = onClick, role = Role.Tab)
            .padding(horizontal = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Glyph(icon, fg, 20.dp)
        Text(label, fontSize = 14.sp, fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold, color = fg, maxLines = 1)
    }
}

/** A sub-screen's top row: a round back button, and room for actions on the right. */
@Composable
fun TopBar(onBack: () -> Unit, actions: @Composable RowScope.() -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().padding(top = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CircleButton(R.drawable.ic_chevron_left, stringResource(R.string.back), onBack)
        Spacer(Modifier.weight(1f))
        actions()
    }
}

@Composable
fun CircleButton(@DrawableRes icon: Int, description: String, onClick: () -> Unit) {
    Box(
        Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(Palette.surface)
            .border(1.dp, Palette.line, CircleShape)
            .clickable(role = Role.Button, onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) { Glyph(icon, Palette.ink, 20.dp) }
}

/** One choice of a small segmented control: an ink pill when selected. */
@Composable
fun Segment(label: String, selected: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(18.dp)
    Box(
        Modifier
            .height(36.dp)
            .clip(shape)
            .background(if (selected) Palette.ink else Palette.surface)
            .border(1.dp, if (selected) Palette.ink else Palette.line, shape)
            .selectable(selected = selected, onClick = onClick, role = Role.RadioButton)
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = if (selected) Color.White else Palette.ink)
    }
}

fun copyToClipboard(context: Context, text: String) {
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(text, text))
    Toast.makeText(context, context.getString(R.string.copied, text), Toast.LENGTH_SHORT).show()
}

fun toast(context: Context, text: String) {
    Toast.makeText(context, text, Toast.LENGTH_SHORT).show()
}
