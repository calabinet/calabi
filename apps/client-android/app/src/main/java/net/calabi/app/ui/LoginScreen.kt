package net.calabi.app.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import net.calabi.app.BuildConfig
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONObject

private const val CODE_LENGTH = 6

@Composable
fun LoginScreen(onSignedIn: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var email by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    // 1: email and password; 2: the account asked for its two-step code.
    var step by rememberSaveable { mutableIntStateOf(1) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val failed = stringResource(R.string.login_failed)
    val badCredentials = stringResource(R.string.login_bad_credentials)
    val notVerified = stringResource(R.string.login_not_verified)
    val badCode = stringResource(R.string.login_totp_invalid)

    fun openConsole(path: String) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(BuildConfig.CONSOLE_URL + path)))
    }

    fun submit() {
        if (busy) return
        busy = true
        error = null
        scope.launch {
            val body = JSONObject().put("email", email.trim()).put("password", password)
            if (step == 2) body.put("totp_code", code)
            val r = CoreClient.call("POST", "/v1/auth/login", body)
            busy = false
            if (r.ok) {
                onSignedIn()
                return@launch
            }
            // The identity service's sentinels; the web console reads the same ones.
            val msg = r.json().optString("error")
            when {
                msg.contains("email not verified", ignoreCase = true) -> { step = 1; error = notVerified }
                msg.contains("invalid totp", ignoreCase = true) -> { code = ""; error = badCode }
                msg.contains("totp required", ignoreCase = true) -> { step = 2; code = "" }
                msg.contains("invalid credentials", ignoreCase = true) -> error = badCredentials
                else -> error = r.error(failed)
            }
        }
    }

    BackHandler(enabled = step == 2) {
        step = 1
        code = ""
        error = null
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(Palette.ground)
            .safeDrawingPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp),
    ) {
        if (step == 1) {
            Spacer(Modifier.height(72.dp))
            Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                // The app icon: the brand's blue and mark, as on the launcher and the desktop client.
                Box(Modifier.size(72.dp).background(Palette.brand, RoundedCornerShape(20.dp)), contentAlignment = Alignment.Center) {
                    Glyph(R.drawable.ic_tile, Color.White, 36.dp)
                }
                Text(stringResource(R.string.app_name), fontFamily = Fonts.display, fontSize = 30.sp, fontWeight = FontWeight.ExtraBold, color = Palette.ink)
                Text(stringResource(R.string.login_subtitle), fontSize = 15.sp, color = Palette.muted, textAlign = TextAlign.Center)
            }
            Spacer(Modifier.height(36.dp))
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                LabeledField(
                    label = stringResource(R.string.login_email), value = email, onValueChange = { email = it },
                    keyboardType = KeyboardType.Email,
                )
                LabeledField(
                    label = stringResource(R.string.login_password), value = password, onValueChange = { password = it },
                    keyboardType = KeyboardType.Password, password = true, imeAction = ImeAction.Done,
                    onImeAction = { if (email.isNotBlank() && password.isNotEmpty()) submit() },
                )
                error?.let { Text(it, fontSize = 14.sp, color = Palette.danger) }
                PrimaryButton(
                    text = stringResource(if (busy) R.string.login_signing_in else R.string.login_sign_in),
                    enabled = !busy && email.isNotBlank() && password.isNotEmpty(),
                    onClick = ::submit,
                    modifier = Modifier.padding(top = 8.dp),
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp, Alignment.CenterHorizontally)) {
                    Link(stringResource(R.string.login_register)) { openConsole("/register") }
                    Link(stringResource(R.string.login_forgot)) { openConsole("/reset-password") }
                }
            }
            Spacer(Modifier.height(48.dp))
            Text(
                stringResource(R.string.login_footnote), fontSize = 12.sp, color = Palette.muted, textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp),
            )
        } else {
            Spacer(Modifier.height(12.dp))
            Row(
                Modifier
                    .heightIn(min = 44.dp)
                    .clip(RoundedCornerShape(22.dp))
                    .clickable(role = Role.Button) { step = 1; code = ""; error = null }
                    .padding(end = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Glyph(R.drawable.ic_chevron_left, Palette.ink, 22.dp)
                Text(stringResource(R.string.login_back), fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink)
            }
            Spacer(Modifier.height(40.dp))
            Text(stringResource(R.string.login_totp_title), style = Styles.screenTitle, color = Palette.ink)
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.login_totp_subtitle, email.trim()), fontSize = 15.sp, color = Palette.muted)
            Spacer(Modifier.height(28.dp))
            CodeField(code, stringResource(R.string.login_totp_code)) {
                code = it
                error = null
                if (it.length == CODE_LENGTH) submit()
            }
            error?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, fontSize = 14.sp, color = Palette.danger)
            }
            Spacer(Modifier.height(24.dp))
            PrimaryButton(
                text = stringResource(if (busy) R.string.login_signing_in else R.string.login_verify),
                enabled = !busy && code.length == CODE_LENGTH,
                onClick = ::submit,
            )
        }
    }
}

@Composable
private fun Link(text: String, onClick: () -> Unit) {
    Box(
        Modifier.heightIn(min = 44.dp).clickable(role = Role.Button, onClick = onClick).padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center,
    ) { Text(text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Palette.accent) }
}

/**
 * One real text field drawn as six boxes. A field per digit jumps focus while an
 * input method is still composing and enters a digit twice (the web console hit
 * exactly that), so there is only ever one field here.
 */
@Composable
private fun CodeField(value: String, label: String, onValueChange: (String) -> Unit) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { focus.requestFocus() }
    BasicTextField(
        value = value,
        onValueChange = { onValueChange(it.filter(Char::isDigit).take(CODE_LENGTH)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
        textStyle = TextStyle(color = Color.Transparent),
        cursorBrush = SolidColor(Color.Transparent),
        modifier = Modifier.fillMaxWidth().focusRequester(focus).semantics { contentDescription = label },
        decorationBox = { inner ->
            Box {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    repeat(CODE_LENGTH) { i ->
                        val shape = RoundedCornerShape(14.dp)
                        val current = i == value.length
                        Box(
                            Modifier
                                .weight(1f)
                                .height(56.dp)
                                .clip(shape)
                                .background(Palette.surface)
                                .border(if (current) 2.dp else 1.dp, if (current) Palette.accent else Palette.fieldLine, shape),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(value.getOrNull(i)?.toString().orEmpty(), fontFamily = Fonts.mono, fontSize = 22.sp, fontWeight = FontWeight.Medium, color = Palette.ink)
                        }
                    }
                }
                Box(Modifier.matchParentSize().alpha(0f)) { inner() }
            }
        },
    )
}
