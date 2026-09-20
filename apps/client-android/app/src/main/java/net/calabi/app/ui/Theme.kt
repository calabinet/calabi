package net.calabi.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Direction A "Signal" (design canvas T2xE6jnS3iBNnPKtFYDR44): a warm off-white
 * ground, ink text, and one green that means "connected". Light only for now;
 * the design has no dark variant yet.
 */
object Palette {
    val ground = Color(0xFFF3F1EC)
    val surface = Color(0xFFFFFFFF)
    val sunken = Color(0xFFF1EEE7)
    val ink = Color(0xFF17171A)
    val muted = Color(0xFF625F59)
    val label = Color(0xFF4A4843)
    val line = Color(0xFFE3E0D8)
    val divider = Color(0xFFEFECE5)
    val fieldLine = Color(0xFFDCD8CF)
    val radioLine = Color(0xFFCFCBC2)
    val avatar = Color(0xFFE6E2D9)
    val offRing = Color(0xFFE9E6DF)
    val accent = Color(0xFF1E7A50)
    val accentSoft = Color(0xFFDCEFE4)
    val relayDot = Color(0xFFD98A1C)
    val relayText = Color(0xFF9A5A05)
    val danger = Color(0xFFB42318)
    val dangerSoft = Color(0xFFF6E1DE)
    /** The logo's blue (web/www/public/favicon.svg). Only for the logo itself. */
    val brand = Color(0xFF2742F0)
}

private val Colors = lightColorScheme(
    primary = Palette.ink,
    onPrimary = Color.White,
    primaryContainer = Palette.accentSoft,
    onPrimaryContainer = Palette.ink,
    secondary = Palette.muted,
    onSecondary = Color.White,
    secondaryContainer = Palette.sunken,
    onSecondaryContainer = Palette.ink,
    tertiary = Palette.accent,
    background = Palette.ground,
    onBackground = Palette.ink,
    surface = Palette.surface,
    onSurface = Palette.ink,
    surfaceVariant = Palette.sunken,
    onSurfaceVariant = Palette.muted,
    surfaceContainerLowest = Palette.surface,
    surfaceContainerLow = Palette.surface,
    surfaceContainer = Palette.surface,
    surfaceContainerHigh = Palette.surface,
    surfaceContainerHighest = Palette.surface,
    outline = Palette.fieldLine,
    outlineVariant = Palette.divider,
    error = Palette.danger,
)

private val Type = Typography().let { t ->
    fun TextStyle.face() = copy(fontFamily = Fonts.display)
    Typography(
        displayLarge = t.displayLarge.face(), displayMedium = t.displayMedium.face(), displaySmall = t.displaySmall.face(),
        headlineLarge = t.headlineLarge.face(), headlineMedium = t.headlineMedium.face(), headlineSmall = t.headlineSmall.face(),
        titleLarge = t.titleLarge.face(), titleMedium = t.titleMedium.face(), titleSmall = t.titleSmall.face(),
        bodyLarge = t.bodyLarge.face(), bodyMedium = t.bodyMedium.face(), bodySmall = t.bodySmall.face(),
        labelLarge = t.labelLarge.face(), labelMedium = t.labelMedium.face(), labelSmall = t.labelSmall.face(),
    )
}

/** The handful of text styles the screens use, named by role. */
object Styles {
    val screenTitle = TextStyle(fontFamily = Fonts.display, fontSize = 30.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp)
    val heroState = TextStyle(fontFamily = Fonts.display, fontSize = 30.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp)
    val section = TextStyle(fontFamily = Fonts.display, fontSize = 18.sp, fontWeight = FontWeight.Bold)
    val sectionLabel = TextStyle(fontFamily = Fonts.display, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Palette.muted)
    val rowTitle = TextStyle(fontFamily = Fonts.display, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink)
    val row = TextStyle(fontFamily = Fonts.display, fontSize = 15.sp, color = Palette.ink)
    val hint = TextStyle(fontFamily = Fonts.display, fontSize = 12.sp, color = Palette.muted)
    val chip = TextStyle(fontFamily = Fonts.display, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Palette.ink)
    val mono = TextStyle(fontFamily = Fonts.mono, fontSize = 12.sp, color = Palette.muted)
    val monoValue = TextStyle(fontFamily = Fonts.mono, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Palette.ink)
}

@Composable
fun CalabiTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Colors, typography = Type, content = content)
}
