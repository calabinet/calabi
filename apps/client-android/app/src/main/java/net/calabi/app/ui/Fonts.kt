package net.calabi.app.ui

import android.content.Context
import android.graphics.Typeface
import android.os.Build
import androidx.annotation.FontRes
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.font.AndroidFont
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontLoadingStrategy
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.core.content.res.ResourcesCompat
import net.calabi.app.R

/**
 * Manrope for text and JetBrains Mono for addresses and numbers, both bundled
 * (licenses in assets/licenses). Bundled rather than FontFamily.Monospace because
 * the system "monospace" on some phones is proportional: IP addresses did not
 * line up.
 *
 * Neither face has CJK glyphs, so Chinese comes from the system font. Loaded the
 * plain way (Font(res, weight, variationSettings)), that fallback was drawn at
 * regular weight whatever the text asked for — every bold Chinese heading on a
 * real phone came out regular. Each weight is therefore built with a system
 * fallback of the same weight.
 */
object Fonts {
    val display: FontFamily = family(R.font.manrope, 400, 500, 600, 700, 800)
    val mono: FontFamily = family(R.font.jetbrains_mono, 400, 500, 600)

    private fun family(@FontRes res: Int, vararg weights: Int) =
        FontFamily(weights.map { BundledFont(res, FontWeight(it)) })
}

@OptIn(ExperimentalTextApi::class)
private class BundledFont(
    @FontRes val res: Int,
    override val weight: FontWeight,
) : AndroidFont(FontLoadingStrategy.Blocking, Loader, FontVariation.Settings(FontVariation.weight(weight.weight))) {
    override val style: FontStyle = FontStyle.Normal

    private object Loader : TypefaceLoader {
        override fun loadBlocking(context: Context, font: AndroidFont): Typeface? {
            val f = font as BundledFont
            val w = f.weight.weight
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val face = android.graphics.fonts.Font.Builder(context.resources, f.res)
                    .setWeight(w)
                    .setFontVariationSettings("'wght' $w")
                    .build()
                return Typeface.CustomFallbackBuilder(android.graphics.fonts.FontFamily.Builder(face).build())
                    .setStyle(android.graphics.fonts.FontStyle(w, android.graphics.fonts.FontStyle.FONT_SLANT_UPRIGHT))
                    .setSystemFallback("sans-serif")
                    .build()
            }
            // Before Android 10 there is no custom fallback: the weight is synthesized.
            val base = ResourcesCompat.getFont(context, f.res) ?: return null
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) Typeface.create(base, w, false)
            else Typeface.create(base, if (w >= 600) Typeface.BOLD else Typeface.NORMAL)
        }

        override suspend fun awaitLoad(context: Context, font: AndroidFont): Typeface? = loadBlocking(context, font)
    }
}
