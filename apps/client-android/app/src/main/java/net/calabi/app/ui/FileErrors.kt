package net.calabi.app.ui

import android.content.Context
import net.calabi.app.R
import java.util.Locale

// User-facing summaries, including errors returned by older native cores.
// Do not put raw paths, HTTP requests or internal exception text in the UI.
internal fun fileErrorText(context: Context, error: String): String {
    if (error.isBlank()) return ""
    if (error == context.getString(R.string.files_cancelled)) return error
    val text = error.lowercase(Locale.ROOT)
    fun matches(pattern: String) = Regex(pattern).containsMatchIn(text)
    val resource = when {
        matches("no longer authorized|not authorized|permission denied|access is denied|http (401|403)") -> R.string.files_error_authorization
        matches("certificate|x509|identity changed|file key") -> R.string.files_error_identity
        matches("source.*(changed|unavailable|missing)|no such file|cannot find the file|file.*(changed|unavailable)|size changed") -> R.string.files_error_source
        matches("checksum|sha256|hash mismatch|verification failed") -> R.string.files_error_integrity
        matches("no space|disk full|not enough space") -> R.string.files_error_storage
        matches("persist|read-only|read only|cannot (save|write)|i/o error") -> R.string.files_error_storagewrite
        matches("file-control|filecontrol|file agent|desktop app|desktop file|daemon unavailable|private inbox") -> R.string.files_error_agent
        matches("timeout|timed out|deadline exceeded|offline|not receiving|connection|dial tcp|network|reconnect|eof|http 5[0-9][0-9]") -> R.string.files_error_connection
        matches("limit exceeded|too many|up to 32|another batch|quota") -> R.string.files_error_limit
        matches("process restarted") -> R.string.files_error_restarted
        matches("unknown task|unknown source|unknown transfer|request changed|task cannot be resumed|http (404|410)") -> R.string.files_error_stale
        matches("context canceled|context cancelled") -> R.string.files_error_interrupted
        else -> R.string.files_error_generic
    }
    return context.getString(resource)
}
