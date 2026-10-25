package net.calabi.app.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import net.calabi.app.R
import java.io.IOException

internal class FileDocumentExportException(cause: Exception, val cleanupFailed: Boolean) :
    Exception(cause.message, cause)

/** The URI comes only from CreateDocument; the native exporter owns its duplicated fd. */
internal fun exportVerifiedDocument(resolver: ContentResolver, uri: Uri, export: (Int) -> Unit) {
    try {
        val document = resolver.openFileDescriptor(uri, "w") ?: throw IOException("cannot write destination")
        document.use {
            // Keep the provider's original descriptor so its close callback sees the final size.
            ParcelFileDescriptor.dup(it.fileDescriptor).use { duplicate -> export(duplicate.detachFd()) }
        }
    } catch (error: Exception) {
        val cleaned = try { DocumentsContract.deleteDocument(resolver, uri) } catch (_: Exception) { false }
        throw FileDocumentExportException(error, !cleaned)
    }
}

internal fun fileDocumentExportError(context: Context, error: Exception): String {
    val cause = error.cause ?: error
    val denied = cause is SecurityException || Regex("permission denied|access is denied", RegexOption.IGNORE_CASE)
        .containsMatchIn(cause.message.orEmpty())
    val message = if (denied) context.getString(R.string.files_error_save_permission)
        else fileErrorText(context, cause.message.orEmpty().ifBlank { "cannot save file" })
    return if (error is FileDocumentExportException && error.cleanupFailed)
        "$message ${context.getString(R.string.files_error_save_cleanup)}" else message
}
