package net.calabi.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** One answer from the core's local API. */
data class ApiResult(val status: Int, val body: String) {
    val ok get() = status in 200..299
    fun json(): JSONObject = try {
        JSONObject(body)
    } catch (_: Exception) {
        JSONObject()
    }

    /** The control plane's message for a failure, or a fallback. */
    fun error(fallback: String): String = json().optString("error").ifBlank { fallback }
}

/**
 * The app's only way to the Go core's data: its in-process /v1 API
 * (apps/client/mobile/api.go). Calls block on network I/O, so they run off the
 * main thread.
 */
object CoreClient {

    suspend fun call(method: String, path: String, body: JSONObject? = null): ApiResult =
        withContext(Dispatchers.IO) { callBlocking(method, path, body) }

    fun callBlocking(method: String, path: String, body: JSONObject? = null): ApiResult {
        val resp = CalabiApp.instance.core.call(method, path, body?.toString()?.toByteArray())
        return ApiResult(resp.status, String(resp.body ?: ByteArray(0)))
    }

    /** Cheap: reads the saved session, no network. */
    fun signedIn(): Boolean = callBlocking("GET", "/v1/state").json().optBoolean("signed_in")
}
