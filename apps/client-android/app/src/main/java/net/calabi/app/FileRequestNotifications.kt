package net.calabi.app

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.KeyguardManager
import android.widget.RemoteViews
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.graphics.drawable.Icon
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

internal data class IncomingFileRequest(
    val key: String, val fingerprint: String, val ids: List<String>, val name: String,
    val count: Int, val bytes: Long,
) { fun stamp() = FileRequestNotifications.tag(toString()) }

/** Only complete offers get actionable notifications; one decision is one batch. */
internal fun incomingFileRequests(snapshot: JSONObject): List<IncomingFileRequest> {
    val fingerprint = snapshot.optJSONObject("identity")?.optString("fingerprint").orEmpty()
    if (!snapshot.optBoolean("available") || fingerprint.isBlank()) return emptyList()
    val rows = snapshot.optJSONArray("received") ?: return emptyList()
    val groups = (0 until rows.length()).mapNotNull { rows.optJSONObject(it) }.groupBy {
        val file = it.optJSONObject("transfer")
        it.optString("device_key") + "/" + file?.optString("batch").orEmpty().ifBlank { file?.optString("id").orEmpty() }
    }
    return groups.mapNotNull { (key, group) ->
        val files = group.mapNotNull { it.optJSONObject("transfer") }
        val waiting = files.filter { it.optString("state") == "waiting" }
        val expected = files.maxOfOrNull { it.optInt("batch_count", 1) } ?: 1
        if (group.first().optString("device_key").isBlank() || expected !in 1..32 || waiting.isEmpty() || files.size < expected) return@mapNotNull null
        val ids = waiting.map { it.optString("id") }.sorted()
        if (ids.any { it.isBlank() } || ids.distinct().size != ids.size) return@mapNotNull null
        val ip = group.first().optString("ip")
        val peers = snapshot.optJSONArray("peers") ?: JSONArray()
        val name = (0 until peers.length()).mapNotNull { peers.optJSONObject(it) }
            .firstOrNull { it.optString("ip") == ip }?.optString("name").orEmpty().ifBlank { ip }
        IncomingFileRequest(key, fingerprint, ids, name, waiting.size, waiting.sumOf { it.optLong("size") })
    }
}

internal class FileRequestNotifications(private val context: Context) {
    private val manager = context.getSystemService(NotificationManager::class.java)
    private var posted = emptyMap<String, IncomingFileRequest>()
    private var stopped = false

    @Synchronized
    fun update(snapshot: JSONObject, permitted: Boolean) {
        if (stopped) return
        val requests = incomingFileRequests(snapshot).associateBy { it.key }
        (posted.keys - requests.keys).forEach { manager.cancel(tag(it), ID) }
        if (permitted) requests.forEach { (key, request) ->
            if (posted[key] == request) return@forEach
            val open = openIntent(context)
            val compact = RemoteViews(context.packageName, R.layout.notification_file_request).apply {
                setTextViewText(R.id.file_request_sender, context.getString(R.string.files_from, request.name))
                setTextViewText(R.id.file_request_count, context.resources.getQuantityString(R.plurals.files_notification_count, request.count, request.count))
            }
            val expanded = RemoteViews(context.packageName, R.layout.notification_file_request_expanded).apply {
                setTextViewText(R.id.file_request_sender, context.getString(R.string.files_from, request.name))
                setTextViewText(R.id.file_request_count, context.resources.getQuantityString(R.plurals.files_notification_count, request.count, request.count))
            }
            val builder = Notification.Builder(context, CalabiApp.CHANNEL_FILES)
                .setSmallIcon(R.drawable.ic_tile).setContentTitle(context.getString(R.string.files_from, request.name))
                .setContentText(context.resources.getQuantityString(R.plurals.files_notification_count, request.count, request.count))
                .setSubText(context.getString(R.string.files_title)).setContentIntent(open)
                .setAutoCancel(true).setOnlyAlertOnce(true).setVisibility(Notification.VISIBILITY_PRIVATE)
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setStyle(Notification.DecoratedCustomViewStyle())
            listOf(true, false).forEach { accept ->
                val intent = Intent(context, FileRequestReceiver::class.java)
                    .setAction(if (accept) ACCEPT else REJECT)
                    .setData(Uri.parse("calabi-file-request://${tag(key)}/${request.stamp()}/${if (accept) "accept" else "reject"}"))
                    .putExtra("key", key).putExtra("fingerprint", request.fingerprint)
                    .putExtra("stamp", request.stamp())
                    .putStringArrayListExtra("ids", ArrayList(request.ids))
                val pending = PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                compact.setOnClickPendingIntent(if (accept) R.id.file_request_accept else R.id.file_request_reject, pending)
                val action = Notification.Action.Builder(
                    Icon.createWithResource(context, if (accept) R.drawable.ic_check else android.R.drawable.ic_menu_close_clear_cancel),
                    context.getString(if (accept) R.string.filetest_accept else R.string.filetest_reject), pending,
                )
                if (android.os.Build.VERSION.SDK_INT >= 31) action.setAuthenticationRequired(true)
                builder.addAction(action.build())
            }
            // Expanded/heads-up templates already include the standard action row.
            builder.setCustomContentView(compact).setCustomBigContentView(expanded).setCustomHeadsUpContentView(expanded)
            manager.notify(tag(key), ID, builder.build())
        }
        posted = if (permitted) requests else emptyMap()
        manager.cancel(ID) // Retire the old non-actionable, combined notification.
    }

    @Synchronized
    fun clear() { stopped = true; posted.keys.forEach { manager.cancel(tag(it), ID) }; posted = emptyMap(); manager.cancel(ID) }

    companion object {
        const val ID = 2
        const val ACCEPT = "net.calabi.app.files.ACCEPT"
        const val REJECT = "net.calabi.app.files.REJECT"
        fun tag(key: String) = MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).joinToString("") { "%02x".format(it) }
        fun openIntent(context: Context) = PendingIntent.getActivity(context, 2,
            Intent(context, MainActivity::class.java).putExtra("open_files", true),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }
}

/** Explicit, non-exported target. No public activity/deep link may accept files. */
class FileRequestReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!BuildConfig.FILE_TRANSFER_ENABLED || intent.action !in setOf(FileRequestNotifications.ACCEPT, FileRequestNotifications.REJECT)) return
        // Custom compact controls do not inherit Action.setAuthenticationRequired.
        // On a locked device, open review instead of executing a decision.
        if (context.getSystemService(KeyguardManager::class.java).isDeviceLocked) {
            runCatching { FileRequestNotifications.openIntent(context).send() }
            return
        }
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            val key = intent.getStringExtra("key").orEmpty()
            val manager = context.getSystemService(NotificationManager::class.java)
            try {
                val expectedIds = intent.getStringArrayListExtra("ids")?.sorted().orEmpty()
                val current = incomingFileRequests(CoreClient.call("GET", "/v1/files").json()).firstOrNull { it.key == key }
                // Reject stale, partial, already-decided and switched-identity actions alike.
                if (current == null || current.ids != expectedIds || current.fingerprint != intent.getStringExtra("fingerprint") || current.stamp() != intent.getStringExtra("stamp")) {
                    manager.cancel(FileRequestNotifications.tag(key), FileRequestNotifications.ID)
                    return@launch
                }
                val result = CoreClient.call("POST", "/v1/files/action", JSONObject().put("action", "decide")
                    .put("ids", JSONArray(current.ids)).put("accept", intent.action == FileRequestNotifications.ACCEPT))
                if (!result.ok) error(result.error(context.getString(R.string.filetest_failed)))
                manager.cancel(FileRequestNotifications.tag(key), FileRequestNotifications.ID)
            } catch (_: Exception) {
                manager.notify(FileRequestNotifications.tag(key), FileRequestNotifications.ID,
                    Notification.Builder(context, CalabiApp.CHANNEL_FILES).setSmallIcon(R.drawable.ic_tile)
                        .setContentTitle(context.getString(R.string.files_title)).setContentText(context.getString(R.string.files_notification_failed))
                        .setContentIntent(FileRequestNotifications.openIntent(context)).setAutoCancel(true).setVisibility(Notification.VISIBILITY_PRIVATE).build())
            } finally { pending.finish() }
        }
    }
}
