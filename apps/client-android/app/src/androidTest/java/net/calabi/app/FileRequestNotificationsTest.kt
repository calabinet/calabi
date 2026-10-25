package net.calabi.app

import android.app.NotificationManager
import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.SystemClock
import android.app.Instrumentation
import android.app.Activity
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

@Suppress("DEPRECATION")
class FileRequestNotificationsTest : Instrumentation() {
    private var preview = false
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); preview = arguments?.getString("preview") == "true"; start() }
    override fun onStart() {
        val results = Bundle()
        try {
            testIncompleteOffersAndDifferentSendersNeverMerge()
            testCompleteBatchIsStableAcrossPollingOrder()
            testDuplicateIdsAndUnavailableIdentityCannotProduceActions()
            testDecisionAndIdentityChangesInvalidateCapturedRequest()
            testActionReceiverIsNotExported()
            testRealNotificationHasTwoActionsAndStaleAcceptDoesNotAcceptAnyFile()
            results.putString("stream", "\n6 notification tests passed\n")
            finish(Activity.RESULT_OK, results)
        } catch (error: Throwable) {
            results.putString("stream", error.stackTraceToString())
            results.putString("failure", error.toString())
            finish(Activity.RESULT_CANCELED, results)
        }
    }
    private fun assertTrue(value: Boolean) = check(value)
    private fun assertFalse(value: Boolean) = check(!value)
    private fun assertEquals(expected: Any?, actual: Any?) = check(expected == actual) { "Expected $expected, got $actual" }
    private fun row(id: String, sender: String = "notification-test-sender", state: String = "waiting") = JSONObject()
        .put("device_key", sender).put("ip", "100.64.0.2")
        .put("transfer", JSONObject().put("id", id).put("batch", "notification-test-batch")
            .put("batch_count", 2).put("state", state).put("name", "$id.txt").put("size", 4))
    private fun snapshot(vararg rows: JSONObject) = JSONObject().put("available", true)
        .put("identity", JSONObject().put("fingerprint", "notification-test-identity"))
        .put("received", JSONArray(rows.toList()))

    fun testIncompleteOffersAndDifferentSendersNeverMerge() {
        assertTrue(incomingFileRequests(snapshot(row("a"))).isEmpty())
        assertTrue(incomingFileRequests(snapshot(row("a"), row("b", "other"))).isEmpty())
    }

    fun testCompleteBatchIsStableAcrossPollingOrder() {
        val before = incomingFileRequests(snapshot(row("b"), row("a"))).single()
        val after = incomingFileRequests(snapshot(row("a"), row("b"))).single()
        assertEquals(before, after)
        assertEquals(listOf("a", "b"), before.ids)
        assertEquals(8L, before.bytes)
    }

    fun testDuplicateIdsAndUnavailableIdentityCannotProduceActions() {
        assertTrue(incomingFileRequests(snapshot(row("a"), row("a"))).isEmpty())
        assertTrue(incomingFileRequests(snapshot(row("a"), row("b")).put("available", false)).isEmpty())
        assertTrue(incomingFileRequests(snapshot(row("a"), row("b")).put("identity", JSONObject())).isEmpty())
    }

    fun testDecisionAndIdentityChangesInvalidateCapturedRequest() {
        val original = incomingFileRequests(snapshot(row("a"), row("b"))).single()
        assertFalse(incomingFileRequests(snapshot(row("a"), row("b", state = "cancelled"))).contains(original))
        val renewed = snapshot(row("a"), row("b")).put("identity", JSONObject().put("fingerprint", "renewed"))
        assertFalse(incomingFileRequests(renewed).contains(original))
    }

    fun testActionReceiverIsNotExported() {
        val context = targetContext
        val info = context.packageManager.getReceiverInfo(ComponentName(context, FileRequestReceiver::class.java), PackageManager.MATCH_DISABLED_COMPONENTS)
        assertFalse(info.exported)
    }

    fun testRealNotificationHasTwoActionsAndStaleAcceptDoesNotAcceptAnyFile() {
        val context = targetContext
        val manager = context.getSystemService(NotificationManager::class.java)
        val notifier = FileRequestNotifications(context)
        val request = incomingFileRequests(snapshot(row("a"), row("b"))).single()
        val tag = FileRequestNotifications.tag(request.key)
        try {
            notifier.update(snapshot(row("a"), row("b")), true)
            val notification = manager.activeNotifications.single { it.tag == tag }.notification
            assertEquals(2, notification.actions.size)
            assertTrue(notification.contentView != null)
            assertTrue(notification.headsUpContentView != null)
            val view = notification.contentView.apply(context, null)
            assertTrue(view.findViewById<android.view.View>(R.id.file_request_accept).hasOnClickListeners())
            assertTrue(view.findViewById<android.view.View>(R.id.file_request_reject).hasOnClickListeners())
            val expanded = notification.bigContentView.apply(context, null)
            assertTrue(expanded.findViewById<android.view.View>(R.id.file_request_accept) == null)
            assertTrue(expanded.findViewById<android.view.View>(R.id.file_request_reject) == null)
            if (preview) SystemClock.sleep(30000) // Optional visual inspection of this fake request only.
            notification.actions[0].actionIntent.send()
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (manager.activeNotifications.any { it.tag == tag } && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
            assertFalse(manager.activeNotifications.any { it.tag == tag })
        } finally { notifier.clear() }
    }
}
