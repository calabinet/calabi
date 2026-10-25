package net.calabi.app.ui

import android.net.Uri
import android.os.CancellationSignal
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.calabi.app.CalabiApp
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private fun JSONObject.objects(key: String): List<JSONObject> = optJSONArray(key)?.let { a ->
    (0 until a.length()).mapNotNull { a.optJSONObject(it) }
}.orEmpty()

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun FileTransfersScreen(initialPeer: String?, shared: List<Uri>, onShareTaken: () -> Unit, onSendOpened: () -> Unit, devices: List<Device>, reviewIncoming: Boolean, onReviewOpened: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var snapshot by remember { mutableStateOf(JSONObject()) }
    var peer by rememberSaveable { mutableStateOf(initialPeer.orEmpty()) }
    var selected by remember { mutableStateOf(setOf<String>()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var exportId by rememberSaveable { mutableStateOf("") }
    var removing by remember { mutableStateOf<JSONObject?>(null) }
    var identityOperation by remember { mutableStateOf<String?>(null) }
    var sendSheet by rememberSaveable { mutableStateOf(false) }
    var settingsSheet by rememberSaveable { mutableStateOf(false) }
    var choosingPeer by rememberSaveable { mutableStateOf(false) }
    var category by rememberSaveable { mutableIntStateOf(0) }
    var direction by rememberSaveable { mutableIntStateOf(0) }
    LaunchedEffect(reviewIncoming) {
        if (reviewIncoming) {
            category = 1
            direction = 1
            sendSheet = false
            settingsSheet = false
            onReviewOpened()
        }
    }
    LaunchedEffect(initialPeer) {
        if (initialPeer != null) {
            peer = initialPeer
            choosingPeer = initialPeer.isBlank()
            sendSheet = true
            onSendOpened()
        }
    }
    val preparingCancelled = remember { AtomicBoolean(false) }
    val preparationSignal = remember { AtomicReference<CancellationSignal?>(null) }
    val failed = stringResource(R.string.filetest_failed)
    val saved = stringResource(R.string.filetest_saved)
    suspend fun refresh() { snapshot = CoreClient.call("GET", "/v1/files").json() }
    suspend fun action(body: JSONObject): Boolean {
        val result = CoreClient.call("POST", "/v1/files/action", body)
        message = if (result.ok) "" else fileErrorText(context, result.error(failed))
        if (result.ok && body.optString("action") == "forget_source") selected = selected - body.optString("id")
        refresh()
        return result.ok
    }
    fun runAction(name: String, id: String) { scope.launch { action(JSONObject().put("action", name).put("id", id)) } }
    suspend fun stage(uris: List<Uri>) {
        if (uris.isEmpty() || busy) return
        busy = true
        preparingCancelled.set(false)
        val signal = CancellationSignal()
        preparationSignal.set(signal)
        try {
            require(uris.size <= 32)
            val ids = withContext(Dispatchers.IO) {
                uris.map { uri ->
                    check(!preparingCancelled.get()) { context.getString(R.string.files_cancelled) }
                    require(uri.scheme == "content")
                    var name = "document"
                    var size = -1L
                    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null, signal)?.use { c ->
                        if (c.moveToFirst()) {
                            val n = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            val s = c.getColumnIndex(OpenableColumns.SIZE)
                            if (n >= 0) name = c.getString(n) ?: name
                            if (s >= 0 && !c.isNull(s)) size = c.getLong(s)
                        }
                    }
                    check(!preparingCancelled.get()) { context.getString(R.string.files_cancelled) }
                    val fd = context.contentResolver.openFileDescriptor(uri, "r", signal) ?: error(failed)
                    fd.use { CalabiApp.instance.core.stageFile(it.detachFd(), name, size) }
                }
            }
            selected = selected + ids.toSet()
            message = ""
        } catch (e: Exception) { message = fileErrorText(context, e.message ?: failed) }
        finally { preparationSignal.compareAndSet(signal, null); busy = false; refresh() }
    }
    LaunchedEffect(Unit) { while (true) { refresh(); delay(1000) } }
    LaunchedEffect(shared, snapshot.optBoolean("available")) {
        if (shared.isNotEmpty() && snapshot.optBoolean("available")) { sendSheet = true; stage(shared); onShareTaken() }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris -> scope.launch { stage(uris) } }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val id = exportId
        exportId = ""
        if (uri != null && id.isNotEmpty()) scope.launch {
            busy = true
            message = try { withContext(Dispatchers.IO) {
                exportVerifiedDocument(context.contentResolver, uri) { fd -> CalabiApp.instance.core.saveFile(id, fd) }
            }; saved } catch (e: Exception) { fileDocumentExportError(context, e) }
            busy = false
        }
    }
    val available = snapshot.optBoolean("available")
    val peers = snapshot.objects("peers").sortedWith(compareBy({ it.optString("name") }, { it.optString("ip") }))
    val staged = snapshot.objects("sources").sortedWith(compareBy({ it.optString("name") }, { it.optString("id") }))
    val received = snapshot.objects("received").sortedWith(compareBy(
        { it.optString("device_key") }, { it.optJSONObject("transfer")?.optString("batch").orEmpty() },
        { it.optJSONObject("transfer")?.optString("name").orEmpty() }, { it.optJSONObject("transfer")?.optString("id").orEmpty() },
    ))
    val jobs = snapshot.objects("jobs").sortedBy { it.optString("id") }
    val waitingCount = received.count { it.optJSONObject("transfer")?.optString("state") == "waiting" }
    val incomingGroups = received.groupBy { it.optString("device_key") + "/" + it.optJSONObject("transfer")?.optString("batch") }
    fun deviceName(ip: String) = peers.firstOrNull { it.optString("ip") == ip }?.optString("name")?.takeIf { it.isNotBlank() }
        ?: devices.firstOrNull { it.overlay == ip }?.name?.takeIf { it.isNotBlank() } ?: ip
    fun deviceIcon(ip: String) = devices.firstOrNull { it.overlay == ip }?.os?.let(::osIcon) ?: R.drawable.ic_laptop
    val snapshotError = snapshot.optString("error").let {
        if (it == "Reconnect to send or receive files. Local records and completed files remain available.") stringResource(R.string.files_reconnect) else fileErrorText(context, it)
    }
    val visibleGroups = incomingGroups.filterValues { group -> direction != 2 && group.any { matchesFileCategory(it.optJSONObject("transfer")?.optString("state").orEmpty(), category) } }
    val visibleJobs = jobs.filter { direction != 1 && matchesFileCategory(it.optString("state"), category) }

    LazyColumn(
        Modifier.fillMaxSize(), contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item("header") {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.files_center), style = Styles.screenTitle, modifier = Modifier.weight(1f))
                CircleButton(R.drawable.ic_settings, stringResource(R.string.files_settings), onClick = { settingsSheet = true })
            }
        }
        item("receiving") {
            Group {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.files_receiving), style = Styles.rowTitle)
                        Text(stringResource(R.string.files_receive_hint), style = Styles.hint)
                    }
                    Switch(checked = snapshot.optBoolean("receiving"), enabled = available && !busy, colors = calabiSwitchColors(), onCheckedChange = { enabled -> scope.launch { action(JSONObject().put("action", "receiving").put("enabled", enabled)) } })
                }
            }
        }
        item("send") {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.files_network_hint), style = Styles.hint, modifier = Modifier.weight(1f))
                Button(enabled = available, onClick = { choosingPeer = peer.isBlank(); sendSheet = true }) {
                    Glyph(R.drawable.ic_share, androidx.compose.ui.graphics.Color.White, 16.dp)
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.files_new_send))
                }
            }
        }
        if (message.isNotBlank() || snapshot.optString("error").isNotBlank() || !available) {
            item("error") {
                Text(message.ifBlank { snapshotError.ifBlank { context.getString(R.string.files_unavailable) } }, style = Styles.hint, color = Palette.danger)
            }
        }
        item("tabs") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(R.string.files_all_directions, R.string.files_incoming, R.string.files_outgoing).forEachIndexed { index, label ->
                    FilterChip(selected = direction == index, onClick = { direction = index }, label = { Text(stringResource(label)) })
                }
            }
            TabRow(selectedTabIndex = category, containerColor = Palette.ground, contentColor = Palette.ink) {
                listOf(R.string.files_active, R.string.files_pending, R.string.files_history).forEachIndexed { index, label ->
                    Tab(selected = category == index, onClick = { category = index }, text = {
                        Text(if (index == 1 && direction != 2 && waitingCount > 0) "${stringResource(label)} ($waitingCount)" else stringResource(label), maxLines = 1)
                    })
                }
            }
        }
        if (visibleGroups.isEmpty() && visibleJobs.isEmpty()) item("empty") {
            Column(Modifier.fillMaxWidth().padding(vertical = 36.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Glyph(R.drawable.ic_transfer, Palette.muted, 28.dp)
                Text(stringResource(when (category) { 1 -> R.string.files_empty_pending; 2 -> R.string.files_empty_history; else -> R.string.files_empty_active }), style = Styles.hint)
            }
        }
        visibleGroups.forEach { (batchKey, group) ->
            item("receive/$batchKey") {
                val waiting = group.mapNotNull { it.optJSONObject("transfer") }.filter { it.optString("state") == "waiting" }
                Group {
                    TransferHeading(false, stringResource(R.string.files_from, deviceName(group.first().optString("ip"))))
                    group.forEach { row -> row.optJSONObject("transfer")?.let { transfer ->
                        val state = transfer.optString("state")
                        if (matchesFileCategory(state, category)) {
                            val id = transfer.optString("id")
                            RowDivider()
                            TransferRecord(transfer, state, transfer.optString("error")) {
                                if (state == "completed") TextButton(enabled = !busy, onClick = { exportId = id; save.launch(transfer.optString("name")) }) { Text(stringResource(R.string.filetest_save)) }
                                if (state in listOf("receiving", "accepted", "waiting_sender")) {
                                    TextButton(enabled = !busy && transfer.optBoolean("pause_supported"), onClick = { runAction("pause_receive", id) }) { Text(stringResource(R.string.files_pause)) }
                                }
                                if (state == "paused") TextButton(enabled = !busy && available, onClick = { runAction("resume_receive", id) }) { Text(stringResource(R.string.files_resume)) }
                                if (state in listOf("receiving", "accepted", "waiting_sender", "paused")) TextButton(onClick = { runAction("cancel_receive", id) }) { Text(stringResource(R.string.filetest_stop)) }
                                if (state in terminalFileStates) TextButton(onClick = { removing = JSONObject().put("action", "forget_receive").put("id", id) }) { Text(stringResource(R.string.files_remove)) }
                            }
                        }
                    } }
                    if (category == 1 && waiting.isNotEmpty()) {
                        val completeOffer = group.size >= waiting.first().optInt("batch_count", 1)
                        if (!completeOffer) Text(stringResource(R.string.files_offer_loading), style = Styles.hint, modifier = Modifier.padding(horizontal = 16.dp))
                        FlowRow(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { scope.launch { action(JSONObject().put("action", "decide").put("ids", JSONArray(waiting.map { it.optString("id") })).put("accept", false)) } }) { Text(stringResource(R.string.filetest_reject)) }
                            Button(enabled = available && completeOffer, onClick = { scope.launch { action(JSONObject().put("action", "decide").put("ids", JSONArray(waiting.map { it.optString("id") })).put("accept", true)) } }) { Text(pluralStringResource(R.plurals.files_accept_count, waiting.size, waiting.size)) }
                        }
                    }
                }
            }
        }
        items(visibleJobs, key = { "send/" + it.optString("id") }) { job ->
            val id = job.optString("id")
            val state = job.optString("state")
            val file = job.optJSONObject("progress")?.optJSONObject("transfer") ?: JSONObject()
            Group {
                TransferHeading(true, stringResource(R.string.files_to, deviceName(job.optString("peer_ip"))))
                RowDivider()
                TransferRecord(file, state, job.optString("error"), job) {
                    if (state == "sending") TextButton(onClick = { runAction("pause", id) }) { Text(stringResource(R.string.files_pause)) }
                    if (state == "paused") TextButton(enabled = available, onClick = { scope.launch { action(JSONObject().put("action", "resume").put("id", id).put("peer", job.optString("peer_ip"))) } }) { Text(stringResource(if (job.optString("error").isNotBlank()) R.string.files_retry else R.string.files_resume)) }
                    if (state == "sending" || state == "paused") TextButton(onClick = { runAction("cancel", id) }) { Text(stringResource(R.string.filetest_stop)) }
                    else TextButton(onClick = { removing = JSONObject().put("action", "forget_job").put("id", id) }) { Text(stringResource(R.string.files_remove)) }
                }
            }
        }
    }
    if (sendSheet) ModalBottomSheet(
        onDismissRequest = { sendSheet = false }, containerColor = Palette.ground,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.9f).padding(horizontal = 20.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.files_new_send), style = Styles.section, modifier = Modifier.weight(1f))
                TextButton(onClick = { sendSheet = false }) { Text(stringResource(R.string.files_close)) }
            }
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val target = peers.firstOrNull { it.optString("ip") == peer }
            if (!choosingPeer && peer.isNotBlank()) {
                Group {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Glyph(deviceIcon(peer), Palette.muted, 24.dp)
                        Column(Modifier.weight(1f)) {
                            Text(deviceName(peer), style = Styles.rowTitle)
                            Text(peer, style = Styles.mono)
                            if (target?.optBoolean("receiving") != true) Text(stringResource(R.string.files_peer_disabled), style = Styles.hint)
                        }
                        TextButton(onClick = { choosingPeer = true }) { Text(stringResource(R.string.files_change_device)) }
                    }
                }
            } else {
                Text(stringResource(R.string.files_device), style = Styles.sectionLabel)
                if (peers.isEmpty()) Text(stringResource(R.string.files_no_devices), style = Styles.hint)
                Group {
                    peers.forEachIndexed { index, p ->
                        if (index > 0) RowDivider()
                        Row(Modifier.fillMaxWidth().clickable(enabled = p.optBoolean("receiving")) { peer = p.optString("ip"); choosingPeer = false }.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Glyph(deviceIcon(p.optString("ip")), Palette.muted, 24.dp)
                            Column(Modifier.weight(1f)) {
                                Text(p.optString("name").ifBlank { p.optString("ip") }, style = Styles.rowTitle)
                                Text(p.optString("ip"), style = Styles.mono)
                                Text(stringResource(if (p.optBoolean("receiving")) R.string.files_peer_ready else R.string.files_peer_disabled), style = Styles.hint)
                            }
                            if (p.optBoolean("receiving")) Glyph(R.drawable.ic_chevron_right, Palette.muted)
                        }
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.files_selected), style = Styles.sectionLabel, modifier = Modifier.weight(1f))
                TextButton(enabled = available && !busy, onClick = { picker.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.files_choose)) }
            }
            val preparing = (busy && preparationSignal.get() != null) || snapshot.optBoolean("preparing")
            if (preparing) {
                LinearProgressIndicator(Modifier.fillMaxWidth(), color = Palette.accent, trackColor = Palette.line)
                Text(stringResource(R.string.files_preparing_hint), style = Styles.hint)
                TextButton(onClick = { preparingCancelled.set(true); preparationSignal.get()?.cancel(); scope.launch { action(JSONObject().put("action", "cancel_preparing")) } }) { Text(stringResource(R.string.filetest_stop)) }
            }
            if (staged.isEmpty() && !preparing) Text(stringResource(R.string.files_empty_selection), style = Styles.hint, modifier = Modifier.padding(vertical = 24.dp))
            Group {
                staged.forEachIndexed { index, file ->
                    val id = file.optString("id")
                    if (index > 0) RowDivider()
                    Row(Modifier.fillMaxWidth().padding(end = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = selected.contains(id), enabled = !busy, onCheckedChange = { selected = if (it) selected + id else selected - id })
                        Column(Modifier.weight(1f).padding(vertical = 12.dp)) {
                            Text(file.optString("name"), style = Styles.row, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(fileBytes(file.optLong("size")), style = Styles.hint)
                        }
                        TextButton(enabled = !busy, onClick = { removing = JSONObject().put("action", "forget_source").put("id", id) }) { Text(stringResource(R.string.files_remove)) }
                    }
                }
            }
            }
            Text(stringResource(R.string.files_selection_summary, selected.size, fileBytes(staged.filter { it.optString("id") in selected }.sumOf { it.optLong("size") })), style = Styles.hint)
            if (message.isNotBlank()) Text(message, style = Styles.hint, color = Palette.danger)
            Button(
                modifier = Modifier.fillMaxWidth(), enabled = available && !busy && selected.isNotEmpty() && peers.any { it.optString("ip") == peer && it.optBoolean("receiving") } && !choosingPeer,
                onClick = { scope.launch {
                    if (busy) return@launch
                    busy = true
                    try {
                        if (action(JSONObject().put("action", "send").put("peer", peer).put("ids", JSONArray(selected.sorted())))) {
                            selected = emptySet(); sendSheet = false; category = 0; direction = 2
                        }
                    } finally { busy = false }
                } },
            ) { Text(stringResource(R.string.files_send, selected.size)) }
        }
    }
    if (settingsSheet) ModalBottomSheet(onDismissRequest = { settingsSheet = false }, containerColor = Palette.ground) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.files_settings), style = Styles.section)
            TextButton(onClick = { context.startActivity(android.content.Intent(android.provider.Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, context.packageName).putExtra(android.provider.Settings.EXTRA_CHANNEL_ID, CalabiApp.CHANNEL_FILES)) }) { Text(stringResource(R.string.files_notification_settings)) }
            Text(stringResource(R.string.files_hint), style = Styles.hint)
            snapshot.optJSONObject("identity")?.let { identity ->
                Group {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(stringResource(R.string.files_identity), style = Styles.rowTitle)
                        if (identity.optLong("expires_unix") > 0) Text(stringResource(R.string.files_identity_expires, java.text.DateFormat.getDateTimeInstance().format(java.util.Date(identity.optLong("expires_unix") * 1000))), style = Styles.hint)
                        if (identity.optString("error").isNotBlank()) Text(fileErrorText(context, identity.optString("error")), color = Palette.danger, style = Styles.hint)
                        else if (identity.optBoolean("needs_renewal")) Text(stringResource(R.string.files_identity_due), style = Styles.hint)
                        TextButton(enabled = !busy && identity.optString("fingerprint").isNotBlank(), onClick = { identityOperation = "renew" }) { Text(stringResource(R.string.files_identity_renew)) }
                        TextButton(enabled = !busy && identity.optBoolean("exists"), onClick = { identityOperation = "reset" }) { Text(stringResource(R.string.files_identity_reset)) }
                    }
                }
            }
        }
    }
    removing?.let { body -> AlertDialog(onDismissRequest = { removing = null }, title = { Text(stringResource(R.string.files_remove)) }, text = { Text(stringResource(R.string.files_remove_confirm)) }, confirmButton = { TextButton(onClick = { removing = null; scope.launch { action(body) } }) { Text(stringResource(R.string.files_remove)) } }, dismissButton = { TextButton(onClick = { removing = null }) { Text(stringResource(R.string.settings_cancel)) } }) }
    identityOperation?.let { operation -> AlertDialog(onDismissRequest = { identityOperation = null }, title = { Text(stringResource(if (operation == "renew") R.string.files_identity_renew else R.string.files_identity_reset)) }, text = { Text(stringResource(R.string.files_identity_confirm)) }, confirmButton = { TextButton(onClick = { identityOperation = null; scope.launch { busy = true; try { action(JSONObject().put("action", "identity_$operation").put("confirmed", true)) } finally { busy = false } } }) { Text(stringResource(if (operation == "renew") R.string.files_identity_renew else R.string.files_identity_reset)) } }, dismissButton = { TextButton(onClick = { identityOperation = null }) { Text(stringResource(R.string.settings_cancel)) } }) }
}

private fun fileBytes(n: Long): String = when { n >= 1L shl 30 -> "%.2f GiB".format(n.toDouble() / (1L shl 30)); n >= 1L shl 20 -> "%.1f MiB".format(n.toDouble() / (1L shl 20)); n >= 1024 -> "%.1f KiB".format(n / 1024.0); else -> "$n B" }
@Composable private fun fileState(state: String): String = stringResource(when (state) { "waiting" -> R.string.files_waiting; "verifying", "committing" -> R.string.files_verifying; "accepted" -> R.string.files_accepted_waiting; "hashing" -> R.string.files_hashing; "connecting" -> R.string.files_connecting; "receiving", "sending" -> R.string.files_transferring; "completed" -> R.string.files_completed; "paused" -> R.string.files_paused; "receiver_paused" -> R.string.files_receiver_paused; "waiting_sender" -> R.string.files_waiting_sender; "interrupted" -> R.string.files_interrupted; "receiver_cancelled" -> R.string.files_receiver_cancelled; "receiver_rejected" -> R.string.files_receiver_rejected; "receiver_failed" -> R.string.files_receiver_failed; "sender_cancelled" -> R.string.files_sender_cancelled; "cancel_pending" -> R.string.files_cancel_pending; "cancelled" -> R.string.files_cancelled; "failed" -> R.string.files_failed; else -> R.string.files_preparing })

private val terminalFileStates = setOf("completed", "cancelled", "failed")

@Composable
private fun TransferHeading(outgoing: Boolean, peer: String) {
    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(if (outgoing) R.string.files_outgoing else R.string.files_incoming),
            style = Styles.rowTitle, color = if (outgoing) Palette.accent else Palette.ink,
            modifier = Modifier.background(Palette.sunken, RoundedCornerShape(6.dp)).padding(horizontal = 10.dp, vertical = 6.dp))
        Text(peer, style = Styles.hint, modifier = Modifier.weight(1f))
    }
}
private fun matchesFileCategory(state: String, category: Int): Boolean = when (category) {
    1 -> state == "waiting"
    2 -> state in terminalFileStates
    else -> state != "waiting" && state !in terminalFileStates
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TransferRecord(file: JSONObject, state: String, error: String, metrics: JSONObject = file, actions: @Composable RowScope.() -> Unit) {
    val phase = file.optString("state")
    val preparation = if (state == "sending") metrics.optJSONObject("progress")?.optJSONObject("preparation") else null
    val displayState = when {
        state == "cancelled" && metrics.optString("stop_reason").isNotBlank() -> metrics.optString("stop_reason")
        metrics.optBoolean("cancel_pending") -> "cancel_pending"
        state == "paused" && error.isNotBlank() -> "interrupted"
        preparation?.optString("phase") in setOf("hashing", "connecting") -> preparation!!.optString("phase")
        state == "sending" && phase == "paused" -> "receiver_paused"
        state == "sending" && phase in setOf("preparing", "waiting", "verifying", "committing") -> phase
        else -> state
    }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(40.dp).background(Palette.sunken, RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) { Glyph(R.drawable.ic_file, Palette.muted) }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(file.optString("name").ifBlank { stringResource(R.string.files_preparing) }, style = Styles.rowTitle, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(fileState(displayState), style = Styles.hint)
            }
        }
        val size = file.optLong("size")
        val offset = file.optLong("offset")
        if (displayState in setOf("preparing", "verifying", "committing", "hashing", "connecting")) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Palette.accent, trackColor = Palette.line)
        } else if (state !in terminalFileStates && displayState != "waiting") {
            LinearProgressIndicator(progress = { if (size > 0) (offset.toDouble() / size).toFloat().coerceIn(0f, 1f) else 0f }, modifier = Modifier.fillMaxWidth(), color = Palette.accent, trackColor = Palette.line)
        }
        Text("${fileBytes(offset)} / ${fileBytes(size)}", style = Styles.mono)
        val rate = metrics.optLong("rate_bps", file.optLong("rate_bps"))
        if (rate > 0 && displayState in setOf("sending", "receiving", "accepted")) Text(stringResource(R.string.files_rate_eta, fileBytes(rate), metrics.optLong("remaining_seconds", file.optLong("remaining_seconds"))), style = Styles.hint)
        if (error.isNotBlank() && state != "cancelled" && !metrics.optBoolean("cancel_pending")) Text(fileErrorText(LocalContext.current, error), color = Palette.danger, style = Styles.hint)
        if (metrics === file && state in setOf("receiving", "accepted", "waiting_sender") && !file.optBoolean("pause_supported")) Text(stringResource(R.string.files_update_sender), style = Styles.hint)
        if (metrics.optBoolean("cancel_pending") && metrics.optString("stop_reason").isNotBlank()) Text(stringResource(R.string.files_cancel_pending), style = Styles.hint)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, content = actions)
    }
}
