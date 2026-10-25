package net.calabi.app.ui

import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.calabi.app.CalabiApp
import net.calabi.app.CoreClient
import net.calabi.app.R
import org.json.JSONObject

/** Debug-only harness. No listener starts until the local user pairs a peer. */
@Composable
fun FileTransferTestScreen(model: AppModel, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var snapshot by remember { mutableStateOf(JSONObject()) }
    var peer by rememberSaveable { mutableStateOf("") }
    var pin by rememberSaveable { mutableStateOf("") }
    var kbps by rememberSaveable { mutableStateOf("512") }
    var exportId by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var clearing by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    val failure = stringResource(R.string.filetest_failed)
    val saved = stringResource(R.string.filetest_saved)
    val unsupported = stringResource(R.string.filetest_source_unavailable)
    suspend fun refresh() { snapshot = CoreClient.call("GET", "/v1/filetest").json() }
    suspend fun decide(id: String, accept: Boolean = false, cancel: Boolean = false) {
        val result = CoreClient.call("POST", "/v1/filetest/decide", JSONObject().put("id", id).put("accept", accept).put("cancel", cancel))
        message = if (result.ok) "" else result.error(failure)
        refresh()
    }

    LaunchedEffect(Unit) {
        while (true) { refresh(); delay(1000) }
    }

    val chooseFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            busy = true
            message = try {
                withContext(Dispatchers.IO) {
                    var name = "document"
                    var size = -1L
                    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            if (nameColumn >= 0) name = cursor.getString(nameColumn) ?: name
                            val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
                            if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) size = cursor.getLong(sizeColumn)
                        }
                    }
                    check(size >= 0) { unsupported }
                    val descriptor = context.contentResolver.openFileDescriptor(uri, "r") ?: error(unsupported)
                    descriptor.use { CalabiApp.instance.core.sendFileTest(it.detachFd(), name, size) }
                }
                ""
            } catch (e: Exception) { e.message ?: failure }
            busy = false
            refresh()
        }
    }
    val saveFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val id = exportId
        if (uri != null && id.isNotBlank()) scope.launch {
            busy = true
            message = try {
                withContext(Dispatchers.IO) {
                    val descriptor = context.contentResolver.openFileDescriptor(uri, "w") ?: error(failure)
                    descriptor.use { CalabiApp.instance.core.saveFileTest(id, it.detachFd()) }
                }
                saved
            } catch (e: Exception) { e.message ?: failure }
            busy = false
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TopBar(onBack)
        Text(stringResource(R.string.filetest_title), style = Styles.screenTitle)
        Text(stringResource(R.string.filetest_hint), style = Styles.hint)
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(model.connection?.overlay.orEmpty(), style = Styles.mono)
                Text(snapshot.optString("fingerprint"), style = Styles.mono)
            }
        }
        val running = snapshot.optBoolean("running")
        val sending = snapshot.optBoolean("sending")
        if (!running) {
            LabeledField(stringResource(R.string.filetest_peer), peer, { peer = it })
            LabeledField(stringResource(R.string.filetest_pin), pin, { pin = it })
            LabeledField(stringResource(R.string.filetest_rate), kbps, { kbps = it }, keyboardType = KeyboardType.Number)
            PrimaryButton(stringResource(R.string.filetest_start), enabled = !busy && peer.isNotBlank() && pin.length == 64 && kbps.toIntOrNull() != null, onClick = {
                scope.launch {
                    busy = true
                    val result = CoreClient.call("POST", "/v1/filetest/start", JSONObject().put("peer_ip", peer.trim()).put("fingerprint", pin.trim()).put("kbps", kbps.toInt()).put("port", 17401))
                    message = if (result.ok) "" else result.error(failure)
                    busy = false
                    refresh()
                }
            })
        }
        if (running) {
            PrimaryButton(stringResource(R.string.filetest_send), enabled = !busy && !sending, onClick = { chooseFile.launch(arrayOf("*/*")) })
            TextButton(onClick = { scope.launch { CoreClient.call("POST", "/v1/filetest/stop"); refresh() } }) {
                Text(stringResource(R.string.filetest_stop))
            }
        }
        val outgoing = snapshot.optJSONObject("outgoing")
        if (outgoing != null && outgoing.optString("id").isNotBlank()) {
            Text(stringResource(R.string.filetest_outgoing, outgoing.optString("name"), outgoing.optLong("offset"), outgoing.optLong("size")), style = Styles.hint)
        }
        val transfers = snapshot.optJSONArray("transfers")
        if (transfers != null) for (i in 0 until transfers.length()) {
            val file = transfers.getJSONObject(i)
            val id = file.optString("id")
            Group {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(file.optString("name"), style = Styles.rowTitle)
                    Text(stringResource(R.string.filetest_progress, file.optLong("offset"), file.optLong("size"), file.optString("state")), style = Styles.hint)
                    if (file.optString("state") == "waiting") {
                        Row {
                            TextButton(onClick = { scope.launch { decide(id, accept = true) } }) { Text(stringResource(R.string.filetest_accept)) }
                            TextButton(onClick = { scope.launch { decide(id) } }) { Text(stringResource(R.string.filetest_reject)) }
                        }
                    } else if (file.optString("state") == "completed") {
                        TextButton(enabled = !busy, onClick = { exportId = id; saveFile.launch(file.optString("name")) }) { Text(stringResource(R.string.filetest_save)) }
                    } else if (file.optString("state") == "accepted" || file.optString("state") == "receiving") {
                        TextButton(onClick = { scope.launch { decide(id, cancel = true) } }) { Text(stringResource(R.string.filetest_stop)) }
                    }
                }
            }
        }
        val error = snapshot.optString("error")
        if (error.isNotBlank()) Text(error, color = Palette.danger)
        if (message.isNotBlank()) Text(message, style = Styles.hint)
        TextButton(enabled = !busy && !sending, onClick = { clearing = true }) { Text(stringResource(R.string.filetest_clear), color = Palette.danger) }
    }
    if (clearing) AlertDialog(
        onDismissRequest = { clearing = false },
        title = { Text(stringResource(R.string.filetest_clear)) },
        text = { Text(stringResource(R.string.filetest_clear_hint)) },
        confirmButton = { TextButton(onClick = {
            clearing = false
            scope.launch {
                val result = CoreClient.call("POST", "/v1/filetest/clear")
                message = if (result.ok) "" else result.error(failure)
                refresh()
            }
        }) { Text(stringResource(R.string.filetest_clear)) } },
        dismissButton = { TextButton(onClick = { clearing = false }) { Text(stringResource(R.string.filetest_reject)) } },
    )
}
