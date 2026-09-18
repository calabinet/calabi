package net.calabi.app.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import net.calabi.app.ApiResult
import net.calabi.app.AppPrefs
import net.calabi.app.CalabiApp
import net.calabi.app.CoreClient
import org.json.JSONArray
import org.json.JSONObject

/** A device on the meshnet, joined from the org's list and this phone's live view. */
data class Device(
    val name: String,
    val os: String,
    val overlay: String,
    val online: Boolean,
    /** An admin approved its default route, so it can be chosen as the exit. */
    val offersExit: Boolean,
    val services: List<Service>,
    /** "direct" / "relay" when this phone has a live path to it, else null. */
    val path: String?,
    val rttMicros: Long,
)

data class Service(val name: String, val proto: String, val port: Int)

/** This phone's own connection (GET /v1/mesh). */
data class Connection(
    val state: String,
    val error: String,
    val name: String,
    val overlay: String,
    /** This phone's address in the org's meshnet, remembered while disconnected. */
    val selfOverlay: String,
    val exitNode: String,
    val peers: JSONArray,
)

data class Org(val id: Long, val name: String, val personal: Boolean)

/** A device of this user's that this phone could be replacing (GET /v1/mesh/replaceable). */
data class OldDevice(val id: Long, val name: String, val overlay: String, val lastSeen: String, val disabled: Boolean)

/** GET /v1/usage/overview; a part the core could not read is null. */
data class UsageOverview(
    val plan: String,
    val month: MonthUsage?,
    val days: List<DayUsage>,
    val devices: SeatUsage?,
)

data class MonthUsage(
    val usedBytes: Long,
    /** > 0 a cap, -1 unlimited, 0 unknown. */
    val limitBytes: Long,
    val tunnelBytes: Long,
    val relayBytes: Long,
    val selfHostedBytes: Long,
)

data class DayUsage(val start: String, val bytes: Long)

data class SeatUsage(val used: Long, val disabled: Long, val limit: Long, val own: Boolean)

/**
 * What the signed-in screens show, shared by the devices and settings tabs so a
 * change made in one (the exit device, subnet routes, the organization) is what
 * the other shows.
 */
class AppModel {
    var connected by mutableStateOf(false)
        private set
    var connection by mutableStateOf<Connection?>(null)
        private set
    var nodes by mutableStateOf<JSONArray?>(null)
        private set
    var nodesError by mutableStateOf<String?>(null)
        private set
    var email by mutableStateOf("")
        private set
    var activeOrgId by mutableLongStateOf(0L)
        private set
    var orgs by mutableStateOf(emptyList<Org>())
        private set
    var deviceName by mutableStateOf("")
        private set
    var exitNode by mutableStateOf("")
        private set
    var acceptRoutes by mutableStateOf(true)
        private set
    var role by mutableStateOf("")
        private set
    var tunnels by mutableStateOf<List<Tunnel>?>(null)
        private set
    var tunnelsError by mutableStateOf<String?>(null)
        private set
    var usage by mutableStateOf<UsageOverview?>(null)
        private set
    var usageError by mutableStateOf<String?>(null)
        private set
    var replaceable by mutableStateOf(emptyList<OldDevice>())
        private set
    /** The VPN was left on and the phone stopped the app since (AppPrefs.vpnStoppedFromOutside). */
    var stoppedInBackground by mutableStateOf(false)
        private set

    /** Owners, admins and auditors see the org's tunnels; everyone else their own. */
    val seesOnlyOwnTunnels: Boolean get() = role.isNotBlank() && role !in setOf("owner", "admin", "auditor")

    val devices: List<Device> get() = joinDevices(nodes, connection)
    val activeOrg: Org? get() = orgs.firstOrNull { it.id == activeOrgId }

    suspend fun refreshLive() {
        connected = CoreClient.call("GET", "/v1/state").json().optBoolean("connected")
        stoppedInBackground = AppPrefs.vpnStoppedFromOutside(CalabiApp.instance)
        val m = CoreClient.call("GET", "/v1/mesh").json()
        connection = Connection(
            state = m.optString("state"), error = m.optString("error"), name = m.optString("name"),
            overlay = m.optString("overlay"), selfOverlay = m.optString("self_overlay"), exitNode = m.optString("exit_node"),
            peers = m.optJSONArray("peers") ?: JSONArray(),
        )
    }

    suspend fun refreshNodes() {
        val r = CoreClient.call("GET", "/v1/mesh/nodes")
        if (r.ok) {
            nodes = r.json().optJSONArray("items") ?: JSONArray()
            nodesError = null
        } else {
            nodesError = r.error("HTTP ${r.status}")
        }
    }

    suspend fun refreshAccount() {
        val st = CoreClient.call("GET", "/v1/state").json()
        email = st.optString("email")
        activeOrgId = st.optLong("active_org_id")
        val s = CoreClient.call("GET", "/v1/settings").json()
        deviceName = s.optString("device_name")
        exitNode = s.optString("exit_node")
        acceptRoutes = s.optBoolean("accept_routes", true)
        val me = CoreClient.call("GET", "/v1/me")
        if (me.ok) role = me.json().optString("role")
        val o = CoreClient.call("GET", "/v1/orgs")
        if (o.ok) {
            val items = o.json().optJSONArray("items")
            orgs = buildList {
                if (items != null) for (i in 0 until items.length()) {
                    val it = items.getJSONObject(i)
                    add(Org(it.optLong("id"), it.optString("name"), it.optString("kind") == "personal"))
                }
            }
        }
    }

    /** The user saw the notice and is not reconnecting: stop showing it. */
    fun dismissStopped() {
        AppPrefs.markVpnDown(CalabiApp.instance)
        stoppedInBackground = false
    }

    /** Changes settings; a running connection restarts to use them. */
    suspend fun saveSettings(change: JSONObject): ApiResult {
        val r = CoreClient.call("PUT", "/v1/settings", change)
        refreshAccount()
        refreshLive()
        return r
    }

    suspend fun switchOrg(id: Long): ApiResult {
        val r = CoreClient.call("POST", "/v1/orgs/switch", JSONObject().put("target_org_id", id))
        // What was shown belongs to the organization just left.
        tunnels = null
        usage = null
        replaceable = emptyList()
        refreshAccount()
        refreshNodes()
        refreshReplaceable()
        return r
    }

    suspend fun refreshTunnels() {
        val r = CoreClient.call("GET", "/v1/tunnels")
        if (r.ok) {
            val items = r.json().optJSONArray("items")
            tunnels = buildList {
                if (items != null) for (i in 0 until items.length()) add(parseTunnel(items.getJSONObject(i)))
            }
            tunnelsError = null
        } else {
            tunnelsError = r.error("HTTP ${r.status}")
        }
    }

    suspend fun refreshUsage() {
        val tz = java.util.TimeZone.getDefault().id
        val r = CoreClient.call("GET", "/v1/usage/overview?tz=" + java.net.URLEncoder.encode(tz, "UTF-8"))
        if (!r.ok) {
            usageError = r.error("HTTP ${r.status}")
            return
        }
        val o = r.json()
        val month = o.optJSONObject("month")?.let {
            MonthUsage(
                it.optLong("used_bytes"), it.optLong("limit_bytes"), it.optLong("tunnel_bytes"),
                it.optLong("relay_bytes"), it.optLong("self_hosted_bytes"),
            )
        }
        val days = buildList {
            o.optJSONArray("days")?.let { a ->
                for (i in 0 until a.length()) a.getJSONObject(i).let { add(DayUsage(it.optString("start"), it.optLong("bytes"))) }
            }
        }
        val devices = o.optJSONObject("devices")?.let {
            SeatUsage(it.optLong("used"), it.optLong("disabled"), it.optLong("limit"), it.optBoolean("own"))
        }
        usage = UsageOverview(o.optString("plan"), month, days, devices)
        usageError = null
    }

    suspend fun refreshReplaceable() {
        val r = CoreClient.call("GET", "/v1/mesh/replaceable")
        if (!r.ok) return
        val items = r.json().optJSONArray("items")
        replaceable = buildList {
            if (items != null) for (i in 0 until items.length()) {
                val it = items.getJSONObject(i)
                add(OldDevice(it.optLong("id"), it.optString("name"), it.optString("overlay"), it.optString("last_seen"), it.optBoolean("disabled")))
            }
        }
    }

    /** Deletes the old device and gives its name to this phone. */
    suspend fun replace(old: OldDevice): ApiResult {
        val r = CoreClient.call("POST", "/v1/mesh/replace", JSONObject().put("node_id", old.id))
        refreshAccount()
        refreshNodes()
        refreshReplaceable()
        refreshLive()
        return r
    }
}

/**
 * The org's devices (GET /v1/mesh/nodes), whether or not this phone is connected,
 * annotated with this phone's live path to each.
 */
private fun joinDevices(nodes: JSONArray?, connection: Connection?): List<Device> {
    val peersByOverlay = HashMap<String, JSONObject>()
    connection?.peers?.let { peers ->
        for (i in 0 until peers.length()) {
            val p = peers.getJSONObject(i)
            val ips = p.optJSONArray("allowed_ips") ?: continue
            for (j in 0 until ips.length()) {
                val ip = ips.getString(j)
                if (ip.startsWith("100.") && ip.endsWith("/32")) peersByOverlay[ip.removeSuffix("/32")] = p
            }
        }
    }
    val self = connection?.selfOverlay.orEmpty().ifBlank { connection?.overlay.orEmpty() }
    val out = ArrayList<Device>()
    val list = nodes ?: return out
    for (i in 0 until list.length()) {
        val n = list.getJSONObject(i)
        val overlay = n.optString("overlay")
        if (overlay.isNotBlank() && overlay == self) continue // this phone
        if (n.optBoolean("disabled")) continue
        val peer = peersByOverlay[overlay]
        val services = ArrayList<Service>()
        n.optJSONArray("services")?.let { svcs ->
            for (j in 0 until svcs.length()) {
                val s = svcs.getJSONObject(j)
                services += Service(s.optString("name"), s.optString("proto"), s.optInt("port"))
            }
        }
        var offersExit = false
        n.optJSONArray("approved_routes")?.let { approved ->
            for (j in 0 until approved.length()) if (approved.getString(j).endsWith("/0")) offersExit = true
        }
        out += Device(
            name = n.optString("name"), os = n.optString("os"), overlay = overlay,
            online = n.optBoolean("online"), offersExit = offersExit, services = services,
            path = peer?.optString("path"), rttMicros = peer?.optLong("rtt_micros") ?: 0,
        )
    }
    return out.sortedWith(compareByDescending<Device> { it.online }.thenBy { it.name })
}
