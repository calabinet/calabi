package net.calabi.app

import org.json.JSONObject

/** Error copy follows the app's current Android locale, with English fallback. */
internal object UserErrors {
    private val catalog by lazy { load("user-error-catalog.json") }
    private val locales by lazy { load("user-error-locales.json") }
    private val rules by lazy {
        val array = catalog.getJSONArray("rules")
        (0 until array.length()).map { index ->
            val rule = array.getJSONObject(index)
            rule to Regex(rule.getString("pattern"), RegexOption.IGNORE_CASE)
        }
    }

    private fun load(name: String): JSONObject = CalabiApp.instance.assets.open(name).bufferedReader().use {
        JSONObject(it.readText())
    }

    private fun language(): String {
        val tag = CalabiApp.instance.resources.configuration.locales[0].toLanguageTag()
        if (locales.has(tag)) return tag
        if (tag.startsWith("zh", ignoreCase = true)) {
            return if (tag.contains("Hant") || tag.contains("TW") || tag.contains("HK")) "zh-TW" else "zh-CN"
        }
        val base = tag.substringBefore('-')
        return if (locales.has(base)) base else "en"
    }

    private fun text(section: String, key: String): String? =
        locales.optJSONObject(language())?.optJSONObject(section)?.optString(key)?.takeIf { it.isNotEmpty() }
            ?: locales.optJSONObject("en")?.optJSONObject(section)?.optString(key)?.takeIf { it.isNotEmpty() }

    private val resources = mapOf(
        "organization" to "organization", "device" to "device", "tunnel" to "tunnel",
        "order" to "order", "subscription" to "subscription", "invoice" to "invoice",
        "certificate" to "certificate", "domain" to "domain", "task" to "task", "session" to "session",
        "API key" to "apiKey", "support ticket" to "supportTicket", "account" to "account",
        "plan" to "plan", "capture" to "capture", "TCP/UDP tunnels" to "tcpUdpTunnels",
        "reserved subdomains" to "reservedSubdomains", "resources" to "resources"
    )
    private val slot = Regex("\\{\\{([a-zA-Z]+)\\}\\}")

    private fun render(key: String, args: JSONObject? = null): String? {
        val template = if (key.startsWith("business.")) text("apiBusinessErrors", key.removePrefix("business."))
            else text("apiErrors", key)
        if (template == null) return null
        if (slot.findAll(template).any { args?.has(it.groupValues[1]) != true }) return null
        if (slot.findAll(template).any { match ->
            val name = match.groupValues[1]
            val rule = catalog.getJSONObject("arguments").optJSONObject(name)
            val value = args?.optString(name).orEmpty()
            if (rule == null) true
            else if (rule.has("pattern")) !Regex(rule.getString("pattern")).matches(value)
            else {
                val values = rule.getJSONArray("values")
                (0 until values.length()).none { values.getString(it) == value }
            }
        }) return null
        return slot.replace(template) { match ->
            val name = match.groupValues[1]
            val value = args?.optString(name).orEmpty()
            if (name == "resource") resources[value]?.let { text("apiErrorResources", it) } ?: value else value
        }
    }

    private fun matchBusiness(raw: String, code: String): Pair<String, JSONObject>? {
        var msg = raw.trim().replace(Regex("^calabi: code=\\d+\\s+"), "")
        while (msg.contains("rpc error: code = ")) {
            val match = Regex("rpc error: code = (\\w+) desc = ([\\s\\S]*)").find(msg) ?: return null
            if (match.groupValues[1] in setOf("Internal", "Unknown", "DataLoss", "Unavailable", "DeadlineExceeded")) return null
            msg = match.groupValues[2]
        }
        val mapped = catalog.getJSONObject("codes").optString(code)
        if (mapped.isNotEmpty()) return "business.$mapped" to JSONObject()
        for ((rule, regex) in rules) {
            val match = regex.matchEntire(msg) ?: continue
            val args = JSONObject(rule.optJSONObject("constants")?.toString() ?: "{}")
            val captures = rule.optJSONObject("args")
            captures?.keys()?.forEach { name -> args.put(name, match.groupValues[captures.getInt(name)]) }
            return "business.${rule.getString("key")}" to args
        }
        return null
    }

    fun render(body: JSONObject, status: Int, fallback: String): String {
        val raw = body.optString("error")
        val key = body.optString("error_key")
        val transport = when {
            Regex("(?:Internal|Unknown|DataLoss) desc =").containsMatchIn(raw) -> "internal"
            raw.contains("Unavailable desc =") -> "unavailable"
            raw.contains("DeadlineExceeded desc =") -> "timeout"
            raw.contains("Canceled desc =") -> "cancelled"
            else -> null
        }
        var result = transport?.let { render(it) } ?: render(key, body.optJSONObject("error_args"))
        if (result == null && status < 500) {
            val reason = matchBusiness(raw, body.optString("code"))
            if (reason != null) result = render(reason.first, reason.second)
        }
        if (result == null) {
            val generic = when {
                Regex("(?:Internal|Unknown|DataLoss) desc =").containsMatchIn(raw) -> "internal"
                raw.contains("DeadlineExceeded") || raw.contains("timeout", ignoreCase = true) -> "timeout"
                raw.contains("Canceled desc =") -> "cancelled"
                raw.contains("Unimplemented") || status == 501 || status == 405 -> "unsupported"
                Regex("dial tcp|connection refused|connection reset|transport:|cannot reach|unreachable", RegexOption.IGNORE_CASE).containsMatchIn(raw) -> "unavailable"
                raw.contains("Unavailable") || status == 502 || status == 503 -> "unavailable"
                status == 504 || status == 408 -> "timeout"
                status >= 500 -> "internal"
                status == 401 -> "unauthenticated"
                status == 403 -> "forbidden"
                status == 404 -> "notFound"
                status == 409 -> "conflict"
                status == 412 -> "precondition"
                status == 429 -> "quota"
                else -> "invalid"
            }
            // Free text from older servers is not a reliable localization key.
            result = render(generic) ?: fallback
        }
        val hints = body.optJSONArray("hints")
        if (hints != null) {
            for (index in 0 until hints.length()) {
                val hint = hints.optJSONObject(index) ?: continue
                render(hint.optString("key"), hint.optJSONObject("args"))?.let { result += " $it" }
            }
        } else if (body.optString("hint").isNotEmpty()) {
            val hint = body.getString("hint")
            val reason = matchBusiness(hint, "")
            result += " " + (reason?.let { render(it.first, it.second) } ?: hint)
            // Preserve completed actions reported by older gateways as well.
            val args = JSONObject()
                .put("devices", Regex("(\\d+) mesh device\\(s\\) disabled").find(hint)?.groupValues?.get(1) ?: "0")
                .put("tunnels", Regex("(\\d+) tunnel\\(s\\) disabled").find(hint)?.groupValues?.get(1) ?: "0")
                .put("keys", Regex("(\\d+) API key\\(s\\) revoked").find(hint)?.groupValues?.get(1) ?: "0")
            if (listOf("devices", "tunnels", "keys").any { args.getString(it) != "0" }) {
                render("business.offboardCompleted", args)?.let { result += " $it" }
            }
        }
        return result ?: fallback
    }

    fun stateError(raw: String): String {
        if (raw.isBlank()) return ""
        val body = JSONObject().put("error", raw)
        matchBusiness(raw, "")?.let { body.put("error_key", it.first).put("error_args", it.second) }
        return render(body, 502, text("apiErrors", "unavailable").orEmpty())
    }
}
