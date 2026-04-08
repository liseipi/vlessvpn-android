package com.musicses.vlessvpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * ★ 修复：wsUrl 构建逻辑与 client.js buildWsUrl() 完全对齐
 *
 * client.js 逻辑：
 *   scheme = (security === "tls" || port === 443) ? "wss" : "ws"
 *
 * 同时修复 path 中含 ? 时被 OkHttp 二次编码的问题。
 */
data class VlessConfig(
    val id: String = System.currentTimeMillis().toString(),
    val name: String = "Default",
    val server: String = "broad.aicms.dpdns.org",
    val port: Int = 443,
    val uuid: String = "55a95ae1-4ae8-4461-8484-457279821b40",
    val path: String = "/?ed=2560",
    val sni: String = "broad.aicms.dpdns.org",
    val wsHost: String = "broad.aicms.dpdns.org",
    val security: String = "none",        // none | tls
    val rejectUnauthorized: Boolean = false,
    val dns1: String = "8.8.8.8",
    val dns2: String = "8.8.4.4",
) {
    /**
     * ★ 关键修复：与 client.js buildWsUrl() 完全一致
     *
     * security=="tls" 或 port==443 → wss://
     * 否则 → ws://
     *
     * 原版只判断 security=="tls"，导致 security="none"&port=443 时
     * 错误使用 ws:// 而服务器要求 wss://
     */
    val wsScheme: String
        get() = if (security == "tls" || port == 443) "wss" else "ws"

    /**
     * ★ 修复：path 中若含 ?，必须拆开 path 和 query 分别处理
     * 否则 OkHttp 会把 "/?ed=2560" 编码成 "/%3Fed%3D2560"
     *
     * 返回 Pair(pathPart, queryPart?)
     * 例：path="/?ed=2560" → ("/" , "ed=2560")
     *     path="/ws"       → ("/ws", null)
     */
    val wsPathPart: String
        get() {
            val qIdx = path.indexOf('?')
            return if (qIdx >= 0) path.substring(0, qIdx) else path
        }

    val wsQueryPart: String?
        get() {
            val qIdx = path.indexOf('?')
            return if (qIdx >= 0) path.substring(qIdx + 1) else null
        }

    /**
     * 完整 WS URL（仅供参考/日志，实际建连用上面拆开的 wsPathPart/wsQueryPart）
     */
    val wsUrl: String
        get() = "$wsScheme://$server:$port$path"

    // ── VLESS URI 导出 ───────────────────────────────────────────────────────
    fun toVlessUri(): String {
        val encodedPath = URLEncoder.encode(path, "UTF-8").replace("+", "%20")
        val params = buildString {
            append("encryption=none")
            append("&security=$security")
            if (sni.isNotBlank()) append("&sni=$sni")
            append("&fp=randomized")
            append("&type=ws")
            if (wsHost.isNotBlank()) append("&host=$wsHost")
            append("&path=$encodedPath")
        }
        val encodedName = URLEncoder.encode(name, "UTF-8").replace("+", "%20")
        return "vless://$uuid@$server:$port?$params#$encodedName"
    }

    // ── JSON 持久化 ──────────────────────────────────────────────────────────
    fun toJson(): JSONObject = JSONObject().apply {
        put("id",                 id)
        put("name",               name)
        put("server",             server)
        put("port",               port)
        put("uuid",               uuid)
        put("path",               path)
        put("sni",                sni)
        put("wsHost",             wsHost)
        put("security",           security)
        put("rejectUnauthorized", rejectUnauthorized)
        put("dns1",               dns1)
        put("dns2",               dns2)
    }

    companion object {
        fun fromVlessUri(uri: String): VlessConfig? {
            return try {
                val raw = uri.trim()
                if (!raw.startsWith("vless://")) return null

                val hashIdx = raw.indexOf('#')
                val name = if (hashIdx >= 0)
                    URLDecoder.decode(raw.substring(hashIdx + 1), "UTF-8") else "Imported"
                val withoutHash = if (hashIdx >= 0) raw.substring(0, hashIdx) else raw

                val noScheme = withoutHash.removePrefix("vless://")
                val atIdx = noScheme.lastIndexOf('@')
                val uuid = noScheme.substring(0, atIdx)

                val rest = noScheme.substring(atIdx + 1)
                val qIdx = rest.indexOf('?')
                val hostPort = if (qIdx >= 0) rest.substring(0, qIdx) else rest
                val query   = if (qIdx >= 0) rest.substring(qIdx + 1) else ""

                val lastColon = hostPort.lastIndexOf(':')
                val server = hostPort.substring(0, lastColon)
                val port   = hostPort.substring(lastColon + 1).toInt()

                val params = mutableMapOf<String, String>()
                query.split("&").forEach { kv ->
                    val eq = kv.indexOf('=')
                    if (eq > 0) {
                        val k = kv.substring(0, eq)
                        val v = URLDecoder.decode(kv.substring(eq + 1), "UTF-8")
                        params[k] = v
                    }
                }

                val path     = params["path"] ?: "/"
                val sni      = params["sni"] ?: server
                val wsHost   = params["host"] ?: server
                val security = params["security"] ?: "none"

                VlessConfig(
                    id       = System.currentTimeMillis().toString(),
                    name     = name,
                    server   = server,
                    port     = port,
                    uuid     = uuid,
                    path     = path,
                    sni      = sni,
                    wsHost   = wsHost,
                    security = security,
                    rejectUnauthorized = false,
                    dns1     = "8.8.8.8",
                    dns2     = "8.8.4.4",
                )
            } catch (_: Exception) { null }
        }

        fun fromJson(o: JSONObject) = VlessConfig(
            id                 = o.optString("id", System.currentTimeMillis().toString()),
            name               = o.optString("name", "Default"),
            server             = o.optString("server", "broad.aicms.dpdns.org"),
            port               = o.optInt("port", 443),
            uuid               = o.optString("uuid", ""),
            path               = o.optString("path", "/"),
            sni                = o.optString("sni", ""),
            wsHost             = o.optString("wsHost", ""),
            security           = o.optString("security", "none"),
            rejectUnauthorized = o.optBoolean("rejectUnauthorized", false),
            dns1               = o.optString("dns1", "8.8.8.8"),
            dns2               = o.optString("dns2", "8.8.4.4"),
        )
    }
}

// ── 配置列表持久化 ────────────────────────────────────────────────────────────

object ConfigStore {
    private const val PREF          = "vless_configs"
    private const val KEY_LIST      = "list"
    private const val KEY_ACTIVE_ID = "active_id"

    fun loadAll(ctx: Context): List<VlessConfig> {
        val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY_LIST, null) ?: return listOf(VlessConfig())
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { VlessConfig.fromJson(arr.getJSONObject(it)) }
                .ifEmpty { listOf(VlessConfig()) }
        } catch (_: Exception) { listOf(VlessConfig()) }
    }

    fun saveAll(ctx: Context, list: List<VlessConfig>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putString(KEY_LIST, arr.toString()).apply()
    }

    fun loadActiveId(ctx: Context): String? =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString(KEY_ACTIVE_ID, null)

    fun saveActiveId(ctx: Context, id: String) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putString(KEY_ACTIVE_ID, id).apply()

    fun loadActive(ctx: Context): VlessConfig {
        val list = loadAll(ctx)
        val activeId = loadActiveId(ctx)
        return list.firstOrNull { it.id == activeId } ?: list.first()
    }
}