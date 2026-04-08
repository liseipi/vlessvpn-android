package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okhttp3.ConnectionPool
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*

private const val TAG = "VlessTunnel"

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val wsRef = AtomicReference<WebSocket?>(null)
    // 增大队列容量，防止高吞吐时丢包
    private val inQueue = LinkedBlockingQueue<ByteArray>(4000)
    private val closed = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)

    private var destHost = ""
    private var destPort = 0

    companion object {
        private val END_MARKER = ByteArray(0)

        // ★ 关键优化1：每个 VpnService 实例共享一个 OkHttpClient
        // 避免每次连接都重新创建 TCP 连接池和 TLS 上下文
        @Volatile private var sharedClient: OkHttpClient? = null
        @Volatile private var sharedClientVpn: VpnService? = null

        fun getOrCreateClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val existing = sharedClient
            // 如果 vpnService 实例没变，复用 client
            if (existing != null && sharedClientVpn === vpnService) {
                return existing
            }
            synchronized(this) {
                val double = sharedClient
                if (double != null && sharedClientVpn === vpnService) return double
                val client = buildClient(cfg, vpnService)
                sharedClient = client
                sharedClientVpn = vpnService
                Log.i(TAG, "✓ Created shared OkHttpClient (vpnService=${vpnService != null})")
                return client
            }
        }

        fun clearSharedClients() {
            synchronized(this) {
                sharedClient?.dispatcher?.cancelAll()
                sharedClient?.connectionPool?.evictAll()
                sharedClient = null
                sharedClientVpn = null
                Log.i(TAG, "Shared OkHttpClient cleared")
            }
        }

        private fun buildClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val sslCtx = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustAll), SecureRandom())
            }

            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .writeTimeout(0, TimeUnit.SECONDS)
                // ★ 关键优化2：启用连接池，最多 10 个空闲连接，保持 5 分钟
                // 原来是 ConnectionPool(0,1,NANOSECONDS) 即完全禁用，每次重建 TCP+TLS
                .connectionPool(ConnectionPool(10, 5, TimeUnit.MINUTES))
                // ping 保持 WebSocket 活跃，防止 NAT 超时断开
                .pingInterval(25, TimeUnit.SECONDS)
                .hostnameVerifier { _, _ -> true }
                // ★ 优化3：启用 HTTP/2 多路复用（默认已启用，但确保不被禁用）
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))

            if (vpnService != null) {
                // 自定义 SocketFactory：在创建 socket 后立即 protect
                builder.socketFactory(object : javax.net.SocketFactory() {
                    private val def = javax.net.SocketFactory.getDefault()
                    private fun p(s: Socket): Socket {
                        s.tcpNoDelay = true
                        // 增大 socket buffer 提升吞吐
                        s.setPerformancePreferences(0, 1, 2)
                        try { s.sendBufferSize = 256 * 1024 } catch (_: Exception) {}
                        try { s.receiveBufferSize = 256 * 1024 } catch (_: Exception) {}
                        if (!vpnService.protect(s)) Log.w(TAG, "Failed to protect socket")
                        return s
                    }
                    override fun createSocket() = p(def.createSocket())
                    override fun createSocket(h: String, port: Int) =
                        p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: String, port: Int, la: java.net.InetAddress, lp: Int) =
                        p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: java.net.InetAddress, port: Int) =
                        p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: java.net.InetAddress, port: Int, la: java.net.InetAddress, lp: Int) =
                        p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
                })

                val baseSsl = sslCtx.socketFactory
                builder.sslSocketFactory(object : SSLSocketFactory() {
                    override fun getDefaultCipherSuites() = baseSsl.defaultCipherSuites
                    override fun getSupportedCipherSuites() = baseSsl.supportedCipherSuites
                    override fun createSocket(s: Socket, h: String, p: Int, ac: Boolean): Socket {
                        val ssl = baseSsl.createSocket(s, h, p, ac)
                        vpnService.protect(ssl)
                        return ssl
                    }
                    override fun createSocket(h: String, p: Int) = baseSsl.createSocket(h, p).also { vpnService.protect(it) }
                    override fun createSocket(h: String, p: Int, la: java.net.InetAddress, lp: Int) = baseSsl.createSocket(h, p, la, lp).also { vpnService.protect(it) }
                    override fun createSocket(h: java.net.InetAddress, p: Int) = baseSsl.createSocket(h, p).also { vpnService.protect(it) }
                    override fun createSocket(h: java.net.InetAddress, p: Int, la: java.net.InetAddress, lp: Int) = baseSsl.createSocket(h, p, la, lp).also { vpnService.protect(it) }
                }, trustAll)
            } else {
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
            }

            return builder.build()
        }
    }

    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        if (closed.get()) { onResult(false); return }

        this.destHost = destHost
        this.destPort = destPort

        // ★ 关键优化4：复用共享 client，不再每次 new OkHttpClient
        val client = getOrCreateClient(cfg, vpnService)

        // ★ 关键修复：正确构建 WebSocket URL，避免 OkHttp 二次编码 path 中的 ?
        val url = buildWsUrl()
        val req = Request.Builder()
            .url(url)
            .header("Host", cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .build()

        Log.i(TAG, "Connecting WS: $url  target=$destHost:$destPort")

        val resultSent = AtomicBoolean(false)
        fun deliver(ok: Boolean) {
            if (resultSent.compareAndSet(false, true)) onResult(ok)
        }

        client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) { webSocket.close(1000, null); deliver(false); return }
                if (!wsRef.compareAndSet(null, webSocket)) { webSocket.close(1000, null); deliver(false); return }
                Log.i(TAG, "✓ WS opened [${response.protocol}]")
                sendFirstPacket(webSocket, earlyData)
                deliver(true)
            }

            override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                if (!closed.get() && bytes.size > 0) {
                    if (!inQueue.offer(bytes.toByteArray(), 5, TimeUnit.SECONDS)) {
                        Log.w(TAG, "inQueue full, dropping ${bytes.size}B")
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty()) inQueue.offer(text.toByteArray())
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.w(TAG, "WS closing: $code ${reason.take(50)}")
                inQueue.offer(END_MARKER)
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code")
                inQueue.offer(END_MARKER)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!closed.get()) Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: ${t.message}")
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    /**
     * ★ 修复：正确构建 WebSocket URL
     * 使用 HttpUrl.Builder 分别设置 path 和 query，避免 OkHttp 对 ? 进行二次编码
     */
    private fun buildWsUrl(): HttpUrl {
        val scheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"
        val builder = HttpUrl.Builder()
            .scheme(scheme)
            .host(cfg.server)
            .port(cfg.port)
            .encodedPath(cfg.wsPathPart.ifBlank { "/" })
        cfg.wsQueryPart?.let { builder.encodedQuery(it) }
        return builder.build()
    }

    private fun sendFirstPacket(webSocket: WebSocket, earlyData: ByteArray?) {
        if (headerSent.getAndSet(true)) return
        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
        val packet = if (earlyData != null && earlyData.isNotEmpty()) {
            Log.d(TAG, "→ header(${header.size}B) + earlyData(${earlyData.size}B)")
            header + earlyData
        } else {
            Log.d(TAG, "→ header only (${header.size}B)")
            header
        }
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return

        val myWs = wsRef.get() ?: run {
            Log.e(TAG, "relay: ws is null")
            return
        }

        var firstResponse = true
        val wsToLocalDone = AtomicBoolean(false)
        val localToWsDone = AtomicBoolean(false)

        // ── WS → Local ───────────────────────────────────────────────────────
        val t1 = Thread {
            try {
                while (!closed.get()) {
                    // ★ 优化：适当的超时，防止僵死连接
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS)
                    if (chunk == null) {
                        Log.w(TAG, "WS→local: 120s idle timeout, closing")
                        break
                    }
                    if (chunk === END_MARKER) { Log.d(TAG, "WS→local: END"); break }

                    val payload = if (firstResponse && chunk.size >= 2) {
                        firstResponse = false
                        val addonLen = chunk[1].toInt() and 0xFF
                        val hdrLen = 2 + addonLen
                        if (chunk.size > hdrLen) chunk.copyOfRange(hdrLen, chunk.size) else null
                    } else {
                        firstResponse = false
                        chunk
                    }

                    if (payload != null && payload.isNotEmpty()) {
                        try {
                            localOut.write(payload)
                            localOut.flush()
                        } catch (e: Exception) {
                            if (!closed.get()) Log.e(TAG, "WS→local write: ${e.message}")
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                if (!closed.get()) Log.e(TAG, "WS→local: ${e.message}")
            } finally {
                wsToLocalDone.set(true)
                runCatching { localOut.close() }
                if (!localToWsDone.get()) runCatching { myWs.cancel() }
            }
        }.apply { isDaemon = true; name = "VT-ws2l-$destPort" }

        // ── Local → WS ───────────────────────────────────────────────────────
        val t2 = Thread {
            try {
                // ★ 优化：增大读取缓冲区，减少系统调用次数
                val buf = ByteArray(32768)
                while (!closed.get() && !wsToLocalDone.get()) {
                    val n = try {
                        localIn.read(buf)
                    } catch (e: Exception) {
                        if (!closed.get() && !wsToLocalDone.get()) Log.e(TAG, "local→WS: ${e.message}")
                        break
                    }
                    if (n < 0) break

                    val data = if (n == buf.size) buf.copyOf() else buf.copyOf(n)
                    if (!headerSent.get()) {
                        sendFirstPacket(myWs, data)
                    } else {
                        val ok = myWs.send(data.toByteString())
                        if (!ok) {
                            if (!closed.get()) Log.e(TAG, "local→WS: send failed (queue full or closed)")
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !wsToLocalDone.get()) Log.e(TAG, "local→WS: ${e.message}")
            } finally {
                localToWsDone.set(true)
                inQueue.offer(END_MARKER)
                runCatching { myWs.close(1000, null) }
            }
        }.apply { isDaemon = true; name = "VT-l2ws-$destPort" }

        t1.start(); t2.start()
        t1.join(); t2.join()
        Log.d(TAG, "relay ended [$destHost:$destPort]")
    }

    fun close() {
        if (closed.getAndSet(true)) return
        inQueue.offer(END_MARKER)
        runCatching { wsRef.get()?.cancel() }
    }
}