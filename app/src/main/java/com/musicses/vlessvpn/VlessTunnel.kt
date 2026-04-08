package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

private const val TAG = "VlessTunnel"

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private var ws: WebSocket? = null
    private val inQueue = LinkedBlockingQueue<ByteArray>(1000)
    private val END_MARKER = ByteArray(0)

    @Volatile private var closed = false
    @Volatile private var headerSent = false

    private var destHost = ""
    private var destPort = 0

    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        if (closed) { onResult(false); return }

        this.destHost = destHost
        this.destPort = destPort

        val client = buildOkHttpClient()

        // ★ OkHttp 不支持 wss/ws scheme，必须用 https/http
        // security=="tls" 或 port==443 → https（对应 wss）
        // 否则 → http（对应 ws）
        val httpScheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"

        val urlBuilder = HttpUrl.Builder()
            .scheme(httpScheme)
            .host(cfg.server)
            .port(cfg.port)

        val pathPart = cfg.wsPathPart
        if (pathPart.isNotEmpty() && pathPart != "/") {
            urlBuilder.addPathSegments(pathPart.trimStart('/'))
        }

        cfg.wsQueryPart?.split("&")?.forEach { kv ->
            val eqIdx = kv.indexOf('=')
            if (eqIdx > 0) {
                urlBuilder.addQueryParameter(kv.substring(0, eqIdx), kv.substring(eqIdx + 1))
            } else if (kv.isNotEmpty()) {
                urlBuilder.addQueryParameter(kv, null)
            }
        }

        val url = urlBuilder.build()
        Log.i(TAG, "Connecting: $url  target=$destHost:$destPort")

        val req = Request.Builder()
            .url(url)
            .header("Host",          cfg.wsHost)
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .header("Pragma",        "no-cache")
            .build()

        var resultSent = false

        client.newWebSocket(req, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed) { webSocket.close(1000, null); return }
                ws = webSocket
                Log.i(TAG, "✓ WS opened")

                val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                val firstPkt = if (earlyData != null && earlyData.isNotEmpty()) {
                    Log.d(TAG, "→ header(${header.size}B) + earlyData(${earlyData.size}B)")
                    header + earlyData
                } else {
                    Log.d(TAG, "→ header only (${header.size}B)")
                    header
                }
                webSocket.send(firstPkt.toByteString())
                headerSent = true

                if (!resultSent) { resultSent = true; onResult(true) }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed) inQueue.offer(bytes.toByteArray(), 100, TimeUnit.MILLISECONDS)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed) inQueue.offer(text.toByteArray(Charsets.UTF_8), 100, TimeUnit.MILLISECONDS)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.w(TAG, "WS closing: $code $reason")
                inQueue.offer(END_MARKER)
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code")
                inQueue.offer(END_MARKER)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "✗ WS failure: ${t.message}")
                response?.let { Log.e(TAG, "  HTTP ${it.code} ${it.message}") }
                inQueue.offer(END_MARKER)
                if (!resultSent) { resultSent = true; onResult(false) }
            }
        })
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed) return

        // WS → local（下行）
        // ★ 修复：不使用 inline lambda 中的 continue，改用普通 while + 变量控制
        val t1 = Thread({
            var respBuf     = ByteArray(0)
            var respSkipped = false
            var respHdrSize = -1

            try {
                while (!closed) {
                    val chunk = inQueue.poll(30, TimeUnit.SECONDS) ?: run {
                        Log.w(TAG, "WS→local: 30s timeout"); null
                    }

                    if (chunk == null) break
                    if (chunk === END_MARKER) { Log.d(TAG, "WS→local: END"); break }

                    // 计算实际要写给本地的 payload
                    val payload: ByteArray? = if (respSkipped) {
                        chunk
                    } else {
                        // 累积响应头数据
                        respBuf = respBuf + chunk

                        // 需要至少 2 字节才能得知 respHdrSize
                        if (respBuf.size < 2) {
                            null  // 还不够，等下一个 chunk
                        } else {
                            if (respHdrSize == -1) {
                                // byte[0]=version, byte[1]=addon_len, hdrSize = 2 + addon_len
                                respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                                Log.d(TAG, "VLESS resp hdrSize=$respHdrSize addonLen=${respBuf[1].toInt() and 0xFF}")
                            }

                            if (respBuf.size < respHdrSize) {
                                null  // 头还没收全，继续等
                            } else {
                                // 头收全了，提取 payload
                                respSkipped = true
                                val p = if (respBuf.size > respHdrSize)
                                    respBuf.copyOfRange(respHdrSize, respBuf.size)
                                else
                                    ByteArray(0)
                                respBuf = ByteArray(0)
                                Log.d(TAG, "✓ VLESS resp header stripped, payload=${p.size}B")
                                p
                            }
                        }
                    }

                    // payload == null 表示还在等响应头，不写数据
                    if (payload != null && payload.isNotEmpty()) {
                        localOut.write(payload)
                        localOut.flush()
                    }
                }
            } catch (e: Exception) {
                if (!closed) Log.e(TAG, "WS→local: ${e.message}")
            } finally {
                runCatching { localOut.close() }
                ws?.cancel()
            }
        }, "VT-down")

        // local → WS（上行）
        val t2 = Thread({
            try {
                val buf = ByteArray(8192)
                while (!closed) {
                    val n = localIn.read(buf)
                    if (n < 0) break
                    val data = buf.copyOf(n)
                    if (!headerSent) {
                        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                        ws?.send((header + data).toByteString())
                        headerSent = true
                    } else {
                        ws?.send(data.toByteString())
                    }
                }
            } catch (e: Exception) {
                if (!closed) Log.e(TAG, "local→WS: ${e.message}")
            } finally {
                inQueue.offer(END_MARKER)
                ws?.close(1000, null)
            }
        }, "VT-up")

        t1.isDaemon = true; t2.isDaemon = true
        t1.start();         t2.start()
        t1.join();          t2.join()
        Log.d(TAG, "relay ended")
    }

    fun close() {
        if (closed) return
        closed = true
        ws?.cancel()
        inQueue.clear()
        inQueue.offer(END_MARKER)
    }

    private fun buildOkHttpClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .pingInterval(20, TimeUnit.SECONDS)

        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val sc = SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(trustAll), SecureRandom())
        }

        if (vpnService != null) {
            builder.socketFactory(object : javax.net.SocketFactory() {
                private val def = javax.net.SocketFactory.getDefault()
                override fun createSocket(): Socket {
                    val s = def.createSocket()
                    s.tcpNoDelay = true
                    if (!vpnService.protect(s)) Log.w(TAG, "protect plain socket failed")
                    return s
                }
                override fun createSocket(h: String, p: Int) =
                    createSocket().also { it.connect(InetSocketAddress(h, p), 10000) }
                override fun createSocket(h: String, p: Int, la: java.net.InetAddress, lp: Int) =
                    createSocket().also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, p), 10000) }
                override fun createSocket(h: java.net.InetAddress, p: Int) =
                    createSocket().also { it.connect(InetSocketAddress(h, p), 10000) }
                override fun createSocket(a: java.net.InetAddress, p: Int, la: java.net.InetAddress, lp: Int) =
                    createSocket().also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(a, p), 10000) }
            })

            builder.sslSocketFactory(object : SSLSocketFactory() {
                private val base = sc.socketFactory
                override fun getDefaultCipherSuites() = base.defaultCipherSuites
                override fun getSupportedCipherSuites() = base.supportedCipherSuites
                override fun createSocket(s: Socket, h: String, p: Int, ac: Boolean): Socket =
                    base.createSocket(s, h, p, ac)
                override fun createSocket(h: String, p: Int): Socket =
                    base.createSocket(h, p).also { vpnService.protect(it) }
                override fun createSocket(h: String, p: Int, la: java.net.InetAddress, lp: Int): Socket =
                    base.createSocket(h, p, la, lp).also { vpnService.protect(it) }
                override fun createSocket(h: java.net.InetAddress, p: Int): Socket =
                    base.createSocket(h, p).also { vpnService.protect(it) }
                override fun createSocket(a: java.net.InetAddress, p: Int, la: java.net.InetAddress, lp: Int): Socket =
                    base.createSocket(a, p, la, lp).also { vpnService.protect(it) }
            }, trustAll)
        } else {
            builder.sslSocketFactory(sc.socketFactory, trustAll)
        }

        builder.hostnameVerifier { _, _ -> true }
        return builder.build()
    }
}