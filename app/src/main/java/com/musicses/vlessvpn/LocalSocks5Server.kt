package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = ThreadPoolExecutor(
        4, 256, 60L, TimeUnit.SECONDS, SynchronousQueue()
    ).also { it.prestartCoreThread() }

    private lateinit var srv: ServerSocket
    private val connectionCount = AtomicInteger(0)

    @Volatile var port: Int = 0; private set
    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 512, InetAddress.getByName("127.0.0.1"))
        port = srv.localPort
        running = true
        pool.submit { acceptLoop() }
        Log.i(TAG, "SOCKS5 server started on 127.0.0.1:$port")
        return port
    }

    fun stop() {
        if (!running) return
        running = false
        runCatching { srv.close() }
        pool.shutdownNow()
        pool.awaitTermination(3, TimeUnit.SECONDS)
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                val id = connectionCount.incrementAndGet()
                pool.submit { handleClient(client, id) }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "Accept error: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket, connId: Int) {
        sock.tcpNoDelay = true
        try { sock.sendBufferSize = 128 * 1024 } catch (_: Exception) {}
        try { sock.receiveBufferSize = 128 * 1024 } catch (_: Exception) {}
        sock.soTimeout = 30_000

        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // === SOCKS5 握手 ===
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) {
                Log.w(TAG, "[$connId] Invalid SOCKS5 greeting")
                return
            }
            val nMethods = greeting[1].toInt() and 0xFF
            if (nMethods > 0) inp.readNBytes(nMethods)
            // 回复：无需认证
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // === 读取请求 ===
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte()) {
                Log.w(TAG, "[$connId] Invalid SOCKS5 request")
                return
            }

            val cmd = req[1].toInt() and 0xFF

            // 只处理 CONNECT (0x01)，拒绝 BIND (0x02) 和 UDP ASSOCIATE (0x03)
            if (cmd == 0x03) {
                // UDP ASSOCIATE：返回成功但用不支持的地址，让客户端自行处理
                // tun2socks 关闭 UDP 后不会发这个请求
                Log.d(TAG, "[$connId] UDP ASSOCIATE - rejecting")
                out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()
                return
            }

            if (cmd != 0x01) {
                Log.w(TAG, "[$connId] Unsupported SOCKS5 command: $cmd")
                out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()
                return
            }

            // === 解析目标地址 ===
            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> {
                    // IPv4
                    InetAddress.getByAddress(inp.readNBytes(4)).hostAddress!! to readPort(inp)
                }
                0x03.toByte() -> {
                    // 域名
                    val len = inp.read() and 0xFF
                    String(inp.readNBytes(len)) to readPort(inp)
                }
                0x04.toByte() -> {
                    // IPv6
                    InetAddress.getByAddress(inp.readNBytes(16)).hostAddress!! to readPort(inp)
                }
                else -> {
                    Log.w(TAG, "[$connId] Unknown address type: ${req[3]}")
                    return
                }
            }

            Log.i(TAG, "[$connId] CONNECT $destHost:$destPort")

            // 回复：成功（绑定地址为 0.0.0.0:0）
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()

            // === 收集 early data（非阻塞） ===
            sock.soTimeout = 0
            val earlyData = collectEarlyDataNonBlocking(inp)
            if (earlyData != null) {
                Log.d(TAG, "[$connId] earlyData: ${earlyData.size}B")
            }

            // === 建立 VLESS 隧道 ===
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
            }

            if (!latch.await(30, TimeUnit.SECONDS)) {
                Log.e(TAG, "[$connId] Tunnel timeout connecting to $destHost:$destPort")
                tunnel.close()
                return
            }

            if (!connected) {
                Log.e(TAG, "[$connId] Tunnel failed to connect to $destHost:$destPort")
                tunnel.close()
                return
            }

            Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying $destHost:$destPort")
            tunnel.relay(inp, out)

        } catch (e: Exception) {
            if (running) Log.d(TAG, "[$connId] ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    private fun collectEarlyDataNonBlocking(inp: InputStream): ByteArray? {
        val avail = try { inp.available() } catch (_: Exception) { return null }
        if (avail <= 0) return null

        val buf = ByteArray(65536)
        val baos = java.io.ByteArrayOutputStream()
        try {
            var remaining = avail
            while (remaining > 0) {
                val n = inp.read(buf, 0, minOf(remaining, buf.size))
                if (n <= 0) break
                baos.write(buf, 0, n)
                remaining -= n
                val more = try { inp.available() } catch (_: Exception) { 0 }
                if (more <= 0) break
                remaining = more
            }
        } catch (_: Exception) {}

        return if (baos.size() > 0) baos.toByteArray() else null
    }

    private fun readPort(inp: InputStream): Int {
        val b = inp.readNBytes(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }
}