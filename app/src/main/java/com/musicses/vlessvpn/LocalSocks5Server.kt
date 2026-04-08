package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = Executors.newCachedThreadPool()
    private lateinit var srv: ServerSocket
    private val connectionCount = AtomicInteger(0)

    @Volatile var port: Int = 0
        private set
    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 256, InetAddress.getByName("127.0.0.1"))
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
                if (running) Log.e(TAG, "Accept: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket, connId: Int) {
        // ★ 握手阶段用 30s 超时（防止僵死连接）
        sock.tcpNoDelay = true
        sock.soTimeout = 30000

        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. SOCKS5 握手 ──────────────────────────────────────────
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) return
            inp.readNBytes(greeting[1].toInt() and 0xFF)
            out.write(byteArrayOf(0x05, 0x00)); out.flush()

            // ── 2. CONNECT 请求 ─────────────────────────────────────────
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) return

            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> InetAddress.getByAddress(inp.readNBytes(4)).hostAddress!! to portOf(inp.readNBytes(2))
                0x03.toByte() -> String(inp.readNBytes(inp.read())) to portOf(inp.readNBytes(2))
                0x04.toByte() -> InetAddress.getByAddress(inp.readNBytes(16)).hostAddress!! to portOf(inp.readNBytes(2))
                else -> return
            }

            Log.i(TAG, "[$connId] CONNECT $destHost:$destPort")

            // 立即回复成功，让客户端开始发数据
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()

            // ── 3. 早期数据收集（最多等 200ms）─────────────────────────
            val earlyData = collectEarlyData(sock, inp, 200)
            if (earlyData != null) {
                Log.d(TAG, "[$connId] earlyData (after 200ms): ${earlyData.size}B")
            } else {
                Log.d(TAG, "[$connId] No earlyData (waited 200ms)")
            }

            Log.d(TAG, "[$connId] Opening VLESS tunnel...")

            // ── 4. 建立 VLESS 隧道 ──────────────────────────────────────
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
            }

            if (!latch.await(30, TimeUnit.SECONDS)) {
                Log.e(TAG, "[$connId] Tunnel timeout (30s)")
                tunnel.close()
                return
            }
            if (!connected) {
                Log.e(TAG, "[$connId] Tunnel failed")
                tunnel.close()
                return
            }

            Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying...")

            // ★ 关键修复：relay 前清除 soTimeout
            // 握手阶段 soTimeout=30000 是必要的（防止僵死）
            // 但 relay 阶段本地可能长时间无数据（正常情况，如等待服务器响应）
            // soTimeout 会导致 "Read timed out"，中断正常连接
            // 改为 0 = 无限等待，由 VlessTunnel 内部的 inQueue.poll(60s) 控制超时
            sock.soTimeout = 0

            // ── 5. 双向中继 ──────────────────────────────────────────────
            tunnel.relay(inp, out)

            Log.d(TAG, "[$connId] Relay ended")

        } catch (e: Exception) {
            if (running) Log.d(TAG, "[$connId] ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    /**
     * 定时收集早期数据（50ms 轮询，200ms 超时）
     * 与 Node.js sock.once('data') + setTimeout(200) 行为一致
     */
    private fun collectEarlyData(sock: Socket, inp: java.io.InputStream, timeoutMs: Long): ByteArray? {
        val buf = ByteArray(8192)
        val collected = ByteArrayOutputStream()
        val deadline = System.currentTimeMillis() + timeoutMs

        // 用短超时轮询，避免阻塞
        sock.soTimeout = 50

        try {
            while (System.currentTimeMillis() < deadline) {
                try {
                    val n = inp.read(buf)
                    if (n < 0) break
                    if (n > 0) {
                        collected.write(buf, 0, n)
                        // 收到数据后，立即尝试读取更多（非阻塞）
                        try {
                            while (inp.available() > 0) {
                                val m = inp.read(buf)
                                if (m > 0) collected.write(buf, 0, m) else break
                            }
                        } catch (_: Exception) {}
                        break
                    }
                } catch (_: java.net.SocketTimeoutException) {
                    // 继续等待
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "collectEarlyData: ${e.message}")
        }
        // 注意：这里不恢复 soTimeout，由调用方在 relay 前设置为 0

        return if (collected.size() > 0) collected.toByteArray() else null
    }

    private fun portOf(b: ByteArray) =
        ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
}