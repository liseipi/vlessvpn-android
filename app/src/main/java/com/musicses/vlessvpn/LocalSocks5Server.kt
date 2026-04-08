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
    // ★ 优化：使用 SynchronousQueue + 无界线程池，避免队列积压导致的连接排队延迟
    // keepAlive=60s：空闲线程等待复用，减少线程创建开销
    private val pool = ThreadPoolExecutor(
        4, Int.MAX_VALUE, 60L, TimeUnit.SECONDS, SynchronousQueue()
    ).also { it.prestartCoreThread() }

    private lateinit var srv: ServerSocket
    private val connectionCount = AtomicInteger(0)

    @Volatile var port: Int = 0
        private set
    @Volatile private var running = false

    fun start(): Int {
        // ★ 优化：增大 backlog 队列（256→512），减少在高并发时 accept 前的连接拒绝
        srv = ServerSocket(0, 512, InetAddress.getByName("127.0.0.1"))
        // ★ 优化：关闭 Nagle 算法，降低本地回环延迟
        srv.setPerformancePreferences(0, 2, 1)
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
        sock.tcpNoDelay = true
        // ★ 优化：增大 socket buffer
        try { sock.sendBufferSize = 128 * 1024 } catch (_: Exception) {}
        try { sock.receiveBufferSize = 128 * 1024 } catch (_: Exception) {}
        sock.soTimeout = 30_000  // 握手阶段 30s 超时

        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. SOCKS5 握手 ──────────────────────────────────────────
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) return
            val nMethods = greeting[1].toInt() and 0xFF
            if (nMethods > 0) inp.readNBytes(nMethods)
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // ── 2. CONNECT 请求 ─────────────────────────────────────────
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) return

            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> {
                    InetAddress.getByAddress(inp.readNBytes(4)).hostAddress!! to readPort(inp)
                }
                0x03.toByte() -> {
                    val len = inp.read() and 0xFF
                    String(inp.readNBytes(len)) to readPort(inp)
                }
                0x04.toByte() -> {
                    InetAddress.getByAddress(inp.readNBytes(16)).hostAddress!! to readPort(inp)
                }
                else -> return
            }

            Log.i(TAG, "[$connId] CONNECT $destHost:$destPort")

            // 立即回复成功，让客户端开始发数据（early data 优化）
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()

            // ── 3. 收集早期数据（Early Data）────────────────────────────
            // ★ 优化：改用 available() 非阻塞读取，不再用 50ms 轮询
            // 最多等 150ms：给客户端时间发送第一个数据包（如 TLS ClientHello）
            val earlyData = collectEarlyDataFast(sock, inp, 150)
            if (earlyData != null) {
                Log.d(TAG, "[$connId] earlyData: ${earlyData.size}B")
            }

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

            Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying $destHost:$destPort")

            // relay 阶段取消超时（由 VlessTunnel 内 120s idle 控制）
            sock.soTimeout = 0

            // ── 5. 双向中继 ──────────────────────────────────────────────
            tunnel.relay(inp, out)

        } catch (e: Exception) {
            if (running) Log.d(TAG, "[$connId] ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    /**
     * ★ 优化版 Early Data 收集
     *
     * 策略：
     * 1. 先用 available() 检查是否已有数据（零延迟）
     * 2. 若无数据，设短超时等待第一个包（最多 timeoutMs）
     * 3. 收到第一个包后，再用 available() 读完剩余（非阻塞）
     *
     * 相比原版 50ms 轮询：
     * - 有数据时：0ms 延迟（原版最多 50ms）
     * - 无数据时：超时行为相同
     */
    private fun collectEarlyDataFast(
        sock: Socket,
        inp: InputStream,
        timeoutMs: Long
    ): ByteArray? {
        val buf = ByteArray(32768)

        // 先检查是否已有数据（完全非阻塞）
        val avail = inp.available()
        if (avail > 0) {
            val n = inp.read(buf, 0, minOf(avail, buf.size))
            if (n > 0) {
                val result = buf.copyOf(n)
                // 尝试继续读取更多（仍非阻塞）
                val extra = drainAvailable(inp, buf)
                return if (extra.isNotEmpty()) result + extra else result
            }
        }

        // 无立即可用数据，设超时等待
        sock.soTimeout = timeoutMs.toInt()
        return try {
            val n = inp.read(buf)
            if (n > 0) {
                val result = buf.copyOf(n)
                // 接着用 available() 排尽剩余
                val extra = drainAvailable(inp, buf)
                if (extra.isNotEmpty()) result + extra else result
            } else null
        } catch (_: java.net.SocketTimeoutException) {
            null  // 超时，没有 early data，正常情况
        } catch (e: Exception) {
            Log.d(TAG, "earlyData read: ${e.message}")
            null
        }
        // 注意：调用方在 relay 前会把 soTimeout 设为 0
    }

    private fun drainAvailable(inp: InputStream, buf: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        try {
            while (inp.available() > 0) {
                val n = inp.read(buf)
                if (n > 0) out.write(buf, 0, n) else break
            }
        } catch (_: Exception) {}
        return out.toByteArray()
    }

    private fun readPort(inp: InputStream): Int {
        val b = inp.readNBytes(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }
}