package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

/**
 * ★ 修复 earlyData 收集时机问题
 *
 * 问题：回复 SOCKS5 成功后用 available() 检查数据，
 * 但 TcpProxy.pendingData flush 有延迟，导致 available()==0，
 * earlyData 始终为空，服务器收到只有 header 就关闭连接。
 *
 * 修复：用短暂等待 + 循环读取，确保能拿到第一批数据：
 * - 最多等待 200ms
 * - 一旦读到数据就停止等待，立即发出
 * - 超时后也继续（earlyData=null，让服务器收到 header 后等客户端发数据）
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = Executors.newCachedThreadPool()
    private lateinit var srv: ServerSocket
    private val connCount = AtomicInteger(0)

    @Volatile var port: Int = 0
        private set
    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
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
        Log.i(TAG, "SOCKS5 server stopped")
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                val id = connCount.incrementAndGet()
                pool.submit { handleClient(client, id) }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "Accept error: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket, id: Int) {
        sock.tcpNoDelay = true
        sock.soTimeout = 30_000
        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── Step 1: SOCKS5 greeting ──────────────────────────────────────
            val ver = inp.read()
            if (ver != 5) { Log.w(TAG, "[$id] Not SOCKS5 (ver=$ver)"); return }
            val nMethods = inp.read()
            repeat(nMethods) { inp.read() }
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // ── Step 2: CONNECT request ──────────────────────────────────────
            val v2   = inp.read()
            val cmd  = inp.read()
            inp.read() // RSV
            val atyp = inp.read()

            if (v2 != 5 || cmd != 1) {
                Log.w(TAG, "[$id] Bad request v=$v2 cmd=$cmd")
                return
            }

            val (destHost, destPort) = parseAddress(inp, atyp) ?: run {
                Log.w(TAG, "[$id] Unknown atyp=$atyp")
                return
            }

            Log.i(TAG, "[$id] CONNECT $destHost:$destPort")

            // ── Step 3: 回复成功 ──────────────────────────────────────────────
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()

            // ── Step 4: 收集 earlyData ────────────────────────────────────────
            // ★ 关键修复：用带超时的等待，确保能拿到 TcpProxy flush 过来的数据
            // 最多等 200ms，一旦有数据立即读取
            val earlyData: ByteArray? = collectEarlyData(inp, id)

            // ── Step 5: 建立 VLESS 隧道 ──────────────────────────────────────
            Log.d(TAG, "[$id] Opening VLESS tunnel...")
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = java.util.concurrent.CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
            }

            if (!latch.await(15, java.util.concurrent.TimeUnit.SECONDS) || !connected) {
                Log.e(TAG, "[$id] Tunnel connect failed/timeout")
                tunnel.close()
                return
            }

            Log.i(TAG, "[$id] ✓ Tunnel ready, relaying...")
            tunnel.relay(inp, out)
            Log.d(TAG, "[$id] Relay ended")

        } catch (e: Exception) {
            Log.d(TAG, "[$id] Error: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    /**
     * ★ 可靠的 earlyData 收集
     *
     * 策略：
     * 1. 先检查 available()，如果立即有数据就读
     * 2. 没有的话，等待最多 200ms（分10次，每次20ms）
     * 3. 一旦有数据立即读取并返回
     * 4. 超时返回 null
     *
     * 200ms 足够 TcpProxy 完成 SOCKS5 握手后 flush pendingData
     */
    private fun collectEarlyData(inp: InputStream, id: Int): ByteArray? {
        // 先尝试立即读
        if (inp.available() > 0) {
            val data = ByteArray(inp.available())
            val n = inp.read(data)
            if (n > 0) {
                Log.d(TAG, "[$id] earlyData (immediate): ${n}B")
                return data.copyOf(n)
            }
        }

        // 等待最多 200ms，分批检查
        val maxWaitMs = 200L
        val stepMs    = 20L
        val steps     = (maxWaitMs / stepMs).toInt()

        for (i in 0 until steps) {
            Thread.sleep(stepMs)
            if (inp.available() > 0) {
                val data = ByteArray(inp.available())
                val n = inp.read(data)
                if (n > 0) {
                    Log.d(TAG, "[$id] earlyData (after ${(i + 1) * stepMs}ms): ${n}B")
                    return data.copyOf(n)
                }
            }
        }

        Log.d(TAG, "[$id] No earlyData (waited ${maxWaitMs}ms)")
        return null
    }

    private fun parseAddress(inp: InputStream, atyp: Int): Pair<String, Int>? {
        return when (atyp) {
            0x01 -> {
                val ip = ByteArray(4).also { readFully(inp, it) }
                InetAddress.getByAddress(ip).hostAddress!! to readPort(inp)
            }
            0x03 -> {
                val len = inp.read()
                val domain = String(ByteArray(len).also { readFully(inp, it) })
                domain to readPort(inp)
            }
            0x04 -> {
                val ip = ByteArray(16).also { readFully(inp, it) }
                InetAddress.getByAddress(ip).hostAddress!! to readPort(inp)
            }
            else -> null
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = inp.read(buf, offset, buf.size - offset)
            if (n < 0) throw java.io.EOFException("closed at $offset/${buf.size}")
            offset += n
        }
    }

    private fun readPort(inp: InputStream): Int = (inp.read() shl 8) or inp.read()
}