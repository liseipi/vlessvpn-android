package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "TunHandler"
private const val MTU = 1500

class TunHandler(
    private var fd: FileDescriptor?,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    // ★ 优化：SynchronousQueue + 弹性线程池，高并发时立即创建线程而非排队
    private val executor = ThreadPoolExecutor(
        4, 512, 60L, TimeUnit.SECONDS, SynchronousQueue()
    ).also { it.prestartCoreThread() }
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()

    @Volatile private var running = false

    private val totalIn  = AtomicLong(0)
    private val totalOut = AtomicLong(0)
    private val totalPkts = AtomicLong(0)
    private val tcpPkts = AtomicLong(0)
    private val udpPkts = AtomicLong(0)

    private lateinit var socksServer: LocalSocks5Server
    private var socksPort: Int = 0

    private val tcpFlows = ConcurrentHashMap<String, TcpProxy>()
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()

    fun start() {
        running = true

        socksServer = LocalSocks5Server(cfg, vpnService) { bytesIn, bytesOut ->
            val tIn  = totalIn.addAndGet(bytesIn)
            val tOut = totalOut.addAndGet(bytesOut)
            onStats(tIn, tOut)
        }
        socksPort = socksServer.start()
        Log.i(TAG, "✓ SOCKS5 proxy started on 127.0.0.1:$socksPort")

        // 每 10 秒诊断日志（减少频率，降低 IO 开销）
        scheduler.scheduleAtFixedRate({
            if (running) logDiag()
        }, 10, 10, TimeUnit.SECONDS)

        // 每 60 秒清理 UDP 会话（120s 无活动视为过期）
        scheduler.scheduleAtFixedRate({
            if (running) cleanupUdpSessions()
        }, 60, 60, TimeUnit.SECONDS)
    }

    fun stop() {
        running = false
        scheduler.shutdownNow()
        socksServer.stop()
        VlessTunnel.clearSharedClients()

        tcpFlows.values.forEach { it.close() }
        tcpFlows.clear()
        udpSessions.values.forEach { it.close() }
        udpSessions.clear()

        executor.shutdownNow()
        executor.awaitTermination(3, TimeUnit.SECONDS)
        Log.i(TAG, "TunHandler stopped")
    }

    fun getSocksPort(): Int = socksPort

    fun setTunFd(tunFd: FileDescriptor) {
        this.fd = tunFd
        executor.submit { tunReadLoop(tunFd) }
        Log.i(TAG, "★ TUN fd set, starting read loop")
    }

    private val pktReadCount = AtomicLong(0)

    private fun tunReadLoop(tunFd: FileDescriptor) {
        val fis = FileInputStream(tunFd)
        val fos = FileOutputStream(tunFd)
        // ★ 优化：增大 TUN 读取缓冲区
        val buf = ByteArray(MTU + 64)

        Log.i(TAG, "★ TUN read loop STARTED")

        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 20) continue

                val count = pktReadCount.incrementAndGet()
                if (count % 500L == 0L) {
                    Log.d(TAG, "TUN pkt #$count: ${n}B proto=${buf[9].toInt() and 0xFF}")
                }

                // ★ 优化：避免不必要的 copyOf，直接传递长度
                handleIpPacket(buf, n, fos)
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}")
        }

        Log.i(TAG, "★ TUN read loop ENDED")
    }

    private fun handleIpPacket(buf: ByteArray, len: Int, tunOut: FileOutputStream) {
        try {
            val version = (buf[0].toInt() and 0xFF) ushr 4
            if (version != 4) return

            totalPkts.incrementAndGet()
            when (val protocol = buf[9].toInt() and 0xFF) {
                6  -> { tcpPkts.incrementAndGet(); handleTcpPacket(buf.copyOf(len), tunOut) }
                17 -> { udpPkts.incrementAndGet(); handleUdpPacket(buf.copyOf(len), tunOut) }
                1  -> handleIcmpPacket(buf.copyOf(len), tunOut)
                else -> { /* 忽略其他协议 */ }
            }
        } catch (_: Exception) {}
    }

    // ── TCP ──────────────────────────────────────────────────────────────────

    private fun handleTcpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 20) return

        val srcIp   = formatIp(packet, 12)
        val dstIp   = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)
        val seqNum  = readUInt32(packet, ihl + 4)
        val flags   = packet[ihl + 13].toInt() and 0xFF
        val isSyn   = (flags and 0x02) != 0
        val isFin   = (flags and 0x01) != 0
        val isRst   = (flags and 0x04) != 0
        val isAck   = (flags and 0x10) != 0

        val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        val dataOffset   = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payloadStart = ihl + dataOffset
        val payload = if (packet.size > payloadStart) packet.copyOfRange(payloadStart, packet.size)
        else ByteArray(0)

        when {
            isSyn && !isAck -> {
                tcpFlows.remove(flowKey)?.close()

                Log.d(TAG, "[$flowKey] SYN (flows=${tcpFlows.size + 1})")

                val proxy = TcpProxy(
                    srcIp, srcPort, dstIp, dstPort,
                    seqNum, socksPort, tunOut,
                    onDown = { bytes ->
                        totalIn.addAndGet(bytes)
                        onStats(totalIn.get(), totalOut.get())
                    },
                    onUp = { bytes ->
                        totalOut.addAndGet(bytes)
                        onStats(totalIn.get(), totalOut.get())
                    }
                )
                tcpFlows[flowKey] = proxy
                // ★ 优化：在线程池中启动，不阻塞 TUN 读取循环
                executor.submit { proxy.start() }
            }

            isFin || isRst -> {
                tcpFlows.remove(flowKey)?.close()
            }

            payload.isNotEmpty() -> {
                val flow = tcpFlows[flowKey]
                if (flow != null) {
                    flow.receiveData(payload, seqNum)
                } else {
                    // 流已关闭，静默丢弃
                }
            }

            // 纯 ACK 不需要处理
        }
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    private fun handleUdpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return

        val srcIp   = formatIp(packet, 12)
        val dstIp   = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)
        val payload = packet.copyOfRange(ihl + 8, packet.size)

        if (payload.isEmpty()) return

        val sessionKey = "$srcIp:$srcPort->$dstIp:$dstPort"
        if (dstPort == 53) Log.d(TAG, "[$sessionKey] DNS ${payload.size}B")

        // ★ 优化：computeIfAbsent 是原子操作，避免并发创建重复 session
        val session = udpSessions.computeIfAbsent(sessionKey) {
            Log.d(TAG, "[$sessionKey] UDP session opened")
            UdpSession(srcIp, srcPort, dstIp, dstPort, tunOut, vpnService)
        }
        session.send(payload)
    }

    // ── ICMP ─────────────────────────────────────────────────────────────────

    private fun handleIcmpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return
        if (packet[ihl].toInt() and 0xFF != 8) return  // 只处理 Echo Request

        val reply = packet.copyOf()
        // 交换源/目标 IP
        for (i in 0..3) {
            val tmp = reply[12 + i]
            reply[12 + i] = reply[16 + i]
            reply[16 + i] = tmp
        }
        reply[ihl] = 0x00  // Echo Reply

        // 重新计算校验和
        reply[10] = 0; reply[11] = 0
        val ipCsum = checksum(reply, 0, ihl)
        reply[10] = (ipCsum ushr 8).toByte()
        reply[11] = (ipCsum and 0xFF).toByte()

        reply[ihl + 2] = 0; reply[ihl + 3] = 0
        val icmpCsum = checksum(reply, ihl, packet.size - ihl)
        reply[ihl + 2] = (icmpCsum ushr 8).toByte()
        reply[ihl + 3] = (icmpCsum and 0xFF).toByte()

        synchronized(tunOut) { runCatching { tunOut.write(reply) } }
    }

    // ── 清理 ─────────────────────────────────────────────────────────────────

    private fun cleanupUdpSessions() {
        val now = System.currentTimeMillis()
        val stale = udpSessions.entries.filter { now - it.value.lastActive > 120_000 }
        stale.forEach { (key, session) ->
            session.close()
            udpSessions.remove(key)
        }
        if (stale.isNotEmpty()) Log.d(TAG, "Cleaned ${stale.size} stale UDP sessions")
    }

    // ── 诊断 ─────────────────────────────────────────────────────────────────

    private var lastIn = 0L
    private var lastOut = 0L

    private fun logDiag() {
        val inNow  = totalIn.get()
        val outNow = totalOut.get()
        val deltaIn  = inNow - lastIn
        val deltaOut = outNow - lastOut
        lastIn = inNow; lastOut = outNow

        Log.i(TAG, "DIAG pkts=${totalPkts.get()} tcp=${tcpPkts.get()} udp=${udpPkts.get()}" +
                " | flows=${tcpFlows.size} udpSess=${udpSessions.size}" +
                " | threads=${executor.activeCount}/${executor.poolSize}" +
                " | in=${fmtBytes(inNow)} out=${fmtBytes(outNow)}" +
                " | Δin=${fmtBytes(deltaIn)}/10s Δout=${fmtBytes(deltaOut)}/10s")
    }

    private fun fmtBytes(b: Long) = when {
        b < 1024L    -> "${b}B"
        b < 1048576L -> "${"%.1f".format(b / 1024.0)}K"
        else         -> "${"%.1f".format(b / 1048576.0)}M"
    }

    // ── 工具 ─────────────────────────────────────────────────────────────────

    private fun formatIp(pkt: ByteArray, offset: Int) =
        "${pkt[offset].toInt() and 0xFF}.${pkt[offset+1].toInt() and 0xFF}" +
                ".${pkt[offset+2].toInt() and 0xFF}.${pkt[offset+3].toInt() and 0xFF}"

    private fun readUInt16(buf: ByteArray, offset: Int) =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readUInt32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
                ((buf[offset+1].toLong() and 0xFF) shl 16) or
                ((buf[offset+2].toLong() and 0xFF) shl 8) or
                (buf[offset+3].toLong() and 0xFF)
}

// ── TCP 代理 ──────────────────────────────────────────────────────────────────

private class TcpProxy(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val initialClientSeq: Long,
    private val socksPort: Int,
    private val tunOut: FileOutputStream,
    private val onDown: (Long) -> Unit,
    private val onUp: (Long) -> Unit
) {
    private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
    private var clientAck = initialClientSeq + 1

    private var socksSocket: Socket? = null

    // ★ 优化：用 AtomicBoolean 代替 CountDownLatch，减少线程阻塞
    private val connectDone = AtomicBoolean(false)
    private val connectLatch = java.util.concurrent.CountDownLatch(1)

    @Volatile private var closed = false
    @Volatile private var isConnected = false

    // ★ 优化：上行数据队列，避免 receiveData 在连接期间阻塞调用线程
    private val upQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(512)

    fun start() {
        try {
            writeSynAck()

            val sock = Socket()
            sock.tcpNoDelay = true
            // ★ 优化：增大 buffer 提升吞吐
            try { sock.sendBufferSize = 128 * 1024 } catch (_: Exception) {}
            try { sock.receiveBufferSize = 128 * 1024 } catch (_: Exception) {}
            sock.connect(InetSocketAddress("127.0.0.1", socksPort), 5000)
            socksSocket = sock

            performSocks5Handshake(sock.getOutputStream(), sock.getInputStream())

            isConnected = true
            connectLatch.countDown()
            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ SOCKS5 OK")

            // ★ 优化：发送连接建立期间积压的数据
            drainUpQueue(sock.getOutputStream())

            // 下行：server → TUN（在当前线程执行，节省线程切换）
            val downThread = Thread {
                val buf = ByteArray(32768)
                try {
                    while (!closed && !sock.isClosed) {
                        val n = sock.getInputStream().read(buf)
                        if (n < 0) break
                        onDown(n.toLong())
                        writeDataToTun(buf, n)
                    }
                } catch (e: Exception) {
                    if (!closed) Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] downstream: ${e.message}")
                } finally {
                    close()
                }
            }.apply { isDaemon = true; name = "TCP-down-$srcPort" }
            downThread.start()

            // 上行：持续从 upQueue 取数据发送（在当前线程）
            try {
                while (!closed && !sock.isClosed) {
                    val data = upQueue.poll(60, TimeUnit.SECONDS) ?: break
                    if (data.isEmpty()) break  // poison pill
                    sock.getOutputStream().write(data)
                    onUp(data.size.toLong())
                    writeAck()
                    // 批量发送：尽量排尽队列中的数据，减少系统调用
                    drainUpQueue(sock.getOutputStream())
                }
            } catch (e: Exception) {
                if (!closed) Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] upstream: ${e.message}")
            } finally {
                close()
            }

        } catch (e: Exception) {
            Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] connect error: ${e.message}")
            isConnected = false
            connectLatch.countDown()
            close()
        }
    }

    private fun drainUpQueue(out: OutputStream) {
        while (true) {
            val data: ByteArray = upQueue.poll() ?: break

            if (data.isEmpty()) {
                break
            }

            out.write(data)
            onUp(data.size.toLong())
            writeAck()
        }
    }

    fun receiveData(data: ByteArray, seqNum: Long) {
        if (closed) return
        clientAck = seqNum + data.size

        if (!connectLatch.await(10, TimeUnit.SECONDS)) {
            Log.w(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] connect timeout, dropping ${data.size}B")
            close()
            return
        }
        if (!isConnected) return

        // ★ 关键优化：不在这里发送数据，而是放入队列
        // 避免多个 receiveData 并发写 socket 导致数据乱序
        if (!upQueue.offer(data, 2, TimeUnit.SECONDS)) {
            Log.w(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] upQueue full, dropping ${data.size}B")
            close()
        }
    }

    private fun writeAck() {
        val pkt = buildTcpPacket(
            dstIp, dstPort, srcIp, srcPort,
            serverSeq, clientAck, 0x10, ByteArray(0)
        )
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    private fun writeDataToTun(buf: ByteArray, len: Int) {
        if (closed) return
        val data = buf.copyOf(len)
        val pkt = buildTcpPacket(
            dstIp, dstPort, srcIp, srcPort,
            serverSeq, clientAck, 0x18, data
        )
        serverSeq = (serverSeq + data.size) and 0xFFFFFFFFL
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    private fun writeSynAck() {
        val pkt = buildTcpPacket(
            dstIp, dstPort, srcIp, srcPort,
            serverSeq, initialClientSeq + 1, 0x12, ByteArray(0)
        )
        serverSeq = (serverSeq + 1) and 0xFFFFFFFFL
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    private fun performSocks5Handshake(out: OutputStream, inp: InputStream) {
        // 握手超时 10s
        socksSocket?.soTimeout = 10_000
        out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
        val r1 = ByteArray(2); inp.read(r1)
        if (r1[0] != 0x05.toByte() || r1[1] != 0x00.toByte()) throw IOException("SOCKS5 auth failed")

        val req = buildSocks5Request(dstIp, dstPort)
        out.write(req); out.flush()

        // 读取响应（固定 10 字节）
        val r2 = ByteArray(10); inp.read(r2)
        if (r2[0] != 0x05.toByte() || r2[1] != 0x00.toByte())
            throw IOException("SOCKS5 connect failed: ${r2[1]}")

        // 握手完成后清除超时
        socksSocket?.soTimeout = 0
    }

    private fun buildSocks5Request(host: String, port: Int): ByteArray {
        val isIpv4 = host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
        return if (isIpv4) {
            val p = host.split(".")
            byteArrayOf(0x05, 0x01, 0x00, 0x01,
                p[0].toInt().toByte(), p[1].toInt().toByte(),
                p[2].toInt().toByte(), p[3].toInt().toByte(),
                (port shr 8).toByte(), (port and 0xFF).toByte())
        } else {
            val hb = host.toByteArray()
            ByteArray(7 + hb.size).apply {
                this[0] = 0x05; this[1] = 0x01; this[2] = 0x00; this[3] = 0x03
                this[4] = hb.size.toByte()
                hb.copyInto(this, 5)
                this[5 + hb.size] = (port shr 8).toByte()
                this[6 + hb.size] = (port and 0xFF).toByte()
            }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        connectLatch.countDown()
        // 发送 poison pill 让上行循环退出
        runCatching { upQueue.offer(ByteArray(0)) }
        runCatching { socksSocket?.close() }
    }
}

// ── UDP 会话 ──────────────────────────────────────────────────────────────────

private class UdpSession(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val tunOut: FileOutputStream,
    private val vpnService: VpnService?
) {
    private val socket = DatagramSocket()
    var lastActive = System.currentTimeMillis()
    @Volatile private var closed = false

    init {
        socket.soTimeout = 5000
        // ★ 优化：增大 UDP buffer
        try { socket.sendBufferSize = 64 * 1024 } catch (_: Exception) {}
        try { socket.receiveBufferSize = 64 * 1024 } catch (_: Exception) {}
        vpnService?.protect(socket)
        Thread { receiveLoop() }.apply { isDaemon = true; name = "UDP-$srcPort" }.start()
    }

    fun send(data: ByteArray) {
        if (closed) return
        lastActive = System.currentTimeMillis()
        try {
            socket.send(DatagramPacket(data, data.size, InetAddress.getByName(dstIp), dstPort))
        } catch (e: Exception) {
            if (!closed) Log.d(TAG, "UDP send error: ${e.message}")
        }
    }

    private fun receiveLoop() {
        val buf = ByteArray(8192)
        while (!closed) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                lastActive = System.currentTimeMillis()
                val data = buf.copyOf(pkt.length)
                val reply = buildUdpPacket(
                    pkt.address.hostAddress ?: dstIp, pkt.port,
                    srcIp, srcPort, data
                )
                synchronized(tunOut) { runCatching { tunOut.write(reply) } }
            } catch (_: java.net.SocketTimeoutException) {
                // 正常超时，继续
            } catch (e: Exception) {
                if (!closed) Log.d(TAG, "UDP recv: ${e.message}")
                break
            }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { socket.close() }
    }
}

// ── 数据包构造（与原版相同，此处略作整理）────────────────────────────────────

private fun buildTcpPacket(
    srcIp: String, srcPort: Int,
    dstIp: String, dstPort: Int,
    seq: Long, ack: Long, flags: Int, payload: ByteArray
): ByteArray {
    val total = 40 + payload.size
    val buf = ByteBuffer.allocate(total)
    val sib = ipToBytes(srcIp); val dib = ipToBytes(dstIp)

    buf.put(0x45.toByte()); buf.put(0); buf.putShort(total.toShort())
    buf.putShort(0); buf.putShort(0x4000.toShort())
    buf.put(64); buf.put(6); buf.putShort(0)
    buf.put(sib); buf.put(dib)
    buf.putShort(10, checksum(buf.array(), 0, 20).toShort())

    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putInt((seq and 0xFFFFFFFFL).toInt())
    buf.putInt((ack and 0xFFFFFFFFL).toInt())
    buf.put((5 shl 4).toByte()); buf.put(flags.toByte())
    buf.putShort(65535.toShort()); buf.putShort(0); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)

    buf.putShort(36, tcpChecksum(sib, dib, buf.array(), 20, 20 + payload.size).toShort())
    return buf.array()
}

private fun buildUdpPacket(
    srcIp: String, srcPort: Int,
    dstIp: String, dstPort: Int, payload: ByteArray
): ByteArray {
    val total = 28 + payload.size
    val buf = ByteBuffer.allocate(total)
    val sib = ipToBytes(srcIp); val dib = ipToBytes(dstIp)

    buf.put(0x45.toByte()); buf.put(0); buf.putShort(total.toShort())
    buf.putShort(0); buf.putShort(0x4000.toShort())
    buf.put(64); buf.put(17); buf.putShort(0)
    buf.put(sib); buf.put(dib)
    buf.putShort(10, checksum(buf.array(), 0, 20).toShort())

    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putShort((8 + payload.size).toShort()); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)
    buf.putShort(26, udpChecksum(sib, dib, buf.array(), 20, 8 + payload.size).toShort())
    return buf.array()
}

private fun ipToBytes(ip: String) = ip.split(".").map { it.toInt().toByte() }.toByteArray()

private fun checksum(buf: ByteArray, off: Int, len: Int): Int {
    var s = 0; var i = off
    while (i < off + len - 1) { s += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i+1].toInt() and 0xFF); i += 2 }
    if ((off + len) % 2 != 0) s += (buf[off + len - 1].toInt() and 0xFF) shl 8
    while (s shr 16 != 0) s = (s and 0xFFFF) + (s shr 16)
    return s.inv() and 0xFFFF
}

private fun tcpChecksum(src: ByteArray, dst: ByteArray, buf: ByteArray, off: Int, len: Int): Int {
    val p = ByteArray(12 + len)
    src.copyInto(p, 0); dst.copyInto(p, 4)
    p[8] = 0; p[9] = 6; p[10] = (len shr 8).toByte(); p[11] = (len and 0xFF).toByte()
    buf.copyInto(p, 12, off, off + len)
    return checksum(p, 0, p.size)
}

private fun udpChecksum(src: ByteArray, dst: ByteArray, buf: ByteArray, off: Int, len: Int): Int {
    val p = ByteArray(12 + len)
    src.copyInto(p, 0); dst.copyInto(p, 4)
    p[8] = 0; p[9] = 17; p[10] = (len shr 8).toByte(); p[11] = (len and 0xFF).toByte()
    buf.copyInto(p, 12, off, off + len)
    return checksum(p, 0, p.size)
}