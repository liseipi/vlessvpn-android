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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * ★★★ 重写版 TunHandler ★★★
 *
 * 修复：
 * 1. "DATA XB but no flow" → 增加流生命周期管理，避免数据到达时流已清理
 * 2. 流量统计正确
 * 3. 诊断日志优化（减少噪音，保留关键信息）
 * 4. UDP 会话稳定性改进
 */
class TunHandler(
    private var fd: FileDescriptor?,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
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
            val tIn = totalIn.addAndGet(bytesIn)
            val tOut = totalOut.addAndGet(bytesOut)
            onStats(tIn, tOut)
        }
        socksPort = socksServer.start()
        Log.i(TAG, "✓ SOCKS5 proxy started on 127.0.0.1:$socksPort")

        // 定期诊断日志（每5秒）
        scheduler.scheduleAtFixedRate({
            if (running) logDiag()
        }, 5, 5, TimeUnit.SECONDS)

        // 定期清理 UDP 会话（每30秒）
        scheduler.scheduleAtFixedRate({
            if (running) cleanupUdpSessions()
        }, 30, 30, TimeUnit.SECONDS)
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
        val buf = ByteArray(MTU)

        Log.i(TAG, "★ TUN read loop STARTED, vpnService=${if (vpnService != null) "OK" else "null"}")

        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 20) continue

                val count = pktReadCount.incrementAndGet()
                if (count % 200 == 0L) {
                    Log.d(TAG, "★ TUN read #$count: ${n}B proto=${buf[9].toInt() and 0xFF}")
                }

                val packet = buf.copyOf(n)
                handleIpPacket(packet, fos)
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}")
        }

        Log.i(TAG, "★ TUN read loop ENDED")
    }

    private fun handleIpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        try {
            val version = (packet[0].toInt() and 0xFF) ushr 4
            if (version != 4) return

            totalPkts.incrementAndGet()
            val protocol = packet[9].toInt() and 0xFF

            when (protocol) {
                6  -> { tcpPkts.incrementAndGet(); handleTcpPacket(packet, tunOut) }
                17 -> { udpPkts.incrementAndGet(); handleUdpPacket(packet, tunOut) }
                1  -> handleIcmpPacket(packet, tunOut)
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
                // 关闭旧流（如果存在）
                tcpFlows.remove(flowKey)?.close()

                val currentFlows = tcpFlows.size
                Log.d(TAG, "[$flowKey] SYN (flows: ${currentFlows + 1})")

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
                proxy.start()
            }

            isFin || isRst -> {
                tcpFlows.remove(flowKey)?.close()
            }

            payload.isNotEmpty() -> {
                val flow = tcpFlows[flowKey]
                if (flow != null) {
                    flow.receiveData(payload, seqNum)
                } else {
                    // 流不存在（可能已关闭），忽略
                    Log.d(TAG, "[$flowKey] DATA ${payload.size}B but no flow")
                }
            }
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

        val session = udpSessions.getOrPut(sessionKey) {
            UdpSession(srcIp, srcPort, dstIp, dstPort, tunOut, vpnService).also {
                Log.d(TAG, "[$sessionKey] UDP session opened (total=${udpSessions.size + 1})")
            }
        }
        session.send(payload)
    }

    // ── ICMP ─────────────────────────────────────────────────────────────────

    private fun handleIcmpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return
        if (packet[ihl].toInt() and 0xFF != 8) return  // 只处理 Echo Request

        val reply = packet.copyOf()
        ipToBytes(formatIp(packet, 16)).copyInto(reply, 12)
        ipToBytes(formatIp(packet, 12)).copyInto(reply, 16)
        reply[ihl] = 0x00

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
        val stale = udpSessions.filterValues { now - it.lastActive > 120_000 }
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

        Log.i(TAG, "══ DIAG ══ pkts=${totalPkts.get()} tcp=${tcpPkts.get()} udp=${udpPkts.get()} other=2" +
                " | flows=${tcpFlows.size} udpSess=${udpSessions.size}" +
                " | in=${inNow}B out=${outNow}B Δin=${deltaIn}B Δout=${deltaOut}B")
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
    private val connected = java.util.concurrent.CountDownLatch(1)
    @Volatile private var closed = false
    @Volatile private var isConnected = false

    private var totalDown = 0L
    private var totalUp   = 0L

    fun start() {
        Thread {
            try {
                writeSynAck()

                val sock = Socket()
                sock.tcpNoDelay = true
                sock.soTimeout = 30000
                sock.connect(InetSocketAddress("127.0.0.1", socksPort), 5000)
                socksSocket = sock

                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ protected")
                performSocks5Handshake(sock.getOutputStream(), sock.getInputStream())
                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ connected to SOCKS5")

                isConnected = true
                connected.countDown()
                Log.i(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ SOCKS5 OK")

                // 读取来自服务器的响应
                Thread {
                    val buf = ByteArray(16384)
                    try {
                        while (!closed && !sock.isClosed) {
                            val n = sock.getInputStream().read(buf)
                            if (n < 0) break
                            val data = buf.copyOf(n)
                            totalDown += n
                            onDown(n.toLong())
                            writeDataToTun(data)
                        }
                    } catch (e: Exception) {
                        if (!closed) Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] downstream ended total=${totalDown}B")
                    } finally {
                        close()
                    }
                }.apply { isDaemon = true }.start()

            } catch (e: Exception) {
                Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] connect error: ${e.message}")
                connected.countDown()
                close()
            }
        }.apply { isDaemon = true; name = "TCP-$srcPort→$dstPort" }.start()
    }

    fun receiveData(data: ByteArray, seqNum: Long) {
        if (closed) return

        clientAck = seqNum + data.size

        if (!connected.await(10, TimeUnit.SECONDS) || !isConnected) {
            close()
            return
        }

        try {
            socksSocket?.getOutputStream()?.write(data)
            totalUp += data.size
            onUp(data.size.toLong())
            writeAck()
        } catch (e: Exception) {
            if (!closed) Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] send error: ${e.message}")
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

    private fun writeDataToTun(data: ByteArray) {
        if (closed) return
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
        out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
        val r1 = ByteArray(2); inp.read(r1)
        if (r1[0] != 0x05.toByte() || r1[1] != 0x00.toByte()) throw IOException("SOCKS5 auth")

        val req = buildSocks5Request(dstIp, dstPort)
        out.write(req); out.flush()

        val r2 = ByteArray(10); inp.read(r2)
        if (r2[0] != 0x05.toByte() || r2[1] != 0x00.toByte()) throw IOException("SOCKS5 connect")
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
        connected.countDown()
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
        vpnService?.protect(socket)
        Thread { receiveLoop() }.apply { isDaemon = true }.start()
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
        val buf = ByteArray(4096)
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
            } catch (e: Exception) {
                if (!closed) break
            }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { socket.close() }
    }
}

// ── 数据包构造 ────────────────────────────────────────────────────────────────

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
    val ipCsum = checksum(buf.array(), 0, 20)
    buf.putShort(10, ipCsum.toShort())

    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putInt((seq and 0xFFFFFFFFL).toInt())
    buf.putInt((ack and 0xFFFFFFFFL).toInt())
    buf.put((5 shl 4).toByte()); buf.put(flags.toByte())
    buf.putShort(65535.toShort()); buf.putShort(0); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)

    val tcpLen = 20 + payload.size
    val tcpCsum = tcpChecksum(sib, dib, buf.array(), 20, tcpLen)
    buf.putShort(36, tcpCsum.toShort())
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
    val ipCsum = checksum(buf.array(), 0, 20)
    buf.putShort(10, ipCsum.toShort())

    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putShort((8 + payload.size).toShort()); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)

    val udpCsum = udpChecksum(sib, dib, buf.array(), 20, 8 + payload.size)
    buf.putShort(26, udpCsum.toShort())
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