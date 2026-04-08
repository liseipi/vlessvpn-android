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
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "TunHandler"
private const val MTU = 1500

class TunHandler(
    private var fd: FileDescriptor?,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = false

    private val totalIn  = AtomicLong(0)
    private val totalOut = AtomicLong(0)

    private lateinit var socksServer: LocalSocks5Server
    private var socksPort: Int = 0

    private val tcpFlows    = ConcurrentHashMap<String, TcpProxy>()
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()

    private val pktTotal = AtomicLong(0)
    private val pktTcp   = AtomicLong(0)
    private val pktUdp   = AtomicLong(0)
    private val pktOther = AtomicLong(0)

    fun start() {
        running = true
        socksServer = LocalSocks5Server(cfg, vpnService) { bytesIn, bytesOut ->
            val newIn  = totalIn.addAndGet(bytesIn)
            val newOut = totalOut.addAndGet(bytesOut)
            onStats(newIn, newOut)
        }
        socksPort = socksServer.start()
        Log.i(TAG, "✓ SOCKS5 proxy started on 127.0.0.1:$socksPort")
        executor.submit { udpSessionCleanup() }
        executor.submit { diagnosticLoop() }
    }

    fun stop() {
        running = false
        socksServer.stop()
        tcpFlows.values.forEach { it.close() }
        tcpFlows.clear()
        udpSessions.values.forEach { it.close() }
        udpSessions.clear()
        executor.shutdownNow()
        Log.i(TAG, "TunHandler stopped")
    }

    fun getSocksPort(): Int = socksPort

    fun setTunFd(tunFd: FileDescriptor) {
        this.fd = tunFd
        executor.submit { tunReadLoop(tunFd) }
        Log.i(TAG, "★ TUN fd set, starting read loop")
    }

    private fun diagnosticLoop() {
        var lastIn = 0L; var lastOut = 0L
        while (running) {
            try {
                Thread.sleep(5000)
                val ci = totalIn.get(); val co = totalOut.get()
                Log.i(TAG, "══ DIAG ══ pkts=${pktTotal.get()} tcp=${pktTcp.get()} " +
                        "udp=${pktUdp.get()} other=${pktOther.get()} | " +
                        "flows=${tcpFlows.size} udpSess=${udpSessions.size} | " +
                        "in=${ci}B out=${co}B Δin=${ci-lastIn}B Δout=${co-lastOut}B")
                lastIn = ci; lastOut = co
            } catch (_: InterruptedException) { break }
        }
    }

    // ── TUN 读取主循环 ───────────────────────────────────────────────────────
    private fun tunReadLoop(tunFd: FileDescriptor) {
        val fis = FileInputStream(tunFd)
        val fos = FileOutputStream(tunFd)
        val buf = ByteArray(MTU)

        Log.i(TAG, "★ TUN read loop STARTED, vpnService=${if (vpnService != null) "OK" else "NULL"}")
        var readCount = 0L

        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 0) { Log.w(TAG, "TUN EOF"); break }
                if (n == 0) continue   // 暂无数据，继续
                if (n < 20) continue   // 包太短

                readCount++
                pktTotal.incrementAndGet()
                if (readCount <= 5L || readCount % 200 == 0L) {
                    Log.d(TAG, "★ TUN read #$readCount: ${n}B proto=${buf[9].toInt() and 0xFF}")
                }
                handleIpPacket(buf.copyOf(n), fos)
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}", e)
        }
        Log.w(TAG, "★ TUN read loop ENDED after $readCount packets")
    }

    private fun handleIpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        if (packet.size < 20) return
        try {
            if ((packet[0].toInt() and 0xFF) ushr 4 != 4) return  // IPv4 only
            when (packet[9].toInt() and 0xFF) {
                6  -> { pktTcp.incrementAndGet();   handleTcpPacket(packet, tunOut) }
                17 -> { pktUdp.incrementAndGet();   handleUdpPacket(packet, tunOut) }
                1  -> { pktOther.incrementAndGet(); handleIcmpPacket(packet, tunOut) }
                else -> pktOther.incrementAndGet()
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleIpPacket: ${e.message}")
        }
    }

    // ── TCP 处理 ─────────────────────────────────────────────────────────────
    private fun handleTcpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 20) return

        val srcIp   = formatIp(packet, 12)
        val dstIp   = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)
        val seqNum  = readUInt32(packet, ihl + 4)

        val flags  = packet[ihl + 13].toInt() and 0xFF
        val isSyn  = (flags and 0x02) != 0
        val isFin  = (flags and 0x01) != 0
        val isRst  = (flags and 0x04) != 0
        val isAck  = (flags and 0x10) != 0

        val flowKey      = "$srcIp:$srcPort->$dstIp:$dstPort"
        val dataOffset   = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payloadStart = ihl + dataOffset
        val payload = if (packet.size > payloadStart)
            packet.copyOfRange(payloadStart, packet.size) else ByteArray(0)

        when {
            isSyn && !isAck -> {
                Log.d(TAG, "[$flowKey] SYN (flows: ${tcpFlows.size + 1})")
                val proxy = TcpProxy(
                    srcIp, srcPort, dstIp, dstPort,
                    seqNum, socksPort, tunOut, vpnService,
                    onBytesDown = { bytes ->
                        val newOut = totalOut.addAndGet(bytes)
                        onStats(totalIn.get(), newOut)
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
                if (flow == null) {
                    Log.w(TAG, "[$flowKey] DATA ${payload.size}B but no flow")
                } else {
                    flow.receiveData(payload, seqNum)
                    val newIn = totalIn.addAndGet(payload.size.toLong())
                    onStats(newIn, totalOut.get())
                }
            }
            isAck && payload.isEmpty() -> tcpFlows[flowKey]?.updateAck()
        }
    }

    // ── UDP 处理 ─────────────────────────────────────────────────────────────
    private fun handleUdpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return
        val srcIp   = formatIp(packet, 12); val dstIp   = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl); val dstPort = readUInt16(packet, ihl + 2)
        val payloadStart = ihl + 8
        if (packet.size <= payloadStart) return
        val payload = packet.copyOfRange(payloadStart, packet.size)
        val key = "$srcIp:$srcPort->$dstIp:$dstPort"
        if (dstPort == 53) Log.d(TAG, "[$key] DNS ${payload.size}B")
        val session = udpSessions.getOrPut(key) {
            UdpSession(srcIp, srcPort, dstIp, dstPort, tunOut, vpnService) { bytes ->
                val newIn = totalIn.addAndGet(bytes)
                onStats(newIn, totalOut.get())
            }
        }
        session.updateLastActive()
        session.send(payload)
        val newOut = totalOut.addAndGet(payload.size.toLong())
        onStats(totalIn.get(), newOut)
    }

    // ── ICMP 处理 ────────────────────────────────────────────────────────────
    private fun handleIcmpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (packet.size < ihl + 8 || packet[ihl].toInt() and 0xFF != 8) return
        val reply = packet.copyOf()
        ipToBytes(formatIp(packet, 16)).copyInto(reply, 12)
        ipToBytes(formatIp(packet, 12)).copyInto(reply, 16)
        reply[ihl] = 0x00
        reply[10] = 0; reply[11] = 0
        val ipCs = checksum(reply, 0, ihl)
        reply[10] = (ipCs ushr 8).toByte(); reply[11] = (ipCs and 0xFF).toByte()
        reply[ihl + 2] = 0; reply[ihl + 3] = 0
        val icmpCs = checksum(reply, ihl, packet.size - ihl)
        reply[ihl + 2] = (icmpCs ushr 8).toByte(); reply[ihl + 3] = (icmpCs and 0xFF).toByte()
        synchronized(tunOut) { runCatching { tunOut.write(reply) } }
    }

    private fun udpSessionCleanup() {
        while (running) {
            try {
                Thread.sleep(30000)
                val now = System.currentTimeMillis()
                udpSessions.filterValues { now - it.lastActive > 60000 }.forEach { (k, s) ->
                    s.close(); udpSessions.remove(k)
                }
            } catch (_: InterruptedException) { break }
        }
    }

    private fun formatIp(p: ByteArray, o: Int) =
        "${p[o].toInt() and 0xFF}.${p[o+1].toInt() and 0xFF}.${p[o+2].toInt() and 0xFF}.${p[o+3].toInt() and 0xFF}"
    private fun readUInt16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o+1].toInt() and 0xFF)
    private fun readUInt32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o+1].toLong() and 0xFF) shl 16) or
                ((b[o+2].toLong() and 0xFF) shl 8) or (b[o+3].toLong() and 0xFF)
}

// ── TcpProxy ─────────────────────────────────────────────────────────────────

private class TcpProxy(
    private val srcIp:   String,
    private val srcPort: Int,
    private val dstIp:   String,
    private val dstPort: Int,
    private val initialClientSeq: Long,
    private val socksPort: Int,
    private val tunOut:  FileOutputStream,
    private val vpnService: VpnService?,
    private val onBytesDown: (Long) -> Unit
) {
    private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
    private var clientAck = initialClientSeq + 1

    private var socksSocket: Socket? = null
    @Volatile private var closed = false

    // ★ 修复"socket not ready, dropping"：连接建立前把数据缓冲起来
    private val pendingData = LinkedBlockingQueue<ByteArray>(200)
    @Volatile private var ready = false   // SOCKS5 握手完成后置 true

    private val id = "$srcIp:$srcPort→$dstIp:$dstPort"

    fun start() {
        Thread {
            try {
                writeSynAck()

                val sock = Socket()
                sock.tcpNoDelay = true
                if (vpnService != null) {
                    if (!vpnService.protect(sock)) Log.e(TAG, "[$id] protect failed")
                    else Log.d(TAG, "[$id] ✓ protected")
                } else {
                    Log.e(TAG, "[$id] vpnService NULL!")
                }

                sock.connect(InetSocketAddress("127.0.0.1", socksPort), 10000)
                sock.soTimeout = 30000
                socksSocket = sock
                Log.d(TAG, "[$id] ✓ connected to SOCKS5")

                socks5Handshake(sock.getOutputStream(), sock.getInputStream())
                Log.i(TAG, "[$id] ✓ SOCKS5 OK")

                // ★ 握手完成，先把缓冲的数据发出去，再标记 ready
                val buffered = mutableListOf<ByteArray>()
                pendingData.drainTo(buffered)
                if (buffered.isNotEmpty()) {
                    Log.d(TAG, "[$id] flushing ${buffered.size} buffered chunks")
                    val out = sock.getOutputStream()
                    for (chunk in buffered) { out.write(chunk); out.flush() }
                }
                ready = true

                // 下行读取线程
                Thread {
                    var total = 0L
                    try {
                        val buf = ByteArray(8192)
                        while (!closed && !sock.isClosed) {
                            val n = sock.getInputStream().read(buf)
                            if (n < 0) break
                            total += n
                            writeDataToTun(buf.copyOf(n))
                            onBytesDown(n.toLong())
                        }
                    } catch (e: Exception) {
                        if (!closed) Log.d(TAG, "[$id] downstream: ${e.message}")
                    } finally {
                        Log.d(TAG, "[$id] downstream ended total=${total}B")
                        close()
                    }
                }.apply { isDaemon = true; name = "down-$srcPort" }.start()

            } catch (e: Exception) {
                Log.e(TAG, "[$id] start error: ${e.message}", e)
                close()
            }
        }.apply { isDaemon = true; name = "TcpProxy-$srcPort" }.start()
    }

    private fun socks5Handshake(out: OutputStream, inp: InputStream) {
        out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
        val auth = readFully(inp, 2)
        check(auth[0] == 0x05.toByte() && auth[1] == 0x00.toByte()) { "auth failed" }

        out.write(buildConnectReq(dstIp, dstPort)); out.flush()
        val resp = readFully(inp, 4)
        check(resp[0] == 0x05.toByte()) { "not SOCKS5 resp" }
        check(resp[1] == 0x00.toByte()) { "CONNECT refused: REP=${resp[1].toInt() and 0xFF}" }

        val skip = when (resp[3].toInt() and 0xFF) {
            0x01 -> 4 + 2
            0x03 -> inp.read() + 2
            0x04 -> 16 + 2
            else -> 4 + 2
        }
        readFully(inp, skip)
    }

    private fun buildConnectReq(host: String, port: Int): ByteArray {
        val isIpv4 = host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
        return if (isIpv4) {
            val p = host.split(".")
            byteArrayOf(0x05, 0x01, 0x00, 0x01,
                p[0].toInt().toByte(), p[1].toInt().toByte(),
                p[2].toInt().toByte(), p[3].toInt().toByte(),
                (port shr 8).toByte(), (port and 0xFF).toByte())
        } else {
            val hb = host.toByteArray()
            ByteArray(7 + hb.size).also { r ->
                r[0] = 0x05; r[1] = 0x01; r[2] = 0x00; r[3] = 0x03
                r[4] = hb.size.toByte()
                hb.copyInto(r, 5)
                r[5 + hb.size] = (port shr 8).toByte()
                r[6 + hb.size] = (port and 0xFF).toByte()
            }
        }
    }

    private fun readFully(inp: InputStream, n: Int): ByteArray {
        if (n == 0) return ByteArray(0)
        val buf = ByteArray(n); var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r < 0) throw EOFException("closed at $off/$n")
            off += r
        }
        return buf
    }

    fun receiveData(data: ByteArray, seqNum: Long) {
        if (closed) return
        clientAck = seqNum + data.size

        if (!ready) {
            // ★ 还没握手完成，先缓冲，不要丢弃
            if (!pendingData.offer(data)) {
                Log.w(TAG, "[$id] pending buffer full, dropping ${data.size}B")
            } else {
                Log.d(TAG, "[$id] buffered ${data.size}B (connecting)")
            }
            writeAck()  // 还是要发 ACK，让客户端知道数据已收
            return
        }

        try {
            val out = socksSocket?.getOutputStream() ?: return
            out.write(data); out.flush()
            writeAck()
        } catch (e: Exception) {
            Log.d(TAG, "[$id] receiveData: ${e.message}")
            close()
        }
    }

    fun updateAck() {}

    private fun writeAck() {
        val pkt = buildTcpPacket(dstIp, dstPort, srcIp, srcPort,
            serverSeq, clientAck, 0x10, ByteArray(0))
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    private fun writeDataToTun(data: ByteArray) {
        if (closed) return
        val pkt = buildTcpPacket(dstIp, dstPort, srcIp, srcPort,
            serverSeq, clientAck, 0x18, data)
        serverSeq = (serverSeq + data.size) and 0xFFFFFFFFL
        synchronized(tunOut) {
            try { tunOut.write(pkt) }
            catch (e: Exception) { Log.d(TAG, "[$id] TUN write: ${e.message}") }
        }
    }

    private fun writeSynAck() {
        val pkt = buildTcpPacket(dstIp, dstPort, srcIp, srcPort,
            serverSeq, initialClientSeq + 1, 0x12, ByteArray(0))
        serverSeq = (serverSeq + 1) and 0xFFFFFFFFL
        synchronized(tunOut) { runCatching { tunOut.write(pkt) } }
    }

    fun close() {
        if (closed) return; closed = true
        runCatching { socksSocket?.close() }
    }
}

// ── UdpSession ───────────────────────────────────────────────────────────────

private class UdpSession(
    private val srcIp: String, private val srcPort: Int,
    private val dstIp: String, private val dstPort: Int,
    private val tunOut: FileOutputStream,
    private val vpnService: VpnService?,
    private val onBytesIn: (Long) -> Unit
) {
    private var udpSocket: DatagramSocket? = null
    var lastActive = System.currentTimeMillis()
    @Volatile private var closed = false

    init {
        try {
            val sock = DatagramSocket()
            sock.soTimeout = 5000
            vpnService?.protect(sock)
            udpSocket = sock
            Thread { receiveLoop() }.apply { isDaemon = true; name = "UDP-$srcPort" }.start()
        } catch (e: Exception) { Log.e(TAG, "UDP init: ${e.message}") }
    }

    fun send(data: ByteArray) {
        if (closed) return
        try {
            udpSocket?.send(DatagramPacket(data, data.size, InetAddress.getByName(dstIp), dstPort))
            lastActive = System.currentTimeMillis()
        } catch (e: Exception) { Log.e(TAG, "UDP send: ${e.message}") }
    }

    private fun receiveLoop() {
        val buf = ByteArray(2048)
        while (!closed) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                udpSocket?.receive(pkt)
                val data = buf.copyOf(pkt.length)
                lastActive = System.currentTimeMillis()
                onBytesIn(data.size.toLong())
                val out = buildUdpPacket(pkt.address.hostAddress ?: dstIp,
                    pkt.port, srcIp, srcPort, data)
                synchronized(tunOut) { runCatching { tunOut.write(out) } }
            } catch (_: java.net.SocketTimeoutException) {
            } catch (e: Exception) {
                if (!closed) Log.e(TAG, "UDP recv: ${e.message}")
                break
            }
        }
    }

    fun updateLastActive() { lastActive = System.currentTimeMillis() }
    fun close() { if (closed) return; closed = true; runCatching { udpSocket?.close() } }
}

// ── 数据包构建 ────────────────────────────────────────────────────────────────

private fun buildTcpPacket(
    srcIp: String, srcPort: Int, dstIp: String, dstPort: Int,
    seq: Long, ack: Long, flags: Int, payload: ByteArray
): ByteArray {
    val total = 40 + payload.size; val buf = ByteBuffer.allocate(total)
    val si = ipToBytes(srcIp); val di = ipToBytes(dstIp)
    buf.put(0x45.toByte()); buf.put(0); buf.putShort(total.toShort())
    buf.putShort(0); buf.putShort(0x4000.toShort()); buf.put(64); buf.put(6); buf.putShort(0)
    buf.put(si); buf.put(di)
    buf.putShort(10, checksum(buf.array(), 0, 20).toShort())
    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putInt((seq and 0xFFFFFFFFL).toInt()); buf.putInt((ack and 0xFFFFFFFFL).toInt())
    buf.put((5 shl 4).toByte()); buf.put(flags.toByte())
    buf.putShort(65535.toShort()); buf.putShort(0); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)
    buf.putShort(36, tcpChecksum(si, di, buf.array(), 20, 20 + payload.size).toShort())
    return buf.array()
}

private fun buildUdpPacket(
    srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, payload: ByteArray
): ByteArray {
    val total = 28 + payload.size; val buf = ByteBuffer.allocate(total)
    val si = ipToBytes(srcIp); val di = ipToBytes(dstIp)
    buf.put(0x45.toByte()); buf.put(0); buf.putShort(total.toShort())
    buf.putShort(0); buf.putShort(0x4000.toShort()); buf.put(64); buf.put(17); buf.putShort(0)
    buf.put(si); buf.put(di)
    buf.putShort(10, checksum(buf.array(), 0, 20).toShort())
    buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
    buf.putShort((8 + payload.size).toShort()); buf.putShort(0)
    if (payload.isNotEmpty()) buf.put(payload)
    buf.putShort(26, udpChecksum(si, di, buf.array(), 20, 8 + payload.size).toShort())
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

private fun tcpChecksum(si: ByteArray, di: ByteArray, buf: ByteArray, off: Int, len: Int): Int {
    val p = ByteArray(12 + len); si.copyInto(p, 0); di.copyInto(p, 4); p[9] = 6
    p[10] = (len shr 8).toByte(); p[11] = (len and 0xFF).toByte()
    buf.copyInto(p, 12, off, off + len); return checksum(p, 0, p.size)
}

private fun udpChecksum(si: ByteArray, di: ByteArray, buf: ByteArray, off: Int, len: Int): Int {
    val p = ByteArray(12 + len); si.copyInto(p, 0); di.copyInto(p, 4); p[9] = 17
    p[10] = (len shr 8).toByte(); p[11] = (len and 0xFF).toByte()
    buf.copyInto(p, 12, off, off + len); return checksum(p, 0, p.size)
}