package com.musicses.vlessvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

private const val TAG = "VlessVpnService"
private const val CH_ID = "vless_vpn"
private const val NOTIF_ID = 1

// TUN 虚拟网段配置
private const val VPN_ADDR      = "10.233.233.1"   // 客户端 TUN IP
private const val VPN_ROUTER    = "10.233.233.2"   // tun2socks 需要的 netif-ipaddr（对端）
private const val VPN_NETMASK   = "255.255.255.252" // /30 子网
private const val VPN_PREFIX    = 24
private const val MTU           = 1500

/**
 * VLESS VPN Service
 *
 * 架构（与 Node.js client.js 保持一致）：
 *
 *   App 流量
 *     │
 *     ▼
 *   TUN 接口 (10.233.233.1)
 *     │
 *     ▼  ← libtun2socks.so 处理 TCP/UDP 转发
 *   LocalSocks5Server (127.0.0.1:动态端口)
 *     │
 *     ▼  ← VlessTunnel (OkHttp WebSocket)
 *   VLESS Server (wss://...)
 *
 * tun2socks 负责：TUN 包 → SOCKS5 协议转换（TCP + UDP）
 * LocalSocks5Server 负责：SOCKS5 → VLESS/WebSocket 协议转换
 */
class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.musicses.vlessvpn.START"
        const val ACTION_STOP  = "com.musicses.vlessvpn.STOP"

        const val BROADCAST    = "com.musicses.vlessvpn.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_IN     = "bytes_in"
        const val EXTRA_OUT    = "bytes_out"
    }

    private var tun: ParcelFileDescriptor? = null
    private var socksServer: LocalSocks5Server? = null
    private var tun2socksThread: Thread? = null

    @Volatile private var running = false

    // ── 生命周期 ──────────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                Log.i(TAG, "Received STOP action")
                stopVpn()
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> {
                Log.i(TAG, "Received START action")
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> {
                Log.w(TAG, "Unknown action: ${intent?.action}")
                START_STICKY
            }
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked")
        stopVpn()
        super.onRevoke()
    }

    // ── 启动流程 ──────────────────────────────────────────────────────────────

    private fun startVpnInBackground() {
        if (running) {
            Log.w(TAG, "Already running, ignoring start request")
            return
        }
        running = true

        Thread(::doStart, "VPN-Start-Thread").start()
    }

    private fun doStart() {
        try {
            Log.i(TAG, "========== VPN Start (tun2socks mode) ==========")

            // ── Step 1: 加载 tun2socks 原生库 ─────────────────────────────────
            Log.d(TAG, "Step 1: Loading tun2socks native library...")
            try {
                Tun2Socks.initialize(applicationContext)
                Log.i(TAG, "✓ libtun2socks.so loaded")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "✗ Failed to load libtun2socks.so: ${e.message}")
                Log.e(TAG, "  Make sure libtun2socks.so is placed in app/src/main/jniLibs/<abi>/")
                broadcast("ERROR")
                return
            }

            // ── Step 2: 读取配置 ──────────────────────────────────────────────
            Log.d(TAG, "Step 2: Loading config...")
            val cfg = ConfigStore.loadActive(this)
            Log.i(TAG, "Config: ${cfg.name}  server=${cfg.server}:${cfg.port}")
            broadcast("CONNECTING")

            // ── Step 3: 启动本地 SOCKS5 代理（VLESS 出口）───────────────────
            Log.d(TAG, "Step 3: Starting LocalSocks5Server (VLESS tunnel)...")
            val server = LocalSocks5Server(cfg, this) { bytesIn, bytesOut ->
                broadcastStats(bytesIn, bytesOut)
                updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
            }
            socksServer = server
            val socksPort = server.start()
            Log.i(TAG, "✓ SOCKS5 proxy on 127.0.0.1:$socksPort")

            // ── Step 4: 建立 TUN 接口 ─────────────────────────────────────────
            Log.d(TAG, "Step 4: Establishing TUN interface...")
            val tunPfd = Builder()
                .setSession("VlessVPN")
                .setMtu(MTU)
                .addAddress(VPN_ADDR, VPN_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(cfg.dns1)
                .addDnsServer(cfg.dns2)
                .addDisallowedApplication(packageName) // 本应用流量不走 VPN（防环路）
                .establish()

            if (tunPfd == null) {
                Log.e(TAG, "✗ Failed to establish TUN interface (null). " +
                        "VPN permission not granted or another VPN is active.")
                broadcast("ERROR")
                server.stop()
                return
            }
            tun = tunPfd
            Log.i(TAG, "✓ TUN interface established, fd=${tunPfd.fd}")

            // ── Step 5: 启动 tun2socks（核心包转发引擎）─────────────────────
            // tun2socks 负责把 TUN 收到的 TCP/UDP 包转成 SOCKS5 请求
            // 转发到我们的 LocalSocks5Server，再由它建立 VLESS WebSocket 隧道
            Log.d(TAG, "Step 5: Starting tun2socks engine...")
            Log.d(TAG, "  tunfd        = ${tunPfd.fd}")
            Log.d(TAG, "  mtu          = $MTU")
            Log.d(TAG, "  socks5       = 127.0.0.1:$socksPort")
            Log.d(TAG, "  netif-ipaddr = $VPN_ROUTER")
            Log.d(TAG, "  netif-nmask  = $VPN_NETMASK")

            tun2socksThread = Thread({
                val ok = Tun2Socks.startTun2Socks(
                    /* logLevel                   */ Tun2Socks.LogLevel.INFO,
                    /* vpnInterfaceFileDescriptor */ tunPfd,
                    /* vpnInterfaceMtu            */ MTU,
                    /* socksServerAddress         */ "127.0.0.1",
                    /* socksServerPort            */ socksPort,
                    /* netIPv4Address             */ VPN_ROUTER,   // tun2socks 虚拟对端 IP
                    /* netIPv6Address             */ null,
                    /* netmask                    */ VPN_NETMASK,
                    /* forwardUdp                 */ true           // UDP 也走 SOCKS5
                )
                Log.i(TAG, "tun2socks exited, result=$ok")
            }, "tun2socks-engine").apply {
                isDaemon = false
                start()
            }

            Log.i(TAG, "========== VPN Connected ==========")
            Log.i(TAG, "Profile : ${cfg.name}")
            Log.i(TAG, "Server  : ${cfg.server}:${cfg.port}")
            Log.i(TAG, "SOCKS5  : 127.0.0.1:$socksPort")
            Log.i(TAG, "Engine  : libtun2socks.so")
            Log.i(TAG, "===================================")
            broadcast("CONNECTED")
            updateNotif("${cfg.name} • Connected")

        } catch (e: SecurityException) {
            Log.e(TAG, "Security exception", e)
            broadcast("ERROR"); cleanup()
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during VPN start", e)
            broadcast("ERROR"); cleanup()
        }
    }

    // ── 停止流程 ──────────────────────────────────────────────────────────────

    private fun stopVpn() {
        if (!running) return
        running = false
        Log.i(TAG, "Stopping VPN...")
        cleanup()
        broadcast("DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "✓ VPN stopped")
    }

    private fun cleanup() {
        // 1. 停止 tun2socks（会触发 tun2socks_terminate，让阻塞的 startTun2Socks 返回）
        runCatching { Tun2Socks.stopTun2Socks() }
        runCatching { tun2socksThread?.join(3000) }
        tun2socksThread = null

        // 2. 停止本地 SOCKS5 代理
        runCatching { socksServer?.stop() }
        socksServer = null

        // 3. 关闭 TUN 接口（关闭后 tun2socks 也会退出）
        runCatching { tun?.close() }
        tun = null
    }

    // ── 广播 ──────────────────────────────────────────────────────────────────

    private fun broadcast(status: String) {
        Log.d(TAG, "Status → $status")
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, status)
            setPackage(packageName)
        })
    }

    private fun broadcastStats(bytesIn: Long, bytesOut: Long) {
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, "CONNECTED")
            putExtra(EXTRA_IN,  bytesIn)
            putExtra(EXTRA_OUT, bytesOut)
            setPackage(packageName)
        })
    }

    // ── 通知 ──────────────────────────────────────────────────────────────────

    private fun buildNotif(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val openPi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, VlessVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle("VLESS VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openPi)
            .addAction(0, "Disconnect", stopPi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotif(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotif(text))
    }

    private fun fmt(b: Long) = when {
        b < 1024L        -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else             -> "${"%.1f".format(b / 1048576.0)}M"
    }
}