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
import java.util.Collections

private const val TAG = "VlessVpnService"
private const val CH_ID = "vless_vpn"
private const val NOTIF_ID = 1

// TUN 虚拟网卡地址
private const val TUN_ADDR = "10.0.0.2"
// tun2socks 需要的 --netif-ipaddr 是"虚拟网关"，必须和 TUN 地址同网段但不同
private const val NET_IF_ADDR = "10.0.0.1"   // tun2socks 的 --netif-ipaddr 参数
private const val VPN_PREFIX = 24
private const val NETMASK = "255.255.255.0"
private const val MTU = 1500

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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                Log.i(TAG, "Received STOP action")
                stopVpn(); stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> {
                Log.i(TAG, "Received START action")
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> START_STICKY
        }
    }

    override fun onDestroy() { Log.i(TAG, "onDestroy"); stopVpn(); super.onDestroy() }
    override fun onRevoke()  { Log.w(TAG, "VPN revoked"); stopVpn(); super.onRevoke() }

    private fun startVpnInBackground() {
        if (running) { Log.w(TAG, "Already running"); return }
        running = true
        Thread(::doStart, "VPN-Start").start()
    }

    private fun doStart() {
        try {
            Log.i(TAG, "========== VPN Start ==========")

            val cfg = ConfigStore.loadActive(this)
            Log.i(TAG, "Config: ${cfg.name}  server=${cfg.server}:${cfg.port}")
            broadcast("CONNECTING")

            // ★ 第一步：建立带 protect 的 OkHttpClient（必须在 TUN 建立之前）
            VlessTunnel.getOrCreateClient(cfg, this)
            Log.i(TAG, "✓ Protected OkHttpClient ready")

            // ★ 第二步：加载 tun2socks native 库
            Tun2Socks.initialize(this)
            Log.d(TAG, "✓ tun2socks library loaded")

            // ★ 第三步：启动 SOCKS5 本地代理
            val server = LocalSocks5Server(cfg, this) { bytesIn, bytesOut ->
                broadcastStats(bytesIn, bytesOut)
                updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
            }
            socksServer = server
            val socksPort = server.start()
            Log.i(TAG, "✓ SOCKS5 on 127.0.0.1:$socksPort")

            // ★ 第四步：建立 TUN 接口
            // 注意：addDisallowedApplication 排除自身，防止 VPN 流量递归
            val tunPfd = Builder()
                .setSession("VlessVPN")
                .setMtu(MTU)
                .addAddress(TUN_ADDR, VPN_PREFIX)          // TUN 自身地址
                .addRoute("0.0.0.0", 0)                    // 路由所有 IPv4
                .addDnsServer(cfg.dns1)
                .addDnsServer(cfg.dns2)
                .addDisallowedApplication(packageName)     // 排除本 app 自身，防止环路
                .establish()
                ?: throw Exception("TUN establish failed — VPN permission not granted?")

            tun = tunPfd
            Log.i(TAG, "✓ TUN established, fd=${tunPfd.fd}, addr=$TUN_ADDR/$VPN_PREFIX")
            Log.i(TAG, "✓ VPN Connected")
            broadcast("CONNECTED")
            updateNotif("${cfg.name} • Connected")

            // ★ 第五步：启动 tun2socks
            // 关键参数说明：
            //   --netif-ipaddr  = tun2socks 虚拟网关 IP（NOT TUN 地址，是 tun2socks 内部虚拟路由器地址）
            //   --tunfd         = TUN 文件描述符
            //   不要开 --socks5-udp，因为我们的 SOCKS5 服务器对 UDP 支持有限，
            //   强制 UDP 会导致 tun2socks 立即退出
            val t = Thread({
                Log.i(TAG, "tun2socks starting → socks=127.0.0.1:$socksPort  netif=$NET_IF_ADDR")
                val ok = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.NOTICE,
                    tunPfd,
                    MTU,
                    "127.0.0.1",
                    socksPort,
                    NET_IF_ADDR,        // ★ --netif-ipaddr：tun2socks 的虚拟路由器地址
                    null,               // 不处理 IPv6
                    NETMASK,
                    false,              // ★ 关闭 UDP 转发，防止 tun2socks 因 UDP 失败退出
                    Collections.emptyList()
                )
                Log.i(TAG, "tun2socks exited with result: $ok")
                if (!ok && running) {
                    Log.e(TAG, "✗ tun2socks exited unexpectedly")
                    broadcast("ERROR")
                }
            }, "tun2socks-main")

            t.isDaemon = true
            t.start()
            tun2socksThread = t

        } catch (e: Exception) {
            Log.e(TAG, "VPN start error: ${e.message}", e)
            broadcast("ERROR")
            cleanup()
        }
    }

    private fun stopVpn() {
        if (!running) return
        running = false
        Log.i(TAG, "Stopping VPN...")

        try { Tun2Socks.stopTun2Socks() } catch (_: Exception) {}
        tun2socksThread?.join(3000)
        tun2socksThread = null

        cleanup()
        broadcast("DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "✓ VPN stopped")
    }

    private fun cleanup() {
        runCatching { socksServer?.stop() }; socksServer = null
        VlessTunnel.clearSharedClients()
        runCatching { tun?.close() }; tun = null
    }

    private fun broadcast(status: String) {
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, status)
            setPackage(packageName)
        })
    }

    private fun broadcastStats(bytesIn: Long, bytesOut: Long) {
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, "CONNECTED")
            putExtra(EXTRA_IN, bytesIn)
            putExtra(EXTRA_OUT, bytesOut)
            setPackage(packageName)
        })
    }

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
            .addAction(0, "断开", stopPi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotif(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotif(text))
    }

    private fun fmt(b: Long) = when {
        b < 1024L -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else -> "${"%.1f".format(b / 1048576.0)}M"
    }
}