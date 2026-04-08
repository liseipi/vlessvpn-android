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
private const val VPN_ADDR = "10.233.233.1"
private const val VPN_PREFIX = 24
private const val MTU = 1500

/**
 * ★ 使用 TunHandler 的版本（备用方案）
 *
 * 如果缺少 libtun2socks.so，可以用这个版本替换
 *
 * 架构：
 *   App 流量
 *     │
 *     ▼
 *   TUN 接口 (10.233.233.1)
 *     │
 *     ▼  ← TunHandler (Kotlin 实现的 TCP/UDP 处理)
 *   LocalSocks5Server (127.0.0.1:动态端口)
 *     │
 *     ▼  ← VlessTunnel (OkHttp WebSocket)
 *   VLESS Server (wss://...)
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
    private var tunHandler: TunHandler? = null

    @Volatile private var running = false

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

    private fun startVpnInBackground() {
        if (running) {
            Log.w(TAG, "Already running")
            return
        }
        running = true

        Thread(::doStart, "VPN-Start-Thread").start()
    }

    private fun doStart() {
        try {
            Log.i(TAG, "========== VPN Start (TunHandler Mode) ==========")

            // Step 1: 加载配置
            Log.d(TAG, "Step 1: Loading config...")
            val cfg = ConfigStore.loadActive(this)
            Log.i(TAG, "Config: ${cfg.name}  server=${cfg.server}:${cfg.port}")
            broadcast("CONNECTING")

            // Step 2: 创建 TunHandler (包含内置 SOCKS5)
            Log.d(TAG, "Step 2: Creating TunHandler...")
            val handler = TunHandler(null, cfg, this) { bytesIn, bytesOut ->
                broadcastStats(bytesIn, bytesOut)
                updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
            }
            tunHandler = handler
            handler.start()

            val socksPort = handler.getSocksPort()
            Log.i(TAG, "✓ TunHandler created, SOCKS5 on 127.0.0.1:$socksPort")

            // Step 3: 建立 TUN 接口
            Log.d(TAG, "Step 3: Establishing TUN interface...")
            val tunPfd = Builder()
                .setSession("VlessVPN")
                .setMtu(MTU)
                .addAddress(VPN_ADDR, VPN_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(cfg.dns1)
                .addDnsServer(cfg.dns2)
                .addDisallowedApplication(packageName)
                .establish()

            if (tunPfd == null) {
                Log.e(TAG, "✗ Failed to establish TUN (null)")
                broadcast("ERROR")
                handler.stop()
                return
            }
            tun = tunPfd
            Log.i(TAG, "✓ TUN interface established, fd=${tunPfd.fd}")

            // Step 4: 将 TUN fd 传递给 TunHandler
            Log.d(TAG, "Step 4: Starting packet processing...")
            handler.setTunFd(tunPfd.fileDescriptor)

            Log.i(TAG, "========== VPN Connected ==========")
            Log.i(TAG, "Profile : ${cfg.name}")
            Log.i(TAG, "Server  : ${cfg.server}:${cfg.port}")
            Log.i(TAG, "SOCKS5  : 127.0.0.1:$socksPort")
            Log.i(TAG, "Engine  : TunHandler (Kotlin)")
            Log.i(TAG, "Features: TCP ✅ UDP ✅ DNS ✅ ICMP ✅")
            Log.i(TAG, "===================================")
            broadcast("CONNECTED")
            updateNotif("${cfg.name} • Connected")

        } catch (e: SecurityException) {
            Log.e(TAG, "Security exception", e)
            broadcast("ERROR")
            cleanup()
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error", e)
            broadcast("ERROR")
            cleanup()
        }
    }

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
        runCatching { tunHandler?.stop() }
        tunHandler = null

        runCatching { tun?.close() }
        tun = null
    }

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