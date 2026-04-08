package com.musicses.vlessvpn;

import android.content.Context;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * libtun2socks.so 的 Java 封装。
 *
 * 放置路径：app/src/main/jniLibs/<abi>/libtun2socks.so
 * 支持的 ABI：arm64-v8a / armeabi-v7a / x86 / x86_64
 */
public class Tun2Socks {

    private static final String TAG = "Tun2Socks";
    private static volatile boolean isInitialized = false;

    // ── 初始化 ────────────────────────────────────────────────────────────────

    /**
     * 加载 libtun2socks.so 原生库。
     * 在调用任何其他方法前必须先调用此方法（通常在 VpnService.onCreate 或 Application.onCreate）。
     */
    public static void initialize(Context context) {
        if (isInitialized) {
            Log.w(TAG, "Already initialized");
            return;
        }
        System.loadLibrary("tun2socks");
        isInitialized = true;
        Log.i(TAG, "✓ libtun2socks.so loaded");
    }

    // ── 主要入口（无 extraArgs）─────────────────────────────────────────────

    /**
     * 启动 tun2socks 引擎（在独立线程中阻塞运行，直到调用 stopTun2Socks）。
     *
     * @param logLevel                   日志级别
     * @param vpnInterfaceFileDescriptor VPN 接口文件描述符（Builder.establish() 返回值）
     * @param vpnInterfaceMtu            MTU，与 Builder.setMtu() 保持一致
     * @param socksServerAddress         本地 SOCKS5 代理地址（通常 "127.0.0.1"）
     * @param socksServerPort            本地 SOCKS5 代理端口
     * @param netIPv4Address             tun2socks 虚拟对端 IP（如 "10.233.233.2"）
     * @param netIPv6Address             IPv6 对端地址，不需要时传 null
     * @param netmask                    子网掩码（如 "255.255.255.252"）
     * @param forwardUdp                 是否将 UDP 也转发到 SOCKS5（需要 SOCKS5 支持 UDP Associate）
     * @return true = 正常退出，false = 异常退出
     */
    public static boolean startTun2Socks(
            LogLevel logLevel,
            ParcelFileDescriptor vpnInterfaceFileDescriptor,
            int vpnInterfaceMtu,
            String socksServerAddress,
            int socksServerPort,
            String netIPv4Address,
            @Nullable String netIPv6Address,
            String netmask,
            boolean forwardUdp) {
        return startTun2Socks(
                logLevel,
                vpnInterfaceFileDescriptor,
                vpnInterfaceMtu,
                socksServerAddress,
                socksServerPort,
                netIPv4Address,
                netIPv6Address,
                netmask,
                forwardUdp,
                Collections.<String>emptyList()
        );
    }

    // ── 完整入口（含 extraArgs）──────────────────────────────────────────────

    /**
     * 与上面相同，但支持追加自定义参数（高级用法）。
     */
    public static boolean startTun2Socks(
            LogLevel logLevel,
            ParcelFileDescriptor vpnInterfaceFileDescriptor,
            int vpnInterfaceMtu,
            String socksServerAddress,
            int socksServerPort,
            String netIPv4Address,
            @Nullable String netIPv6Address,
            String netmask,
            boolean forwardUdp,
            List<String> extraArgs) {

        ArrayList<String> arguments = new ArrayList<>();

        arguments.add("badvpn-tun2socks");

        // 日志输出到 stdout（这样 logcat 可以看到）
        arguments.addAll(Arrays.asList("--logger", "stdout"));
        arguments.addAll(Arrays.asList("--loglevel", String.valueOf(logLevel.ordinal())));

        // TUN 文件描述符
        arguments.addAll(Arrays.asList(
                "--tunfd", String.valueOf(vpnInterfaceFileDescriptor.getFd())));
        arguments.addAll(Arrays.asList("--tunmtu", String.valueOf(vpnInterfaceMtu)));

        // 虚拟网段
        arguments.addAll(Arrays.asList("--netif-ipaddr", netIPv4Address));
        if (!TextUtils.isEmpty(netIPv6Address)) {
            arguments.addAll(Arrays.asList("--netif-ip6addr", netIPv6Address));
        }
        arguments.addAll(Arrays.asList("--netif-netmask", netmask));

        // SOCKS5 代理地址
        arguments.addAll(Arrays.asList(
                "--socks-server-addr",
                String.format(Locale.US, "%s:%d", socksServerAddress, socksServerPort)));

        // UDP 支持
        if (forwardUdp) {
            arguments.add("--socks5-udp");
        }

        // 额外参数
        arguments.addAll(extraArgs);

        Log.d(TAG, "Starting tun2socks with args: " + arguments);

        int exitCode = start_tun2socks(arguments.toArray(new String[0]));

        Log.i(TAG, "tun2socks exited with code: " + exitCode);
        return exitCode == 0;
    }

    // ── 原生方法 ──────────────────────────────────────────────────────────────

    /** 启动 tun2socks（阻塞直到 stopTun2Socks 被调用） */
    private static native int start_tun2socks(String[] args);

    /** 停止 tun2socks（线程安全，可从任意线程调用） */
    public static native void stopTun2Socks();

    /** 在 logcat 打印帮助信息（调试用） */
    public static native void printTun2SocksHelp();

    /** 在 logcat 打印版本信息（调试用） */
    public static native void printTun2SocksVersion();

    // ── 枚举 ──────────────────────────────────────────────────────────────────

    public enum LogLevel {
        NONE,    // 0
        ERROR,   // 1
        WARNING, // 2
        NOTICE,  // 3
        INFO,    // 4
        DEBUG    // 5
    }
}