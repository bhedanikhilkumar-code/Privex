package com.privateprotection.mobile.shield;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.privateprotection.mobile.R;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local Privacy-First Web Shield VPN Service.
 *
 * CRITICAL ARCHITECTURAL CONSTRAINTS:
 * 1. Strictly intercepts local DNS queries on 10.0.0.1:53 via TUN.
 * 2. NO TLS MITM, NO Root CA certificate installation, NO HTTPS decryption.
 * 3. NO user traffic, browsing history, or payload uploaded off-device.
 * 4. Only parses DNS QNAME to check against local offline threat intelligence.
 * 5. Returns synthetic NXDOMAIN for verified malicious/phishing domains.
 */
public class WebShieldVpnService extends VpnService implements Runnable {

    private static final String TAG = "WebShieldVpnService";
    private static final String CHANNEL_ID = "web_shield_vpn_channel";
    private static final int NOTIFICATION_ID = 4001;

    public static final String ACTION_START = "com.privateprotection.mobile.shield.START_VPN";
    public static final String ACTION_STOP = "com.privateprotection.mobile.shield.STOP_VPN";

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private Thread vpnThread;
    private ParcelFileDescriptor vpnInterface;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, createForegroundNotification());

        if (!isRunning.get()) {
            isRunning.set(true);
            vpnThread = new Thread(this, "WebShieldVpnThread");
            vpnThread.start();
        }

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private void stopVpn() {
        isRunning.set(false);
        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.w(TAG, "Error closing VPN interface: " + e.getMessage());
            }
            vpnInterface = null;
        }
        stopForeground(true);
        stopSelf();
    }

    private Notification createForegroundNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Web Shield Active Protection",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Protects your device from malicious phishing and scam domains locally.");
            nm.createNotificationChannel(channel);
        }

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Private Protection Web Shield Active")
                .setContentText("Local on-device DNS threat filter active. Zero data leaves your device.")
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    @Override
    public void run() {
        try {
            Builder builder = new Builder();
            builder.setSession("Private Protection Local Web Shield");
            builder.setMtu(1500);

            // Configure TUN interface with local dummy address
            builder.addAddress("10.0.0.2", 32);

            // Route ONLY DNS traffic to the TUN interface (10.0.0.1/32)
            // DO NOT route 0.0.0.0/0 to strictly ensure all standard internet traffic
            // bypasses the VPN completely.
            builder.addDnsServer("10.0.0.1");
            builder.addRoute("10.0.0.1", 32);

            builder.setBlocking(true);

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface. Another VPN might be active.");
                stopVpn();
                return;
            }

            WebShieldService webShieldService = WebShieldService.getInstance(getApplicationContext());
            webShieldService.setVpnActive(true);

            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            byte[] packetBuffer = new byte[32767];

            while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
                int length = in.read(packetBuffer);
                if (length <= 0) {
                    continue;
                }

                // Parse DNS query
                DnsPacketParser.ParsedIpUdpPacket parsed = DnsPacketParser.parseIpUdpDnsPacket(packetBuffer, length);
                if (parsed != null && parsed.dnsQuery != null) {
                    String domain = parsed.dnsQuery.qname;
                    webShieldService.recordDnsQuery(domain);

                    boolean isThreat = webShieldService.isDomainBlocked(domain);
                    if (isThreat) {
                        webShieldService.recordBlockedQuery(domain);

                        // Synthesize NXDOMAIN packet and send back to caller immediately
                        byte[] nxdomain = DnsPacketParser.buildSyntheticNxdomainResponse(
                                parsed, DnsPacketParser.RCODE_NXDOMAIN);
                        if (nxdomain != null) {
                            out.write(nxdomain);
                            out.flush();
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN loop exception: " + e.getMessage());
        } finally {
            WebShieldService webShieldService = WebShieldService.getInstance(getApplicationContext());
            webShieldService.setVpnActive(false);
            stopVpn();
        }
    }
}
