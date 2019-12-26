package com.rqg.envproxy

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.support.v4.app.NotificationCompat
import android.support.v4.content.LocalBroadcastManager

/**
 * * Created by rqg on 03/04/2018.
 */


class ProxyService : VpnService() {
    companion object {
        const val STATUS_BROADCAST = "STATUS_BROADCAST"
        const val STATUS_BROADCAST_TRIGGER = "STATUS_BROADCAST_TRIGGER"

        const val PROXY_STATUS = "PROXY_STATUS"
        const val STATUS_RUNNING = 1
        const val STATUS_STOPED = 2

        const val PROXY_CMD = "PROXY_CMD"
        const val CMD_START = 1
        const val CMD_STOP = 2

        const val NOTIFICATION_CHANNEL = "EnvProxy"
    }

    private val proxyNative by lazy { ProxyNative(this) }


    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val cmd = intent?.getIntExtra(PROXY_CMD, -1)

        when (cmd) {
            CMD_START -> {
                startProxy()
            }

            CMD_STOP -> {
                stopProxy()
                stopSelf()
            }
        }

        return Service.START_STICKY
    }

    private fun stopProxy() {
        proxyNative.stopProxy()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopProxy()
    }

    private fun startProxy() {
        startForeground(1, getNotification())
        val fileDp = getVpnBuilder().establish()
        proxyNative.vpnFileDescriptor = fileDp
        Thread {

            setKeyAndCertificate()
            proxyNative.startProxy()
            proxyNative.vpnFileDescriptor?.close()
        }.start()
    }

    private fun setKeyAndCertificate() {
//        val pemDir = getDir(MainActivity.PEM_DIR, Context.MODE_PRIVATE)
//        val keyFile = File(pemDir, MainActivity.PEM_ENV2_KEY)
//        val certFile = File(pemDir, MainActivity.PEM_ENV2_CERT)

//        proxyNative.setKeyAndCertsDir(keyFile.absolutePath, certFile.absolutePath)
    }

    private val triggerReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val bi = Intent(STATUS_BROADCAST)
            bi.putExtra(PROXY_STATUS, if (proxyNative.isProxyRunning) STATUS_RUNNING else STATUS_STOPED)
            LocalBroadcastManager.getInstance(this@ProxyService)
                    .sendBroadcast(bi)
        }
    }

    override fun protect(socket: Int): Boolean {
        val protect = super.protect(socket)
        return protect
    }

    override fun onCreate() {
        super.onCreate()
        LocalBroadcastManager.getInstance(this)
                .registerReceiver(triggerReceiver, IntentFilter(STATUS_BROADCAST_TRIGGER))
    }

    override fun onDestroy() {
        super.onDestroy()
        LocalBroadcastManager.getInstance(this@ProxyService)
                .unregisterReceiver(triggerReceiver)

        stopProxy()
    }


    private fun getNotification(): Notification? {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)

        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(pi)
                .setOngoing(true)
                .setAutoCancel(false)
                .setContentTitle("Env Proxy")
                .setContentText("desc")
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .build()

        return notification

    }


    private fun getVpnBuilder(): VpnService.Builder {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)


        val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(ProxyNative.getMTU())
                .setBlocking(false)
//                .addAllowedApplication(BuildConfig.APPLICATION_ID)
                .setConfigureIntent(pi)

        // VPN address
        builder.addAddress("10.1.10.1", 32)
        builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
        //route
        builder.addRoute("0.0.0.0", 0)
        builder.addRoute("2000::", 3) // unicast

        builder.addDnsServer("8.8.8.8")
        builder.addDnsServer("114.114.114.114")

//        builder.addDnsServer("172.17.1.235")
        return builder
    }
}