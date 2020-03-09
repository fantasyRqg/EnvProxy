package com.rqg.envproxy

import android.app.*
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat

/**
 * * Created by rqg on 03/04/2018.
 */


class ProxyService : VpnService() {
    companion object {
        private const val TAG = "ProxyService"

        const val STATUS_RUNNING = 1
        const val STATUS_STOPPED = 2

        const val PROXY_CMD = "PROXY_CMD"
        const val CMD_START = 1
        const val CMD_STOP = 2

        const val APP_PN_CMD = "APP_PN_CMD"

        const val NOTIFICATION_CHANNEL = "EnvProxy"
    }

    private val proxyNative by lazy { ProxyNative(this) }
    private var appPackageName = ""

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val cmd = intent?.getIntExtra(PROXY_CMD, -1)
        appPackageName = intent?.getStringExtra(APP_PN_CMD) ?: ""

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
        Log.d(TAG, "stopProxy: ")
        proxyNative.stopProxy()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopProxy()
    }

    private fun startProxy() {
        ServiceBus.publish(STATUS_RUNNING)
        startForeground(1, getNotification())
        val fileDp = getVpnBuilder().establish()
        proxyNative.vpnFileDescriptor = fileDp
        Thread {
            setKeyAndCertificate()
            proxyNative.startProxy()
            proxyNative.vpnFileDescriptor?.close()
            stopForeground(true)
            ServiceBus.publish(STATUS_STOPPED)
        }.start()
    }

    private fun setKeyAndCertificate() {
//        val pemDir = getDir(MainActivity.PEM_DIR, Context.MODE_PRIVATE)
//        val keyFile = File(pemDir, MainActivity.PEM_ENV2_KEY)
//        val certFile = File(pemDir, MainActivity.PEM_ENV2_CERT)

//        proxyNative.setKeyAndCertsDir(keyFile.absolutePath, certFile.absolutePath)
    }


    override fun protect(socket: Int): Boolean {
        val protect = super.protect(socket)
        return protect
    }

    override fun onCreate() {
        super.onCreate()

    }

    override fun onDestroy() {
        super.onDestroy()

        stopProxy()
    }


    @RequiresApi(Build.VERSION_CODES.O)
    private fun createNotificationChannel(channelId: String, channelName: String): String {
        val chan = NotificationChannel(
            channelId,
            channelName, NotificationManager.IMPORTANCE_HIGH
        )
        chan.lightColor = Color.BLUE
        chan.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        val service = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        service.createNotificationChannel(chan)
        return channelId
    }

    private fun getNotification(): Notification? {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)

        val channelId =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                createNotificationChannel(NOTIFICATION_CHANNEL, NOTIFICATION_CHANNEL)
            } else {
                // If earlier version channel ID is not used
                // https://developer.android.com/reference/android/support/v4/app/NotificationCompat.Builder.html#NotificationCompat.Builder(android.content.Context)
                NOTIFICATION_CHANNEL
            }

        val notification = NotificationCompat.Builder(this, channelId)
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

        if (!appPackageName.isBlank()) {
            builder.addAllowedApplication(appPackageName)
        }

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