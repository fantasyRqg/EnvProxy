package com.youzan.envproxy

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.support.v4.app.NotificationCompat

/**
 * * Created by rqg on 03/04/2018.
 */


class ProxyService : VpnService() {
    companion object {
        const val NOTIFICATION_CHANNEL = "EnvProxy"
    }

    val proxyNative = ProxyNative()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, getNotification())


        return Service.START_STICKY
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

        val fileDp = getVpnBuilder().establish()

        fileDp.fd
        return notification

    }


    private fun getVpnBuilder(): VpnService.Builder {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)


        val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(ProxyNative.getMTU())
                .setBlocking(false)
                .setConfigureIntent(pi)

        // VPN address
        builder.addAddress("10.1.10.1", 32)
        builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
        //route
        builder.addRoute("0.0.0.0", 0)
        builder.addRoute("2000::", 3) // unicast

        builder.addDnsServer("172.17.1.234")
        builder.addDnsServer("172.17.1.235")


        return builder
    }
}