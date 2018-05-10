package com.youzan.envproxy

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.support.v4.content.ContextCompat
import android.support.v4.content.LocalBroadcastManager
import android.util.Log
import io.reactivex.Observable
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.schedulers.Schedulers
import kotlinx.android.synthetic.main.activity_main.*
import okhttp3.OkHttpClient
import okhttp3.Request

class MainActivity : Activity() {
    companion object {
        val TAG = "MainActivity"
        private const val REQUEST_CONNECT = 0
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        tcp_count.text = getString(R.string.tcp_count, 0)
        udp_count.text = getString(R.string.udp_count, 0)
        icmp_count.text = getString(R.string.icmp_count, 0)
        unknown_count.text = getString(R.string.tcp_count, 0)


        vpn_switch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                startProxy()
            } else {
                stopProxy()
            }
        }


        btn.setOnClickListener {
            Observable.just("https://olympic.qima-inc.com/api/apps.get?page=0&app_id=&app_version=&type=&count=10&end_time=2018-05-10")
                    .subscribeOn(Schedulers.io())
                    .map {
                        val client = OkHttpClient()
                        val request = Request.Builder()
                                .url(it)
                                .build()
                        client.newCall(request)
                                .execute()
                                .body()
                    }
                    .observeOn(AndroidSchedulers.mainThread())
                    .subscribe({
                        tv_response.text = it?.charStream()?.readText()
                    }, {
                        tv_response.text = it.toString()
                    })
        }

        LocalBroadcastManager.getInstance(this)
                .registerReceiver(statusReceiver, IntentFilter(ProxyService.STATUS_BROADCAST))

        LocalBroadcastManager.getInstance(this)
                .sendBroadcast(Intent(ProxyService.STATUS_BROADCAST_TRIGGER))
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val status = intent?.getIntExtra(ProxyService.PROXY_STATUS, ProxyService.STATUS_STOPED)
            vpn_switch.setCheckedNoEvent(status == ProxyService.STATUS_RUNNING)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        LocalBroadcastManager.getInstance(this)
                .unregisterReceiver(statusReceiver)
    }

    private fun startProxy() {
        val intent = VpnService.prepare(this)

        if (intent != null) startActivityForResult(intent, REQUEST_CONNECT)
        else runOnUiThread { onActivityResult(REQUEST_CONNECT, Activity.RESULT_OK, null) }
    }


    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java)
        intent.putExtra(ProxyService.PROXY_CMD, ProxyService.CMD_STOP)
        ContextCompat.startForegroundService(this, intent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_CONNECT && resultCode == RESULT_OK) {
            val intent = Intent(this, ProxyService::class.java)
            intent.putExtra(ProxyService.PROXY_CMD, ProxyService.CMD_START)
            ContextCompat.startForegroundService(this, intent)
        }
    }
}
