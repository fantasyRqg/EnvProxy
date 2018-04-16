package com.youzan.envproxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.support.v4.content.ContextCompat
import kotlinx.android.synthetic.main.activity_main.*
import java.io.File

class MainActivity : Activity() {

    companion object {
        private const val REQUEST_CONNECT = 0
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        tcp_count.text = getString(R.string.tcp_count, 0)
        udp_count.text = getString(R.string.udp_count, 0)
        icmp_count.text = getString(R.string.icmp_count, 0)
        unknown_count.text = getString(R.string.tcp_count, 0)


        vpn_switch.setOnCheckedChangeListener { buttonView, isChecked ->
            if (isChecked) {
                startProxy()
            } else {
                stopProxy()
            }
        }
    }


    private fun startProxy() {
        val intent = VpnService.prepare(this)

        if (intent != null) startActivityForResult(intent, REQUEST_CONNECT)
        else runOnUiThread { onActivityResult(REQUEST_CONNECT, Activity.RESULT_OK, null) }
    }


    private fun stopProxy() {

    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_CONNECT && resultCode == RESULT_OK) {
            val intent = Intent(this, ProxyService::class.java)
            ContextCompat.startForegroundService(this, intent)
        }
    }
}
