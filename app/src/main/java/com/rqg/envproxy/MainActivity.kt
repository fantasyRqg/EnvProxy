package com.rqg.envproxy

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.security.KeyChain
import android.support.v4.content.ContextCompat
import android.support.v4.content.LocalBroadcastManager
import android.util.Log
import io.reactivex.Observable
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.schedulers.Schedulers
import kotlinx.android.synthetic.main.activity_main.*
import okhttp3.*
import okhttp3.EventListener
import java.io.FileInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*


class MainActivity : Activity() {
    companion object {
        val TAG = "MainActivity"
        private const val REQUEST_CONNECT = 0
        private const val REQUEST_INSTALL_CERT = 1

        val ROOT_CA_FINGERPRINT_SHA1 = "C20B596423AF562AD943300C5D7768E4553DEE32".hexStringToByteArray()
    }

    private var sslCmdReady = false
    private var sslRootCertReady = false

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
//            Observable.just("https://raw.githubusercontent.com/barretlee/autocreate-ca/master/cnf/intermediate-ca")
//            Observable.just("https://www.baidu.com")
                    .subscribeOn(Schedulers.io())
                    .map {
                        val client = OkHttpClient.Builder()
                                .retryOnConnectionFailure(false)
//                                .eventListener(LogEventListener)
                                .build()

                        val request = Request.Builder()
                                .url(it)
                                .build()
                        client.newCall(request)
                                .execute()
                                .body()
                                ?.charStream()
                                ?.readText()
                    }
                    .observeOn(AndroidSchedulers.mainThread())
                    .subscribe({
                        tv_response.text = it
                    }, {
                        tv_response.text = it.toString()
                        Log.e(TAG, "onCreate: ", it)
                    })
        }


        LocalBroadcastManager.getInstance(this)
                .registerReceiver(statusReceiver, IntentFilter(ProxyService.STATUS_BROADCAST))

        LocalBroadcastManager.getInstance(this)
                .sendBroadcast(Intent(ProxyService.STATUS_BROADCAST_TRIGGER))


        val subscribe = Observable.just(true)
                .observeOn(Schedulers.io())
                .map {
                    sslCmdReady = SSLCmd.prepareOpenSSLExecutable()
                    it
                }
                .map {
                    if (!checkCAInstalled()) {
                        installCa()
                    }

                    it
                }
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe {
                    updateRootCertStatus()
                }
    }


    private fun updateRootCertStatus() {
        sslRootCertReady = checkCAInstalled()

        if (sslRootCertReady) {
            cert_status.text = "root cert ready"
            cert_status.setBackgroundResource(R.drawable.bg_green_stroke)
        } else {
            cert_status.text = "root cert not install"
            cert_status.setBackgroundResource(R.drawable.bg_red_stroke)
        }
    }

    private fun installCa() {
        val intent = KeyChain.createInstallIntent()

        intent.putExtra(KeyChain.EXTRA_NAME, "envProxy")


        val file = SSLCmd.rootCert
        val fis = FileInputStream(file)
        val bytesArray = ByteArray(file.length().toInt())
        fis.read(bytesArray)
        intent.putExtra(KeyChain.EXTRA_CERTIFICATE, bytesArray)
        startActivityForResult(intent, REQUEST_INSTALL_CERT)
    }

    private fun checkCAInstalled(): Boolean {
        try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            val sha1Md = MessageDigest.getInstance("SHA1")
            if (ks != null) {
                ks.load(null, null)
                val aliases = ks.aliases()
                while (aliases.hasMoreElements()) {
                    val alias = aliases.nextElement() as String
                    val cert = ks.getCertificate(alias) as java.security.cert.X509Certificate
                    if (Arrays.equals(sha1Md.digest(cert.encoded), ROOT_CA_FINGERPRINT_SHA1)) {
                        return true
                    }
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: java.security.cert.CertificateException) {
            e.printStackTrace()
        }


        return false
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
        Log.d(TAG, "onActivityResult() called with: requestCode = [ ${requestCode} ], resultCode = [ ${resultCode} ], data = [ ${data} ]")
        when (requestCode) {
            REQUEST_CONNECT -> {
                if (resultCode == RESULT_OK) {
                    val intent = Intent(this, ProxyService::class.java)
                    intent.putExtra(ProxyService.PROXY_CMD, ProxyService.CMD_START)
                    ContextCompat.startForegroundService(this, intent)
                }

            }
            REQUEST_INSTALL_CERT -> {
                Log.d(TAG, "onActivityResult: cert installed")
                updateRootCertStatus()
            }
        }

    }
}


object LogEventListener : EventListener() {
    private const val TAG = "LogEventListener"

    override fun connectFailed(call: Call?, inetSocketAddress: InetSocketAddress?, proxy: Proxy?, protocol: Protocol?, ioe: IOException?) {
        Log.d(TAG, "connectFailed() called with: call = [ ${call} ], inetSocketAddress = [ ${inetSocketAddress} ], proxy = [ ${proxy} ], protocol = [ ${protocol} ], ioe = [ ${ioe} ]")
    }

    override fun responseHeadersStart(call: Call?) {
        Log.d(TAG, "responseHeadersStart() called with: call = [ ${call} ]")
    }

    override fun connectionAcquired(call: Call?, connection: Connection?) {
        Log.d(TAG, "connectionAcquired() called with: call = [ ${call} ], connection = [ ${connection} ]")
    }

    override fun connectionReleased(call: Call?, connection: Connection?) {
        Log.d(TAG, "connectionReleased() called with: call = [ ${call} ], connection = [ ${connection} ]")
    }

    override fun callEnd(call: Call?) {
        Log.d(TAG, "callEnd() called with: call = [ ${call} ]")
    }

    override fun requestHeadersStart(call: Call?) {
        Log.d(TAG, "requestHeadersStart() called with: call = [ ${call} ]")
    }

    override fun requestBodyEnd(call: Call?, byteCount: Long) {
        Log.d(TAG, "requestBodyEnd() called with: call = [ ${call} ], byteCount = [ ${byteCount} ]")
    }

    override fun requestBodyStart(call: Call?) {
        Log.d(TAG, "requestBodyStart() called with: call = [ ${call} ]")
    }

    override fun callFailed(call: Call?, ioe: IOException?) {
        Log.d(TAG, "callFailed() called with: call = [ ${call} ], ioe = [ ${ioe} ]")
    }

    override fun connectEnd(call: Call?, inetSocketAddress: InetSocketAddress?, proxy: Proxy?, protocol: Protocol?) {
        Log.d(TAG, "connectEnd() called with: call = [ ${call} ], inetSocketAddress = [ ${inetSocketAddress} ], proxy = [ ${proxy} ], protocol = [ ${protocol} ]")
    }

    override fun responseBodyStart(call: Call?) {
        Log.d(TAG, "responseBodyStart() called with: call = [ ${call} ]")
    }

    override fun secureConnectStart(call: Call?) {
        Log.d(TAG, "secureConnectStart() called with: call = [ ${call} ]")
    }

    override fun dnsEnd(call: Call?, domainName: String?, inetAddressList: MutableList<InetAddress>?) {
        Log.d(TAG, "dnsEnd() called with: call = [ ${call} ], domainName = [ ${domainName} ], inetAddressList = [ ${inetAddressList} ]")
    }

    override fun connectStart(call: Call?, inetSocketAddress: InetSocketAddress?, proxy: Proxy?) {
        Log.d(TAG, "connectStart() called with: call = [ ${call} ], inetSocketAddress = [ ${inetSocketAddress} ], proxy = [ ${proxy} ]")
    }

    override fun requestHeadersEnd(call: Call?, request: Request?) {
        Log.d(TAG, "requestHeadersEnd() called with: call = [ ${call} ], request = [ ${request} ]")
    }

    override fun responseHeadersEnd(call: Call?, response: Response?) {
        Log.d(TAG, "responseHeadersEnd() called with: call = [ ${call} ], response = [ ${response} ]")
    }

    override fun callStart(call: Call?) {
        Log.d(TAG, "callStart() called with: call = [ ${call} ]")
    }

    override fun responseBodyEnd(call: Call?, byteCount: Long) {
        Log.d(TAG, "responseBodyEnd() called with: call = [ ${call} ], byteCount = [ ${byteCount} ]")
    }

    override fun dnsStart(call: Call?, domainName: String?) {
        Log.d(TAG, "dnsStart() called with: call = [ ${call} ], domainName = [ ${domainName} ]")
    }

    override fun secureConnectEnd(call: Call?, handshake: Handshake?) {
        Log.d(TAG, "secureConnectEnd() called with: call = [ ${call} ], handshake = [ ${handshake} ]")
    }
}