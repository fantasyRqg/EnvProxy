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
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException


class MainActivity : Activity() {
    companion object {
        val TAG = "MainActivity"
        private const val REQUEST_CONNECT = 0
        private const val REQUEST_INSTALL_CERT = 1

        const val PEM_CHAIN_CERT = "ca-chain.cert.pem"
        const val PEM_ENV2_KEY = "www.env2.com.key.pem"
        const val PEM_ENV2_CERT = "www.evn2.com.cert.pem"
        const val PEM_DIR = "pems"

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
            //            Observable.just(1)
//                    .observeOn(Schedulers.io())
//                    .subscribe {
//                        ProxyNative.getMTU()
//                    }

            //            Observable.just("https://olympic.qima-inc.com/api/apps.get?page=0&app_id=&app_version=&type=&count=10&end_time=2018-05-10")
            Observable.just("https://raw.githubusercontent.com/barretlee/autocreate-ca/master/cnf/intermediate-ca")
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
                    makeSurePems()
                    it
                }
                .filter {
                    !checkCAInstalled()
                }
                .subscribe {
                    installCa()
                }
    }

    private fun installCa() {
        val intent = KeyChain.createInstallIntent()

        intent.putExtra(KeyChain.EXTRA_NAME, "envProxy")


        val file = File(getDir(PEM_DIR, Context.MODE_PRIVATE), PEM_CHAIN_CERT)
        val fis = FileInputStream(file)
        val bytesArray = ByteArray(file.length().toInt())
        fis.read(bytesArray)
        intent.putExtra(KeyChain.EXTRA_CERTIFICATE, bytesArray)

        startActivityForResult(intent, REQUEST_INSTALL_CERT)
    }


    private fun makeSurePems() {
        val pemDir = getDir(PEM_DIR, Context.MODE_PRIVATE)
        checkPemFile(pemDir, PEM_CHAIN_CERT)
        checkPemFile(pemDir, PEM_ENV2_CERT)
        checkPemFile(pemDir, PEM_ENV2_KEY)
    }

    private fun checkPemFile(pemDir: File, name: String) {
        val chainFile = File(pemDir, name)
        if (!chainFile.exists()) {
            val fos = FileOutputStream(chainFile)
            val fis = assets.open(name)
            val buffer = ByteArray(1024)
            var read: Int
            while (true) {
                read = fis.read(buffer);
                if (read != -1)
                    fos.write(buffer, 0, read)
                else
                    break;
            }

            fos.close()
            fis.close()
        }
    }

    private fun checkCAInstalled(): Boolean {
        try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            if (ks != null) {
                ks.load(null, null)
                val aliases = ks.aliases()
                while (aliases.hasMoreElements()) {
                    val alias = aliases.nextElement() as String
                    val cert = ks.getCertificate(alias) as java.security.cert.X509Certificate
                    if (cert.issuerDN.name.contains("www.env.com")) {
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
        if (requestCode == REQUEST_CONNECT && resultCode == RESULT_OK) {
            when (requestCode) {
                REQUEST_CONNECT -> {
                    val intent = Intent(this, ProxyService::class.java)
                    intent.putExtra(ProxyService.PROXY_CMD, ProxyService.CMD_START)
                    ContextCompat.startForegroundService(this, intent)
                }
                REQUEST_INSTALL_CERT -> {
                    Log.d(TAG, "onActivityResult: cert installed")
                }
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