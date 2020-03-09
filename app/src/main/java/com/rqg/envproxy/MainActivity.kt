package com.rqg.envproxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.security.KeyChain
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import io.reactivex.Observable
import kotlinx.android.synthetic.main.activity_main.*
import java.io.FileInputStream
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.TimeUnit


class MainActivity : BaseActivity() {
    companion object {
        private val TAG = "MainActivity"
        private const val REQUEST_CONNECT = 0
        private const val REQUEST_INSTALL_CERT = 1

        val ROOT_CA_FINGERPRINT_SHA1 = "C20B596423AF562AD943300C5D7768E4553DEE32".hexStringToByteArray()
    }

    private var appPackageName = ""
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        vpn_switch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                startProxy()
            } else {
                stopProxy()
            }
        }

        app_info.setOnClickListener {
            val f = AppListFragment()
            f.show(supportFragmentManager, "app_info")
        }

        ViewModelProvider(this).get(VM::class.java)
            .changeApp
            .observe(this, androidx.lifecycle.Observer {
                app_icon.setImageDrawable(it.icon)
                app_name.text = it.name
                appPackageName = it.packageName

                Log.d(TAG, "onCreate: ${vpn_switch.isChecked}")

                if (vpn_switch.isChecked) {
                    stopProxy()
                    Observable.timer(500, TimeUnit.MILLISECONDS)
                        .subscribe { startProxy() }
                }
            })


        ServiceBus.listen()
            .dsubscribe({
                Log.d(TAG, "onCreate: ServiceBus $it")
                runOnUiThread {
                    vpn_switch.setCheckedNoEvent(it == ProxyService.STATUS_RUNNING)
                }
            }, {
                Log.e(TAG, "onCreate: ", it)
            })
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


    override fun onDestroy() {
        super.onDestroy()

    }

    private fun startProxy() {
        Log.d(TAG, "startProxy: ")
        val intent = VpnService.prepare(this)

        if (intent != null) startActivityForResult(intent, REQUEST_CONNECT)
        else runOnUiThread { onActivityResult(REQUEST_CONNECT, Activity.RESULT_OK, null) }
    }


    private fun stopProxy() {
        Log.d(TAG, "stopProxy: ")
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
                    intent.putExtra(ProxyService.APP_PN_CMD, appPackageName)
                    ContextCompat.startForegroundService(this, intent)
                }

            }
            REQUEST_INSTALL_CERT -> {
                Log.d(TAG, "onActivityResult: cert installed")
//                updateRootCertStatus()
            }
            else -> {
                super.onActivityResult(requestCode, resultCode, data)
            }
        }

    }

    private fun getSubjectAltNames(certificate: X509Certificate, type: Int): List<String> {
        val result = ArrayList<String>()
        try {
            Log.d(TAG, "getSubjectAltNames: ${certificate.subjectDN.name}")
            val subjectAltNames = certificate.subjectAlternativeNames ?: return emptyList()
            for (subjectAltName in subjectAltNames) {
                val entry = subjectAltName as List<*>
                if (entry == null || entry.size < 2) {
                    continue
                }
                val altNameType = entry[0] as Int ?: continue
                if (altNameType == type) {
                    val altName = entry[1] as String
                    if (altName != null) {
                        result.add(altName)
                    }
                }
            }
            return result
        } catch (e: CertificateParsingException) {
            Log.e(TAG, "getSubjectAltNames: ", e)
            return emptyList()
        }

    }
}
