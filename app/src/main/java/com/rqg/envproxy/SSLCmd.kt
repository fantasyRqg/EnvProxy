package com.rqg.envproxy

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * * Created by rqg on 2018/11/14.
 */

class SSLCmd(val context: Context) {
    companion object {
        private const val TAG = "SSLCmd"
    }

    private val workingDir by lazy {
        val appDir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            context.dataDir
        } else {
            context.filesDir
        }

        File(appDir.absolutePath + "/openssl")
    }


    val rootCert by lazy {
        File(workingDir.absolutePath + "/ca.cert.pem")
    }

    private val opensslExecutable by lazy {
        File(workingDir.absolutePath + "/openssl")
    }

    private val sslCnf by lazy {
        File(workingDir.absolutePath + "/openssl.cnf")
    }

    fun prepareOpenSSLExecutable(): Boolean {
        if (!workingDir.exists() && !workingDir.mkdirs()) {
            Log.e(TAG, "prepareOpenSSLExecutable: prepare working dir failure")
            return false
        }

        if (!rootCert.exists() && !copyFileFromAssetToWorkingDir("ca.cert.pem")) {
            Log.e(TAG, "prepareOpenSSLExecutable: copy root cert file failure")
            return false
        }

        if (!opensslExecutable.exists()
                && !copyFileFromAssetToWorkingDir("openssl")
                && (opensslExecutable.canExecute() || opensslExecutable.setExecutable(true, true))) {
            Log.e(TAG, "prepareOpenSSLExecutable: prepare openssl executable file failure")
            return false
        }

        if (!sslCnf.exists() && !copyFileFromAssetToWorkingDir("openssl.cnf")) {
            Log.e(TAG, "prepareOpenSSLExecutable: preapre openssl cnf file failure")
            return false
        }


        return true
    }


    private fun copyFileFromAssetToWorkingDir(assetFileName: String): Boolean {
        val inputStream = context.assets.open(assetFileName)
        val outputStream = FileOutputStream(workingDir.absolutePath + "/" + assetFileName)

        try {
            val buffer = ByteArray(1024)
            var read: Int
            while (true) {
                read = inputStream.read(buffer)

                if (read == -1)
                    break

                outputStream.write(buffer, 0, read)
            }

            return true

        } catch (e: Exception) {
            Log.e(TAG, "copyFileFromAssetToWorkingDir: $assetFileName ", e)
        } finally {
            inputStream.close()
            outputStream.close()
        }

        return false
    }
}