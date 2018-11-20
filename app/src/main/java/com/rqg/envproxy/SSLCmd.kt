package com.rqg.envproxy

import android.os.Build
import android.util.Log
import java.io.*


/**
 * * Created by rqg on 2018/11/14.
 */

object SSLCmd {

    private const val TAG = "SSLCmd"

    private val workingDir by lazy {
        val appDir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            App.get().dataDir
        } else {
            App.get().filesDir
        }

        File(appDir.absolutePath + "/openssl")
    }


    val rootCert by lazy {
        File(workingDir.absolutePath + "/ca.cert.pem")
    }

    val rootKey by lazy {
        File(workingDir.absolutePath + "/ca.key.pem")
    }

    private val opensslExecutable by lazy {
        File(workingDir.absolutePath + "/openssl")
    }

    private val sslCnf by lazy {
        File(workingDir.absolutePath + "/openssl.cnf")
    }

    private val priDir by lazy {
        File(workingDir.absolutePath + "/private")
    }

    val certsDir by lazy {
        File(workingDir.absolutePath + "/certs")
    }

    private val csrDir by lazy {
        File(workingDir.absolutePath + "/csr")
    }


    val basePrivateKey by lazy {
        File(workingDir.absolutePath + "/base_private_key.key.pem")
    }

    fun prepareOpenSSLExecutable(): Boolean {
        Log.d(TAG, "prepareOpenSSLExecutable: " + workingDir.absoluteFile)

        if (!workingDir.exists() && !workingDir.mkdirs()) {
            Log.e(TAG, "prepareOpenSSLExecutable: prepare working dir failure")
            return false
        }

        if (!rootCert.exists() && !copyFileFromAssetToWorkingDir("ca.cert.pem")) {
            Log.e(TAG, "prepareOpenSSLExecutable: copy root cert file failure")
            return false
        }

        if (!rootKey.exists() && !copyFileFromAssetToWorkingDir("ca.key.pem")) {
            Log.e(TAG, "prepareOpenSSLExecutable: copy root key file failure")
            return false
        }

        if (!opensslExecutable.exists() && !copyFileFromAssetToWorkingDir("openssl")) {
            Log.e(TAG, "prepareOpenSSLExecutable: prepare openssl executable file failure")
            return false
        }

        if (!opensslExecutable.canExecute() && !opensslExecutable.setExecutable(true)) {
            Log.e(TAG, "prepareOpenSSLExecutable: cannot set openssl excutable")
            return false
        }


        if (!sslCnf.exists() && !copyFileFromAssetToWorkingDir("openssl.cnf")) {
            Log.e(TAG, "prepareOpenSSLExecutable: preapre openssl cnf file failure")
            return false
        }


        if (!priDir.exists() && !priDir.mkdir()) {
            Log.e(TAG, "prepareOpenSSLExecutable: create private dir failure")
            return false
        }

        if (!certsDir.exists() && !certsDir.mkdir()) {
            Log.e(TAG, "prepareOpenSSLExecutable: create certs dir failure")
            return false
        }

        if (!csrDir.exists() && !csrDir.mkdir()) {
            Log.e(TAG, "prepareOpenSSLExecutable: create csr dir failure")
            return false
        }

        val indexFile = File(workingDir.absolutePath + "/index.txt")
        if (!indexFile.exists() && !indexFile.createNewFile()) {
            Log.e(TAG, "prepareOpenSSLExecutable: create index file failure")
            return false
        }

        val serialFile = File(workingDir.absolutePath + "/serial")
        if (!serialFile.exists() && !createSerialFile(serialFile)) {
            Log.e(TAG, "prepareOpenSSLExecutable: create serial file failure")
            return false
        }


        val newcertsDir = File(workingDir.absolutePath + "/newcerts")
        if (!newcertsDir.exists() && !newcertsDir.mkdir()) {
            Log.e(TAG, "prepareOpenSSLExecutable: create newcerts file failure")
            return false
        }


        if (!basePrivateKey.exists() && runCmd("${opensslExecutable.absolutePath} genrsa -aes256 -passout pass:1234567890 -out ${basePrivateKey.absolutePath} 2048") != 0) {
            Log.e(TAG, "prepareOpenSSLExecutable: generate base private key failure")
            return false
        }


        return true
    }


    private fun createSerialFile(serialFile: File): Boolean {
        if (!serialFile.createNewFile()) {
            return false
        }

        val outputStream = FileOutputStream(serialFile)
        try {
            val writer = outputStream.bufferedWriter()
            writer.write("1000")
            writer.newLine()
            writer.flush()
            outputStream.close()
        } catch (e: Exception) {
            Log.e(TAG, "createSerialFile: ", e)
            return false
        } finally {
            outputStream.close();
        }

        return true
    }

    private fun copyFileFromAssetToWorkingDir(assetFileName: String): Boolean {
        val inputStream = App.get().assets.open(assetFileName)
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


    private fun readStream(outputStream: InputStream): String {
        val bufferedReader = BufferedReader(InputStreamReader(outputStream))

        // Grab the results
        val outBuffer = StringBuilder()
        var line: String?
        while (true) {
            line = bufferedReader.readLine()
            if (line == null)
                break

            outBuffer.append(line + "\n")
        }

        return outBuffer.toString()
    }

    fun runCmd(cmd: String): Int {
        try {
            val cmdProc = Runtime.getRuntime().exec(cmd, null, workingDir)
            cmdProc.waitFor()

            val normalMsg = readStream(cmdProc.inputStream)

            val errMsg = readStream(cmdProc.errorStream)

            Log.d(TAG, "runCmd: $cmd \n")
            if (normalMsg.isNotEmpty()) {
                Log.d(TAG, "runCmd: $normalMsg")
            }

            if (errMsg.isNotEmpty()) {
                Log.e(TAG, "runCmd: $errMsg")
            }

            return cmdProc.exitValue()
        } catch (e: Exception) {
            Log.e(TAG, "runCmd: ", e)
            return -1
        }

    }


    fun generateSignedCert(url: String): Int {
        var r = 0

        r = runCmd("${opensslExecutable.absolutePath} req -batch -passin pass:1234567890 -config ${sslCnf.absolutePath} -key ${basePrivateKey.absolutePath} -new -sha256 -out ${csrDir.absolutePath}/${url}.csr.pem -subj /C=CN/ST=HangZhou/L=West_Lake/O=YZ/OU=Retail/CN=${url}")
        if (r != 0) {
            Log.e(TAG, "test: req failure")
            return r
        }
        r = runCmd("${opensslExecutable.absolutePath} ca -batch -passin pass:1234567890 -config ${sslCnf.absolutePath} -extensions server_cert -days 3000 -notext -md sha256 -in ${csrDir.absolutePath}/${url}.csr.pem -out ${certsDir.absolutePath}/${url}.cert.pem")
        if (r != 0) {
            Log.e(TAG, "test: ca failure")
            return r
        }


        return r
    }

//    fun test() {
//        Log.d(TAG, "test:  start test")
//        var r = 0
//        r = runCmd("${opensslExecutable.absolutePath} genrsa -aes256 -passout pass:1234567890 -out ${priDir.absolutePath}/www.example.com.key.pem 2048")
//        if (r != 0) {
//            Log.e(TAG, "test: genrsa failure")
//            return
//        }
//        r = runCmd("${opensslExecutable.absolutePath} req -batch -passin pass:1234567890 -config ${sslCnf.absolutePath} -key ${priDir.absolutePath}/www.example.com.key.pem -new -sha256 -out ${csrDir.absolutePath}/www.example.com.csr.pem -subj /C=CN/ST=HangZhou/L=West_Lake/O=YZ/OU=Retail/CN=www.ex.com")
//        if (r != 0) {
//            Log.e(TAG, "test: req failure")
//            return
//        }
//        r = runCmd("${opensslExecutable.absolutePath} ca -batch -passin pass:1234567890 -config ${sslCnf.absolutePath} -extensions server_cert -days 3000 -notext -md sha256 -in ${csrDir.absolutePath}/www.example.com.csr.pem -out ${certsDir.absolutePath}/www.example.com.cert.pem")
//        if (r != 0) {
//            Log.e(TAG, "test: ca failure")
//            return
//        }
//    }
}