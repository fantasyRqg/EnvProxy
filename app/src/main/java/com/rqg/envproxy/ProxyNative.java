package com.rqg.envproxy;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;

/**
 * * Created by rqg on 03/04/2018.
 */
public class ProxyNative {
    static {
        Log.d("Test", "static initializer: " + SSLCmd.class.getName());
        System.loadLibrary("libProxy");

        initClass();
    }

    private ParcelFileDescriptor mVpnFd = null;
    private ProxyService mProxyService;

    public ProxyNative(ProxyService proxyService) {
        initNative();
        mProxyService = proxyService;
    }


    public void setVpnFileDescriptor(ParcelFileDescriptor fd) {
        mVpnFd = fd;
    }

    public ParcelFileDescriptor getVpnFileDescriptor() {
        return mVpnFd;
    }


    public void startProxy() {
        if (mVpnFd == null) {
            throw new RuntimeException("not set Vpn fd");
        }

        setProxyService(mProxyService, SSLCmd.INSTANCE);
        setKeyAndCertsDir(SSLCmd.INSTANCE.getBasePrivateKey().getAbsolutePath(), SSLCmd.INSTANCE.getCertsDir().getAbsolutePath() + File.separator);
        setVpnFd(mVpnFd.getFd());

        startProxy_Native();
    }

    public boolean isProxyRunning() {
        return isProxyRunning_Native();
    }


    public void stopProxy() {
        stopProxy_Native();
    }


    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        destroyNative();
    }

    /**
     * native handler
     */
    private long mNativeHandler = -1;


    public long getNativeHandler() {
        return mNativeHandler;
    }

    private native void initNative();

    private native void setProxyService(ProxyService proxyService, SSLCmd sslCmd);

    private native void destroyNative();

    private native void setVpnFd(int fd);

    private native void startProxy_Native();

    private native void stopProxy_Native();

    public native void setKeyAndCertsDir(String key, String certDir);

    private native boolean isProxyRunning_Native();

    private static native void initClass();

    public static native int getMTU();

    public static native String genRsaAes256l2048();
}
