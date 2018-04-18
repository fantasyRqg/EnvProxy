package com.youzan.envproxy;

import android.os.ParcelFileDescriptor;

/**
 * * Created by rqg on 03/04/2018.
 */
public class ProxyNative {
    static {
        System.loadLibrary("libProxy");

        initClass();
    }

    private ParcelFileDescriptor mVpnFd = null;

    public ProxyNative() {
        initNative();
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

    private native void destroyNative();

    private native void setVpnFd(int fd);

    private native void startProxy_Native();

    private native void stopProxy_Native();

    private native boolean isProxyRunning_Native();

    private static native void initClass();

    public static native int getMTU();
}
