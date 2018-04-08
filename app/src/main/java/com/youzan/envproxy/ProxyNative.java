package com.youzan.envproxy;

/**
 * * Created by rqg on 03/04/2018.
 */
public class ProxyNative {
    static {
        System.loadLibrary("libProxy");

        initClass();
    }

    private int mVpnFd = -1;

    public ProxyNative() {
        initNative();
    }

    public void setVpnFileDescriptor(int fd) {
        mVpnFd = fd;
    }


    public void startProxy() {
        if (mVpnFd < 0) {
            throw new RuntimeException("not set Vpn fd");
        }


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

    private static native void initClass();

    public static native int getMTU();
}
