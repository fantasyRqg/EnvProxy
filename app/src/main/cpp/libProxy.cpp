
#define LOG_TAG "simplejni native.cpp"

#include <stdio.h>
#include <openssl/bio.h>
#include <cstring>
#include "jni.h"
#include "proxyEngine.h"
#include "log.h"
#include "ssl/ssl.h"


#define SOCKT_MTU  10000

jfieldID nativeHandlerField;

proxyEngine *getProxyEngine(JNIEnv *env, jobject thiz) {
    return reinterpret_cast<proxyEngine *>(env->GetLongField(thiz, nativeHandlerField));
}

void initClass(JNIEnv *env, jclass clazz) {
    nativeHandlerField = env->GetFieldID(clazz, "mNativeHandler", "J");
}

jint getMTU(JNIEnv *, jclass) {
    return SOCKT_MTU;
}

void initNative(JNIEnv *env, jobject thiz) {
    auto p = new proxyEngine(SOCKT_MTU);
    env->SetLongField(thiz, nativeHandlerField, reinterpret_cast<jlong>(p));

}

void destroyNative(JNIEnv *env, jobject thiz) {
    delete getProxyEngine(env, thiz);
    env->SetLongField(thiz, nativeHandlerField, static_cast<jlong >(NULL));
}

void setVpnFd(JNIEnv *env, jobject thiz, jint fd) {
    getProxyEngine(env, thiz)->mTunFd = fd;
}

void startProxy(JNIEnv *env, jobject thiz) {
    getProxyEngine(env, thiz)->handleEvents();
}


void stopProxy(JNIEnv *env, jobject thiz) {
    getProxyEngine(env, thiz)->stopHandleEvents();
}

jboolean isProxyRunning(JNIEnv *env, jobject thiz) {
    return (jboolean) (getProxyEngine(env, thiz)->isProxyRunning());
}

void setProxyService(JNIEnv *env, jobject thiz, jobject proxyService) {
    getProxyEngine(env, thiz)->setJniEnv(env, proxyService);
}

void setKeyAndCertificate(JNIEnv *env, jobject thiz, jstring key, jstring certificate) {
    auto *nKey = env->GetStringUTFChars(key, 0);
    auto keyLen = env->GetStringUTFLength(key);
    auto *nCert = env->GetStringUTFChars(certificate, 0);
    auto certLen = env->GetStringUTFLength(certificate);
    getProxyEngine(env, thiz)->setKeyAndCertificate(reinterpret_cast<const char *>(nKey),
                                                    static_cast<size_t>(keyLen),
                                                    reinterpret_cast<const char *>(nCert),
                                                    static_cast<size_t>(certLen));


    env->ReleaseStringUTFChars(key, nKey);
    env->ReleaseStringUTFChars(certificate, nCert);
}


void createRootCa(JNIEnv *env, jobject thiz, jstring name) {

}


jstring genRsaAes256l2048(JNIEnv *env, jclass) {
    auto bio = genrsaAes256l2048();

    req_main(bio, true);

//    if (bio != nullptr) {
//        auto len = BIO_ctrl_pending(bio);
//        char *data = static_cast<char *>(malloc(len + 1));
//        memset(data, 0, len + 1);
//        BIO_read(bio, data, len);
//        BIO_free_all(bio);
//        return env->NewStringUTF(data);
//    }

    return nullptr;
}
























//########################################################################################################################

static const char *classPathName = "com/rqg/envproxy/ProxyNative";
static JNINativeMethod methods[] = {
        {"getMTU",                "()I",                                     (void *) getMTU},
        {"initNative",            "()V",                                     (void *) initNative},
        {"initClass",             "()V",                                     (void *) initClass},
        {"destroyNative",         "()V",                                     (void *) destroyNative},
        {"setVpnFd",              "(I)V",                                    (void *) setVpnFd},
        {"startProxy_Native",     "()V",                                     (void *) startProxy},
        {"stopProxy_Native",      "()V",                                     (void *) stopProxy},
        {"isProxyRunning_Native", "()Z",                                     (void *) isProxyRunning},
        {"setProxyService",       "(Lcom/rqg/envproxy/ProxyService;)V",      (void *) setProxyService},
        {"setKeyAndCertificate",  "(Ljava/lang/String;Ljava/lang/String;)V", (void *) setKeyAndCertificate},
        {"genRsaAes256l2048",     "()Ljava/lang/String;",                    (void *) genRsaAes256l2048},
};

/*
 * Register several native methods for one class.
 */
static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        ALOGE("Native registration unable to find class '%s'", className);
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        ALOGE("RegisterNatives failed for '%s'", className);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/*
 * Register native methods for all classes we know about.
 *
 * returns JNI_TRUE on success.
 */
static int registerNatives(JNIEnv *env) {
    if (!registerNativeMethods(env, classPathName,
                               methods, sizeof(methods) / sizeof(methods[0]))) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
// ----------------------------------------------------------------------------
/*
 * This is called by the VM when the shared library is first loaded.
 */

typedef union {
    JNIEnv *env;
    void *venv;
} UnionJNIEnvToVoid;

jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    UnionJNIEnvToVoid uenv;
    uenv.venv = NULL;
    jint result = -1;
    JNIEnv *env = NULL;

    ALOGI("JNI_OnLoad");
    if (vm->GetEnv(&uenv.venv, JNI_VERSION_1_4) != JNI_OK) {
        ALOGE("ERROR: GetEnv failed");
        goto bail;
    }
    env = uenv.env;
    if (registerNatives(env) != JNI_TRUE) {
        ALOGE("ERROR: registerNatives failed");
        goto bail;
    }

    result = JNI_VERSION_1_4;

    bail:
    return result;
}