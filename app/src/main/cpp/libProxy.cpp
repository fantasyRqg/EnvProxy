
#define LOG_TAG "simplejni native.cpp"

#include <stdio.h>
#include "jni.h"
#include "proxyEngine.h"
#include "log.h"

jfieldID nativeHandlerField;

proxyEngine *getProxyEngine(JNIEnv *env, jobject thiz) {
    return reinterpret_cast<proxyEngine *>(env->GetLongField(thiz, nativeHandlerField));
}

static void initClass(JNIEnv *env, jclass clazz) {
    nativeHandlerField = env->GetFieldID(clazz, "mNativeHandler", "J");
}

static jint getMTU(JNIEnv *, jclass) {
//    int result = a + b;
//    ALOGI("%d + %d = %d", a, b, result);
    return 10000;
}

static void initNative(JNIEnv *env, jobject thiz) {
    auto p = new proxyEngine();

    ALOGI("new instance %ld", p);
    env->SetLongField(thiz, nativeHandlerField, reinterpret_cast<jlong>(p));
}


static void destroyNative(JNIEnv *env, jobject thiz) {
    delete getProxyEngine(env, thiz);
    env->SetLongField(thiz, nativeHandlerField, NULL);
}


































//########################################################################################################################

static const char *classPathName = "com/youzan/envproxy/ProxyNative";
static JNINativeMethod methods[] = {
        {"getMTU",        "()I", (void *) getMTU},
        {"initNative",    "()V", (void *) initNative},
        {"initClass",     "()V", (void *) initClass},
        {"destroyNative", "()V", (void *) destroyNative},
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