//
// Created by Rqg on 2018/10/25.
//

#include <openssl/ssl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include "CertManager.h"

#include "log.h"
#include "proxyEngine.h"

#define LOG_TAG "certManager"

#define PEM_FILE_SUFFIX ".cert.pem"

int ssl_ctx_init(SSL_CTX **ctx, const char *keyPath, const char *certPath, int is_server);

int commonSslServernameCb(SSL *s, int *ad, void *arg);

EVP_PKEY *loadBasePrivagteKey(const char *const keyFilePath);

CertManager::CertManager(proxyEngine *engine, const char *_certsDirPath, const char *_keyFilePath)
        : engine(engine) {
    certsDirPath = static_cast<char *>(malloc(strlen(_certsDirPath)));
    strcpy(certsDirPath, _certsDirPath);

    keyFilePath = static_cast<char *>(malloc(strlen(_keyFilePath)));
    strcpy(keyFilePath, _keyFilePath);

    baseKey = loadBasePrivagteKey(keyFilePath);

    ssl_ctx_init(&commonClientCtx, NULL, NULL, 0);
    ssl_ctx_init(&commonServerCtx, keyFilePath, NULL, 1);

    SSL_CTX_set_tlsext_servername_callback(commonServerCtx, commonSslServernameCb);
    SSL_CTX_set_tlsext_servername_arg(commonServerCtx, this);

    commonCert = new SSLCert();
    commonCert->serverCtx = commonServerCtx;
    commonCert->clientCtx = commonClientCtx;
}


CertManager::~CertManager() {
    free(certsDirPath);
    free(keyFilePath);
    SSL_CTX_free(commonClientCtx);
    SSL_CTX_free(commonServerCtx);
    delete commonCert;

    for (auto it = certsMap.begin(); it != certsMap.end(); ++it) {
        free(it->first);
        free(it->second->cert);
        free(it->second);
    }
}


int ssl_verify_peer(int ok, X509_STORE_CTX *ctx) {
    return 1;
}


int commonPwdCallback(char *buf, int size, int rwflag, void *userdata) {
    strcpy(buf, "1234567890\0");
    return strlen(buf);
}


int ssl_ctx_init(SSL_CTX **ctx, const char *keyPath, const char *certPath, int is_server) {

    int r = 0;

    /* create a new context using DTLS */
    if (is_server) {
        *ctx = SSL_CTX_new(TLS_server_method());
    } else {
        *ctx = SSL_CTX_new(TLS_client_method());
    }
    if (!*ctx) {
        ALOGE("Error: cannot create SSL_CTX. ");
        return -1;
    }

    /* set our supported ciphers */
    r = SSL_CTX_set_cipher_list(*ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (r != 1) {
        ALOGE("Error: cannot set the cipher list.");
        return -2;
    }

    if (!is_server) {
        /* the client doesn't have to send it's certificate */
        SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, ssl_verify_peer);
    }


    /* enable srtp */
    r = SSL_CTX_set_tlsext_use_srtp(*ctx, "SRTP_AES128_CM_SHA1_80");
    if (r != 0) {
        ALOGE("Error: cannot setup srtp.");
        return -3;
    }

    if (is_server) {

        ALOGV("cert path = %s, key path = %s", certPath, keyPath);

        /* load key and certificate */
        //        do not load cert , SSL load cert after
        /* certificate file; contains also the public key */
//        r = SSL_CTX_use_certificate_file(*ctx, certPath, SSL_FILETYPE_PEM);
//        if (r != 1) {
//            ALOGE("Error: cannot load certificate file. ");
//            return -4;
//        }

//        SSL_CTX_set_default_passwd_cb(*ctx, commonPwdCallback);
//
//        /* load private key */
//        r = SSL_CTX_use_PrivateKey_file(*ctx, keyPath, SSL_FILETYPE_PEM);
//        if (r != 1) {
//            ALOGE("Error: cannot load private key file. error:%d", r);
//            return -5;
//        }

//        /* check if the private key is valid */
//        r = SSL_CTX_check_private_key(*ctx);
//        if (r != 1) {
//            ALOGE("Error: checking the private key failed. ");
//            return -6;
//        }
    }
    return 0;
}

int commonSslServernameCb(SSL *s, int *ad, void *arg) {
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        ALOGE("client hello , not SNI info");
        return SSL_TLSEXT_ERR_NOACK;
    }

    ALOGD("server name: %s", servername);

    CertManager *cm = static_cast<CertManager *>(arg);
    auto cert = cm->getSSLCtx(const_cast<char *>(servername));

    if (cert != NULL) {
        int r = 0;
        r = SSL_use_certificate(s, cert->cert);
        if (r != 1) {
            ALOGE("Error: cannot load certificate file.");
            return SSL_TLSEXT_ERR_NOACK;
        }

        r = SSL_use_PrivateKey(s, cm->getBaseKey());
        if (r != 1) {
            ALOGE("Error: cannot load private key file. error:%d", r);
            return SSL_TLSEXT_ERR_NOACK;
        }

        /* check if the private key is valid */
        r = SSL_check_private_key(s);
        if (r != 1) {
            ALOGE("Error: checking the private key failed. ");
            return SSL_TLSEXT_ERR_NOACK;
        }

        return SSL_TLSEXT_ERR_OK;
    } else {
        ALOGE("get cert failure");
        return SSL_TLSEXT_ERR_NOACK;
    }


}

EVP_PKEY *loadBasePrivagteKey(const char *const keyFilePath) {
    int j, ret = -1;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, keyFilePath) <= 0) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    j = ERR_R_PEM_LIB;
    pkey = PEM_read_bio_PrivateKey(in, NULL, commonPwdCallback, NULL);

    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, j);
        goto end;
    }

    ret = 0;

    end:
    BIO_free(in);

    if (ret == 0) {
        return pkey;
    } else {
        return nullptr;
    }
}

SSLCert *CertManager::getSSLCtx(char *hostName) {
    SSLCert *cert = certsMap[hostName];

    //check memory cache
    if (cert == nullptr) {
        char *path = static_cast<char *>(malloc(
                strlen(certsDirPath) + strlen(hostName) + sizeof(PEM_FILE_SUFFIX)));
        strcpy(path, certsDirPath);
        strcat(path, hostName);
        strcat(path, PEM_FILE_SUFFIX);

        struct stat buffer;
        if (stat(path, &buffer) == 0) {
            cert = loadCertFromFile(path);
        } else {
            if (engine->generateCerts(hostName) != 0) {
                ALOGE("%s ,generate cert error", hostName);
            } else {
                cert = loadCertFromFile(path);

                if (cert != NULL) {
                    char *chm = static_cast< char *>(malloc(strlen(hostName)));
                    strcpy(chm, hostName);
                    certsMap[chm] = cert;
                }
            }
        }

        free(path);
    }

    return cert;
}

SSLCert *CertManager::loadCertFromFile(const char *path) {

    SSLCert *cert = new SSLCert();
    cert->clientCtx = commonClientCtx;
    cert->serverCtx = commonServerCtx;


    int j;
    BIO *in;
    int ret = -1;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, path) <= 0) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    j = ERR_R_PEM_LIB;
    x = PEM_read_bio_X509(in, NULL, commonPwdCallback, NULL);

    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    cert->cert = x;

    ret = 0;

    end:
    BIO_free(in);


    if (ret == 0) {
        return cert;
    } else {
        delete cert;
        return nullptr;
    }
}

const SSLCert *const CertManager::getCommonCert() {
    return commonCert;
}

EVP_PKEY *CertManager::getBaseKey() {
    return baseKey;
}


