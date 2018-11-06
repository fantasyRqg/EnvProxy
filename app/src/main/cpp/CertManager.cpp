//
// Created by Rqg on 2018/10/25.
//

#include <openssl/ssl.h>
#include "CertManager.h"
#include "log.h"

#define LOG_TAG "certManager"


int ssl_verify_peer(int ok, X509_STORE_CTX *ctx) {
    return 1;
}

int ssl_ctx_init(SSL_CTX **ctx, char *keyPath, char *certPath, int is_server) {

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
//    r = SSL_CTX_set_cipher_list(*ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
//    if (r != 1) {
//        ALOGE("Error: cannot set the cipher list.");
//        return -2;
//    }

    if (!is_server) {
        /* the client doesn't have to send it's certificate */
        SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, ssl_verify_peer);
    }


    /* enable srtp */
//    r = SSL_CTX_set_tlsext_use_srtp(*ctx, "SRTP_AES128_CM_SHA1_80");
//    if (r != 0) {
//        ALOGE("Error: cannot setup srtp.");
//        return -3;
//    }

    if (is_server) {

        ALOGV("cert path = %s, key path = %s", certPath, keyPath);

        /* load key and certificate */
        /* certificate file; contains also the public key */
        r = SSL_CTX_use_certificate_file(*ctx, certPath, SSL_FILETYPE_PEM);
        if (r != 1) {
            ALOGE("Error: cannot load certificate file. ");
            return -4;
        }

        /* load private key */
        r = SSL_CTX_use_PrivateKey_file(*ctx, keyPath, SSL_FILETYPE_PEM);
        if (r != 1) {

            ALOGE("Error: cannot load private key file. ");
            return -5;
        }

        /* check if the private key is valid */
        r = SSL_CTX_check_private_key(*ctx);
        if (r != 1) {
            ALOGE("Error: checking the private key failed. ");
            return -6;
        }
    }
    return 0;
}


int ssl_err_callback(const char *str, size_t len, void *u) {
    ALOGD("TlsSession ssl err %s", str);
    return 0;
}


SSLCert *CertManager::getSSLCtx(std::string hostName) {
    return nullptr;
}
