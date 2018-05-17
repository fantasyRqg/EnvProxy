//
// Created by Rqg on 24/04/2018.
//

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "TlsSession.h"
#include "../log.h"
#include "../proxyTypes.h"


#define LOG_TAG "TlsSession"

struct TlsCtx {
    SSL_CTX *ctx;                                                                       /* main ssl context */
    SSL *ssl;                                                                           /* the SSL* which represents a "connection" */
    BIO *in_bio;                                                                        /* we use memory read bios */
    BIO *out_bio;                                                                       /* we use memory write bios */
};

typedef void (*info_callback)(const SSL *, int, int);


void get_err_msg(char *msg, size_t size) {
    auto eb = BIO_new_mem_buf(msg, size);
    ERR_print_errors(eb);
    BIO_free(eb);
}

int krx_ssl_verify_peer(int ok, X509_STORE_CTX *ctx) {
    return 1;
}

const char *getSSLErrStr(int e) {
    switch (e) {
        case SSL_ERROR_NONE :
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL :
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ :
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE :
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP :
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL :
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN :
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT :
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT :
            return "SSL_ERROR_WANT_ACCEPT";
        case SSL_ERROR_WANT_ASYNC :
            return "SSL_ERROR_WANT_ASYNC";
        case SSL_ERROR_WANT_ASYNC_JOB :
            return "SSL_ERROR_WANT_ASYNC_JOB";
        case SSL_ERROR_WANT_CLIENT_HELLO_CB :
            return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
        default:
            return "UNKNOWN";
    }
}

/* this sets up the SSL* */

int krx_ssl_init(TlsCtx *k, int isserver, info_callback cb) {
    /* create SSL* */
    k->ssl = SSL_new(k->ctx);
    if (!k->ssl) {
        printf("Error: cannot create new SSL*.\n");
        return -1;
    }

    /* info callback */
    if (cb != nullptr) {
        SSL_set_info_callback(k->ssl, cb);
    }

    /* bios */
    k->in_bio = BIO_new(BIO_s_mem());
    if (k->in_bio == NULL) {
        printf("Error: cannot allocate read bio.\n");
        return -2;
    }
    /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
    BIO_set_mem_eof_return(k->in_bio, -1);

    k->out_bio = BIO_new(BIO_s_mem());
    if (k->out_bio == NULL) {
        printf("Error: cannot allocate write bio.\n");
        return -3;
    }
    /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
    BIO_set_mem_eof_return(k->out_bio, -1);

    SSL_set_bio(k->ssl, k->in_bio, k->out_bio);

    /* either use the server or client part of the protocol */
    if (isserver == 1) {
        SSL_set_accept_state(k->ssl);
    } else {
        SSL_set_connect_state(k->ssl);
    }

    return 0;
}

int krx_ssl_ctx_init(SessionInfo *sessionInfo, TlsCtx *k, int is_server) {

    int r = 0;

    /* create a new context using DTLS */
    if (is_server) {
        k->ctx = SSL_CTX_new(TLS_server_method());
    } else {
        k->ctx = SSL_CTX_new(TLS_client_method());
    }
    if (!k->ctx) {
        char errstr[250];
        get_err_msg(errstr, sizeof(errstr));
        ALOGE("Error: cannot create SSL_CTX. %s", errstr);
        return -1;
    }

    /* set our supported ciphers */
    r = SSL_CTX_set_cipher_list(k->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (r != 1) {
        char errstr[250];
        get_err_msg(errstr, sizeof(errstr));
        ALOGE("Error: cannot set the cipher list. %s", errstr);
        return -2;
    }

    if (is_server) {
        /* the client doesn't have to send it's certificate */
        SSL_CTX_set_verify(k->ctx, SSL_VERIFY_PEER, krx_ssl_verify_peer);
    }


    /* enable srtp */
    r = SSL_CTX_set_tlsext_use_srtp(k->ctx, "SRTP_AES128_CM_SHA1_80");
    if (r != 0) {
        char errstr[250];
        get_err_msg(errstr, sizeof(errstr));
        printf("Error: cannot setup srtp. %s", errstr);
        return -3;
    }

    if (is_server) {

        ALOGV("cert path = %s, key path = %s", sessionInfo->context->certPath,
              sessionInfo->context->keyPath);

        /* load key and certificate */
        /* certificate file; contains also the public key */
        r = SSL_CTX_use_certificate_file(k->ctx, sessionInfo->context->certPath, SSL_FILETYPE_PEM);
        if (r != 1) {
            char err_msg[250];
            get_err_msg(err_msg, sizeof(err_msg));
            ALOGE("Error: cannot load certificate file. %s", err_msg);
            return -4;
        }

        /* load private key */
        r = SSL_CTX_use_PrivateKey_file(k->ctx, sessionInfo->context->keyPath, SSL_FILETYPE_PEM);
        if (r != 1) {
            char err_msg[250];
            get_err_msg(err_msg, sizeof(err_msg));
            ALOGE("Error: cannot load private key file. %s", err_msg);
            return -5;
        }

        /* check if the private key is valid */
        r = SSL_CTX_check_private_key(k->ctx);
        if (r != 1) {
            char err_msg[250];
            get_err_msg(err_msg, sizeof(err_msg));
            ALOGE("Error: checking the private key failed. %s", err_msg);
            return -6;
        }
    }
    return 0;
}


TlsSession::TlsSession(SessionInfo *sessionInfo)
        : Session(sessionInfo), mTunServer(nullptr),
          mClient(nullptr), mPenddingData(nullptr) {
    mTunServer = new TlsCtx();

    if (krx_ssl_ctx_init(sessionInfo, mTunServer, 1) != 0) {
        ALOGE("init server ctx fail");
    }

    if (krx_ssl_init(mTunServer, 1, nullptr) != 0) {
        ALOGE("init server ssl fail");
    }

    mClient = new TlsCtx();

    if (krx_ssl_ctx_init(sessionInfo, mClient, 0) != 0) {
        ALOGE("init server ctx fail");
    }

    if (krx_ssl_init(mClient, 0, nullptr) != 0) {
        ALOGE("init server ssl fail");
    }
}

void free_ctx(TlsCtx *ctx) {
    if (ctx == nullptr)
        return;

    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = nullptr;
    }
    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = nullptr;
    }

    if (ctx->in_bio) {
        BIO_free(ctx->in_bio);
        ctx->in_bio = nullptr;
    }

    if (ctx->out_bio) {
        BIO_free(ctx->out_bio);
        ctx->out_bio = nullptr;
    }

    delete ctx;

}

TlsSession::~TlsSession() {
    free_ctx(mTunServer);
    mTunServer = nullptr;

    free_ctx(mClient);
    mClient = nullptr;
}

int TlsSession::onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    int tun_write_size = BIO_write(mTunServer->in_bio, downData->data, downData->size);

    if (tun_write_size != downData->size) {
        ALOGE("write tun server bio error");
        freeLinkDataBuffer(sessionInfo, downData);
        return -1;
    }


    if (tun_write_size <= 0) {
        ALOGE("write tun server bio error, write size %d, data size %u", tun_write_size,
              downData->size);
        freeLinkDataBuffer(sessionInfo, downData);
        return -1;
    }

    if (!SSL_is_init_finished(mTunServer->ssl)) {
        auto s_s_r = SSL_do_handshake(mTunServer->ssl);

        if (s_s_r <= 0) {
            ALOGE("server handshake error %s",
                  getSSLErrStr(SSL_get_error(mTunServer->ssl, s_s_r)));
            freeLinkDataBuffer(sessionInfo, downData);
            return -1;
        }

        //after do handshake has data to tun
        auto toTunSize = BIO_ctrl_pending(mTunServer->out_bio);
        if (toTunSize > 0) {
            auto to_tun_data = createDataBuffer(sessionInfo, toTunSize);
            if (BIO_read(mTunServer->out_bio, to_tun_data->data, to_tun_data->size) !=
                to_tun_data->size) {
                freeLinkDataBuffer(sessionInfo, downData);
                freeLinkDataBuffer(sessionInfo, to_tun_data);
                ALOGE("read tun server handshake data fail");
                return -1;
            }
            //write handshake data to tun
            prev->onSocketUp(sessionInfo, to_tun_data);
        }
    } else {
        //assume must have next session (httpSession)
        // handle ssl/tls data from tun
        auto d_size = SSL_pending(mTunServer->ssl);
        if (d_size > 0) {
            auto h_data = createDataBuffer(sessionInfo, static_cast<size_t>(d_size));
            if (SSL_read(mTunServer->ssl, h_data->data, h_data->size) != h_data->size) {
                ALOGE("read tun server data fail");
                freeLinkDataBuffer(sessionInfo, downData);
                freeLinkDataBuffer(sessionInfo, h_data);
                return -1;
            }

            next->onTunDown(sessionInfo, h_data);
        }

    }

    freeLinkDataBuffer(sessionInfo, downData);
    return 0;
}


int TlsSession::onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) {

    if (!SSL_is_init_finished(mClient->ssl)) {
        //client handshake not finish
        int rCode = SSL_do_handshake(mClient->ssl);
        if (rCode <= 0) {
            ALOGE("tls client handshake error, %s",
                  getSSLErrStr(SSL_get_error(mClient->ssl, rCode)));
            return 0;
        }
        outClientData(sessionInfo);

        if (upData != nullptr) {
            appendPendingData(upData);
        }

        return 0;
    } else {
        //ssl handshake has finished
        //deal pendding data first,
        appendPendingData(upData);
        return handlePendingData(sessionInfo);
    }
}

int TlsSession::outClientData(SessionInfo *sessionInfo) {
    auto p_size = BIO_ctrl_pending(mClient->out_bio);
    if (p_size > 0) {
        auto to_socket = createDataBuffer(sessionInfo, p_size);
        BIO_read(mClient->out_bio, to_socket->data, to_socket->size);
        if (prev->onTunUp(sessionInfo, to_socket) != 0) {
            ALOGE("tls session onTunUp fail in outClientData");
            return -1;
        } else {
            return static_cast<int>(p_size);
        }
    } else {
        ALOGW("read content nothing");
    }

    return 0;
}

int TlsSession::onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    BIO_write(mClient->in_bio, downData->data, downData->size);

    int result = 0;

    if (!SSL_is_init_finished(mClient->ssl)) {
        int code = SSL_do_handshake(mClient->ssl);
        if (code <= 0) {
            ALOGE("tls session client handshake error, %s",
                  getSSLErrStr(SSL_get_error(mClient->ssl, code)));
            result = -1;
            goto out;
        }

        result = outClientData(sessionInfo);
    } else {
        auto clen = SSL_pending(mClient->ssl);
        if (clen > 0) {
            auto cData = createDataBuffer(sessionInfo, static_cast<size_t>(clen));
            SSL_read(mClient->ssl, cData->data, cData->size);

            result = next->onSocketDown(sessionInfo, cData);
        }
    }

    out:
    freeLinkDataBuffer(sessionInfo, downData);
    return result;
}

int TlsSession::onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    SSL_write(mTunServer->ssl, upData->data, upData->size);

    auto oLen = BIO_ctrl_pending(mTunServer->out_bio);
    auto oData = createDataBuffer(sessionInfo, static_cast<size_t>(oLen));
    BIO_read(mTunServer->out_bio, oData->data, oData->size);

    freeLinkDataBuffer(sessionInfo, upData);
    return prev->onSocketUp(sessionInfo, oData);
}


void TlsSession::releaseResource(SessionInfo *sessionInfo) {
    freeLinkDataBuffer(sessionInfo, mPenddingData);
}

/**
 *  client must be init finished
 * @param sessionInfo
 * @return
 */
int TlsSession::handlePendingData(SessionInfo *sessionInfo) {

    int result = 0;

    while (mPenddingData != nullptr) {
        if (SSL_write(mClient->ssl, mPenddingData->data, mPenddingData->size) !=
            mPenddingData->size) {
            ALOGE("tls session write pending data fail");
            result = -1;
            break;
        }

        if (outClientData(sessionInfo) < 0) {
            break;
        }

        auto tmp = mPenddingData;
        mPenddingData = mPenddingData->next;
        tmp->next = nullptr;
        freeLinkDataBuffer(sessionInfo, tmp);
    }

    return result;
}

void TlsSession::appendPendingData(DataBuffer *db) {
    if (db == nullptr)
        return;

    if (mPenddingData == nullptr) {
        mPenddingData = db;
    } else {
        auto pd = mPenddingData;
        while (pd->next != nullptr) {
            pd->next = db;
        }
    }
}
