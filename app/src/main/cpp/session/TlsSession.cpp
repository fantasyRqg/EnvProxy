//
// Created by Rqg on 24/04/2018.
//

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "TlsSession.h"

//#define ENABLE_LOG

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

int ssl_init(TlsCtx *k, int isserver, info_callback cb) {
    /* create SSL* */
    k->ssl = SSL_new(k->ctx);
    if (!k->ssl) {
        ALOGE("Error: cannot create new SSL*.");
        return -1;
    }

    /* info callback */
    if (cb != nullptr) {
        SSL_set_info_callback(k->ssl, cb);
    }

    /* bios */
    k->in_bio = BIO_new(BIO_s_mem());
    if (k->in_bio == NULL) {
        ALOGE("Error: cannot allocate read bio.");
        return -2;
    }
    /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
    BIO_set_mem_eof_return(k->in_bio, -1);

    k->out_bio = BIO_new(BIO_s_mem());
    if (k->out_bio == NULL) {
        ALOGE("Error: cannot allocate write bio.");
        return -3;
    }

    /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
    BIO_set_mem_eof_return(k->out_bio, -1);

    SSL_set0_wbio(k->ssl, k->out_bio);
    SSL_set0_rbio(k->ssl, k->in_bio);

    /* either use the server or client part of the protocol */
    if (isserver) {
        SSL_set_accept_state(k->ssl);
    } else {
        SSL_set_connect_state(k->ssl);
    }

    return 0;
}


const char *getSSLCbMsg(int where) {
    switch (where) {
        case SSL_CB_LOOP:
            return "SSL_CB_LOOP";
        case SSL_CB_EXIT:
            return "SSL_CB_EXIT";
        case SSL_CB_READ:
            return "SSL_CB_READ";
        case SSL_CB_WRITE:
            return "SSL_CB_WRITE";
        case SSL_CB_ALERT:
            return "SSL_CB_ALERT";
        case SSL_CB_READ_ALERT:
            return "SSL_CB_READ_ALERT";
        case SSL_CB_WRITE_ALERT:
            return "SSL_CB_WRITE_ALERT";
        case SSL_CB_ACCEPT_LOOP:
            return "SSL_CB_ACCEPT_LOOP";
        case SSL_CB_ACCEPT_EXIT:
            return "SSL_CB_ACCEPT_EXIT";
        case SSL_CB_CONNECT_LOOP:
            return "SSL_CB_CONNECT_LOOP";
        case SSL_CB_CONNECT_EXIT:
            return "SSL_CB_CONNECT_EXIT";
        case SSL_CB_HANDSHAKE_START:
            return "SSL_CB_HANDSHAKE_START";
        case SSL_CB_HANDSHAKE_DONE:
            return "SSL_CB_HANDSHAKE_DONE";

        default:
            return "SSL_CB_UNKNOWN";
    }

}

void ssl_info_callback(const SSL *ssl, int where, int ret, const char *name) {

    if (ret == 0) {
        ALOGE("-- ssl_info_callback: error occured.");
        return;
    }

    ALOGV("+ %s %20.20s  - %30.30s  - %5.10s", name, getSSLCbMsg(where),
          SSL_state_string_long(ssl), SSL_state_string(ssl));
}

void ssl_server_info_callback(const SSL *ssl, int where, int ret) {
    ssl_info_callback(ssl, where, ret, "server");
}

void ssl_client_info_callback(const SSL *ssl, int where, int ret) {
    ssl_info_callback(ssl, where, ret, "client");
}


TlsSession::TlsSession(SessionInfo *sessionInfo)
        : Session(sessionInfo), mTunServer(nullptr),
          mClient(nullptr), mPenddingData(nullptr) {
    mTunServer = new TlsCtx();

    mTunServer->ctx = sessionInfo->context->serverCtx;

    if (ssl_init(mTunServer, 1, ssl_server_info_callback) != 0) {
        ALOGE("init server ssl fail");
    }

    mClient = new TlsCtx();
    mClient->ctx = sessionInfo->context->clientCtx;
    if (ssl_init(mClient, 0, ssl_client_info_callback) != 0) {
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

    int o_size = BIO_ctrl_pending(mTunServer->out_bio);

    if (o_size > 0) {
        auto to_tun_data = createDataBuffer(sessionInfo, static_cast<size_t>(o_size));
        BIO_read(mTunServer->out_bio, to_tun_data->data, to_tun_data->size);

        //write data to tun
        prev->onSocketUp(sessionInfo, to_tun_data);
    }

    if (!SSL_is_init_finished(mTunServer->ssl)) {
        auto s_s_r = SSL_do_handshake(mTunServer->ssl);

        if (s_s_r <= 0) {
            auto e = SSL_get_error(mTunServer->ssl, s_s_r);
            if (e != SSL_ERROR_WANT_READ) {
                ALOGE("server handshake error %s", getSSLErrStr(e));
                freeLinkDataBuffer(sessionInfo, downData);
                return -1;
            }
        }

        //after do handshake has data to tun
        auto toTunSize = BIO_ctrl_pending(mTunServer->out_bio);
        if (toTunSize > 0) {
            auto to_tun_data = createDataBuffer(sessionInfo, toTunSize);
            BIO_read(mTunServer->out_bio, to_tun_data->data, to_tun_data->size);
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
