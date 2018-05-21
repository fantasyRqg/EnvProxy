//
// Created by Rqg on 03/04/2018.
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <cstring>
#include <sys/resource.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>

#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/tls1.h>

#include "proxyEngine.h"
#include "log.h"
#include "ip/IpPackageFactory.h"
#include "ip/IpHandler.h"
#include "transport/TransportFactory.h"
#include "proxyTypes.h"
#include "session/SessionFactory.h"
#include "BufferPool.h"
#include "util.h"

#define LOG_TAG "proxyEngine"


proxyEngine::proxyEngine(size_t mtu)
        : mMTU(mtu),
          mJniEnv(nullptr),
          mProxyService(nullptr),
          mProtectMid(nullptr),
          mTunFd(-1),
          mRunning(false) {
}

proxyEngine::~proxyEngine() {
    if (mJniEnv != nullptr && mProxyService != nullptr) {
        mJniEnv->DeleteGlobalRef(mProxyService);
        mJniEnv = nullptr;
        mProxyService = nullptr;
        mProtectMid = nullptr;
    }
}


//void ssl_begin() {
//    SSL_library_init();
//    SSL_load_error_strings();
//    ERR_load_BIO_strings();
//    OpenSSL_add_all_algorithms();
//}
//
//void ssl_end() {
//    CONF_modules_unload(1);
//    ERR_free_strings();
//    EVP_cleanup();
//    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
//    CRYPTO_cleanup_all_ex_data();
//    OPENSSL_thread_stop();
//}

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

void proxyEngine::handleEvents() {
    mRunning = true;
    if (mTunFd < 0) {
        ALOGE("not set vpn fd");
        return;
    }

    // Get max number of sessions
    int maxsessions = SESSION_MAX;
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim))
        ALOGW("getrlimit error %d: %s", errno, std::strerror(errno));
    else {
        maxsessions = (int) (rlim.rlim_cur * SESSION_LIMIT / 100);
        if (maxsessions > SESSION_MAX)
            maxsessions = SESSION_MAX;
        ALOGW("getrlimit soft %ld hard %ld max sessions %d", rlim.rlim_cur, rlim.rlim_max,
              maxsessions);
    }


    auto epoll_fd = epoll_create(1);
    if (epoll_fd < 0) {
        ALOGE("epoll create error %d: %s", errno, strerror(errno));
        return;
    }


    BufferPool bufferPool;

    ProxyContext context = {
            this,
            mTunFd,
            epoll_fd,
            &bufferPool,
            mMTU,
            maxsessions,
            0,
            nullptr,
            nullptr

    };

    ssl_ctx_init(&context.serverCtx, mKeyPath, mCertPath, 1);
    ssl_ctx_init(&context.clientCtx, mKeyPath, mCertPath, 0);
    ERR_print_errors_cb(ssl_err_callback, nullptr);

    //ip package factory
    IpPackageFactory ipPackageFactory(&context);
    TransportFactory transportFactory;
    SessionFactory sessionFactory(maxsessions);

    //monitor tun event
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = &ev_tun;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mTunFd, &ev_tun)) {
        ALOGE("epoll add tun error %d: %s", errno, strerror(errno));
        return;
    }

    long long last_check = 0;
    while (mRunning) {
        //main looping

        int recheck = 0;
        time_t timeout = EPOLL_TIMEOUT;

        // Count sessions
        int isessions = 0;
        int usessions = 0;
        int tsessions = 0;

        auto s = sessionFactory.getSessions();
        while (s != NULL) {
            if (s->transportHandler->isActive(s)) {
                if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                    isessions++;
                } else if (s->protocol == IPPROTO_UDP) {
                    usessions++;
                } else if (s->protocol == IPPROTO_TCP) {
                    tsessions++;
                    recheck = recheck | s->transportHandler->monitorSession(s);
                }
            }

            s = s->next;
        }
        int sessions = isessions + usessions + tsessions;
        context.sessionCount = sessions;

        // Check sessions
        long long ms = get_ms();
        if (ms - last_check > EPOLL_MIN_CHECK || recheck) {
            last_check = ms;

            time_t now = time(NULL);
            s = sessionFactory.getSessions();
            while (s != NULL) {
                int del = s->transportHandler->checkSession(s);
                timeout = s->transportHandler->checkTimeout(s, timeout, del, now);


                if (del) {
                    auto tmp = s;
                    s = s->next;
                    sessionFactory.freeSession(tmp);
                } else {
                    s = s->next;
                }
            }
        } else {
            ALOGD("Skipped session checks");
        }


        ALOGD("sessions ICMP %d UDP %d TCP %d max %d/%d/%d timeout %ld recheck %d",
              isessions, usessions, tsessions, sessions, maxsessions,
              sessionFactory.getSessionCount(), timeout, recheck);

        struct epoll_event ev[EPOLL_EVENTS];
        int wait_ms = recheck ? EPOLL_MIN_CHECK : static_cast<int>(timeout) * 1000;
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS, wait_ms);

        ALOGV("epoll wait %d ms, ready %d", wait_ms, ready);

        for (int i = 0; i < ready; ++i) {
            if (ev[i].data.ptr == &ev_tun) {
//                 Check upstream
                ALOGD("tun epoll ready %d/%d in %d out %d err %d hup %d",
                      i, ready,
                      (ev[i].events & EPOLLIN) != 0,
                      (ev[i].events & EPOLLOUT) != 0,
                      (ev[i].events & EPOLLERR) != 0,
                      (ev[i].events & EPOLLHUP) != 0);

                //tun event
                auto ipPkt = checkTun(&context, &ev[i], &ipPackageFactory);
                if (ipPkt == nullptr) continue;


                auto tPkt = transportFactory.handleIpPkt(ipPkt);
                if (tPkt == nullptr) {
                    ALOGW("create transport pkt error, protocol = %d ", ipPkt->protocol);
                    delete ipPkt;
                    continue;
                }

//                logPkt(ipPkt, tPkt);

                auto sessionInfo = sessionFactory.findOrCreateSession(tPkt);
                if (sessionInfo != nullptr)
                    sessionInfo->transportHandler->processTransportPkt(sessionInfo, tPkt);

                delete tPkt;
            } else if (ev[i].data.ptr != nullptr) {
                // Check downstream
                SessionInfo *si = static_cast<SessionInfo *>(ev[i].data.ptr);

                ALOGD("session epoll ready %d/%d in %d out %d err %d hup %d prot %d protocol %d",
                      i, ready,
                      (ev[i].events & EPOLLIN) != 0,
                      (ev[i].events & EPOLLOUT) != 0,
                      (ev[i].events & EPOLLERR) != 0,
                      (ev[i].events & EPOLLHUP) != 0,
                      si->ipVersoin,
                      si->protocol
                );
                //process socket data incoming
                si->transportHandler->onSocketEvent(si, &ev[i]);
            }
        }

    }

    // clean up jni env
    if (mJniEnv != nullptr && mProxyService != nullptr) {
        mJniEnv->DeleteGlobalRef(mProxyService);
        mJniEnv = nullptr;
        mProxyService = nullptr;
        mProtectMid = nullptr;
    }

    free(mKeyPath);
    free(mCertPath);
    SSL_CTX_free(context.serverCtx);
    SSL_CTX_free(context.clientCtx);


    ALOGI("proxy stop");
}

void proxyEngine::logPkt(const IpPackage *ipPkt, const TransportPkt *tPkt) const {
    ADDR_TO_STR(ipPkt);

    ALOGD("sAddr = %15s, dAddr = %15s, protocol = %3u, sPort = %6d, dPort = %6d, pkt_size = %6zu ,payload_size = %6zu",
          source, dest,
          ipPkt->protocol,
          tPkt->sPort, tPkt->dPort,
          ipPkt->pktSize,
          ipPkt->payloadSize
    );
}


IpPackage *proxyEngine::checkTun(ProxyContext *context, epoll_event *pEvent,
                                 IpPackageFactory *ipPackageFactory) {
    if (pEvent->events & EPOLLERR) {
        ALOGE("tun error %d: %s", errno, strerror(errno));
        return nullptr;
    }

    if (pEvent->events & EPOLLIN) {
        uint8_t *buffer = context->bufferPool->allocBuffer(context->mtu);

        if (buffer == nullptr) {
            ALOGW("buffer allocate failure, should not happen");
            return nullptr;
        }

        auto length = read(mTunFd, buffer, context->mtu);
        if (length < 0) {
            context->bufferPool->freeBuffer(buffer);
            ALOGE("tun %d read error %d: %s", mTunFd, errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN)
                // Retry later
                return nullptr;
        } else if (length > 0) {
            auto ipPkt = ipPackageFactory->createIpPackage(buffer, static_cast<size_t>(length));
            if (ipPkt == NULL) {
                ALOGW("unhandled package ip_version %d", *buffer >> 4);
            }
            return ipPkt;
        } else {
            context->bufferPool->freeBuffer(buffer);
            ALOGE("tun %d empty read", mTunFd);
            return nullptr;
        }


    }

    return nullptr;
}

void proxyEngine::stopHandleEvents() {
    mRunning = false;
}

bool proxyEngine::isProxyRunning() {
    return mRunning;
}

void proxyEngine::setJniEnv(JNIEnv *env, jobject proxyService) {
    mJniEnv = env;
    mProxyService = mJniEnv->NewGlobalRef(proxyService);


    jclass cls = mJniEnv->GetObjectClass(mProxyService);
    if (cls == NULL) {
        ALOGE("protect socket failed to get class");
        mJniEnv = nullptr;
        mProxyService = nullptr;
        return;
    }

//    mProtectMid = jniGetMethodID(ctx->env, cls, "protect", "(I)Z");
    mProtectMid = mJniEnv->GetMethodID(cls, "protect", "(I)Z");
    if (mProtectMid == NULL) {
        ALOGE("protect socket failed to get method");
        mJniEnv = nullptr;
        mProxyService = nullptr;
        return;
    }
}

bool proxyEngine::protectSocket(int socket) {
    if (mJniEnv == nullptr)
        return false;

    jboolean isProtected = mJniEnv->CallBooleanMethod(mProxyService, mProtectMid, socket);

    if (!isProtected) {
        ALOGE("protect socket failed");
        return false;
    }
    return true;
}

void proxyEngine::setKeyAndCertificate(const char *key, size_t keyLen, const char *cert,
                                       size_t certLen) {

    mKeyPath = static_cast<char *>(malloc(keyLen + 1));
    memset(mKeyPath, 0, keyLen + 1);
    memcpy(mKeyPath, key, keyLen);

    mCertPath = static_cast<char *>(malloc(certLen + 1));
    memset(mCertPath, 0, certLen + 1);
    memcpy(mCertPath, cert, certLen);

}
