//
// Created by Rqg on 03/04/2018.
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <cstring>
#include <sys/resource.h>
#include <sys/epoll.h>
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

#include "proxyEngine.h"
#include "log.h"
#include "ip/IpPackageFactory.h"
#include "ip/IpHandler.h"
#include "transport/TransportFactory.h"

#define LOG_TAG "proxyEngine"

proxyEngine::proxyEngine(size_t mtu) {
    mMTU = mtu;
}

proxyEngine::~proxyEngine() {
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

    //ip package factory
    IpPackageFactory ipPackageFactory(this);
    TransportFactory transportFactory;

    //monitor tun event
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = &ev_tun;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mTunFd, &ev_tun)) {
        ALOGE("epoll add tun error %d: %s", errno, strerror(errno));
        return;
    }


    while (mRunning) {
        //main looping

        struct epoll_event ev[EPOLL_EVENTS];
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS, 1000);

        for (int i = 0; i < ready; ++i) {
            if (ev[i].data.ptr == &ev_tun) {
                //tun event
                auto ipPkt = checkTun(&ev[i], &ipPackageFactory);
                if (ipPkt == nullptr) continue;


                auto tPkt = transportFactory.handleIpPkt(ipPkt);
                if (tPkt == nullptr) {
                    ALOGW("create transport pkt error, protocol = %d ", ipPkt->protocol);
                    ipPkt->handler->freeIpPkt(ipPkt);
                    continue;
                }

                char source[INET6_ADDRSTRLEN + 1];
                char dest[INET6_ADDRSTRLEN + 1];

                if (ipPkt->versoin == IPVERSION) {
                    inet_ntop(AF_INET, &ipPkt->srcAddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &ipPkt->dstAddr.ip4, dest, sizeof(dest));
                } else if (ipPkt->versoin == IPV6_VERSION) {
                    inet_ntop(AF_INET6, &ipPkt->srcAddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &ipPkt->dstAddr.ip6, dest, sizeof(dest));
                }

                ALOGD("sAddr = %15s, dAddr = %15s, protocol = %3u, sPort = %6lu, dPort = %6lu, pkt_size = %6lu ,payload_size = %6lu",
                      source, dest,
                      ipPkt->protocol,
                      tPkt->sPort, tPkt->dPort,
                      ipPkt->pktSize,
                      ipPkt->payloadSize
                );

                tPkt->handler->freePkt(tPkt);

            } else if (ev[i].data.ptr != nullptr) {
                //task event

            }
        }

    }
}


IpPackage *proxyEngine::checkTun(epoll_event *pEvent, IpPackageFactory *ipPackageFactory) {
    if (pEvent->events & EPOLLERR) {
        ALOGE("tun error %d: %s", errno, strerror(errno));
        return nullptr;
    }

    if (pEvent->events & EPOLLIN) {
        uint8_t *buffer = static_cast<uint8_t *>(malloc(mMTU));

        auto length = read(mTunFd, buffer, mMTU);
        if (length < 0) {
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
            free(buffer);
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


