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
#include "ip/ip4.h"
#include "ip/IpPackage.h"

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


    //init IpPackage handlers
#define IP_HDL_SIZE  1
    IpPackage **ip_hdl_s = static_cast<IpPackage **>(malloc(sizeof(IpPackage *)));
    ip_hdl_s[0] = new ip4(epoll_fd, mTunFd);


    //monitor tun event
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = nullptr;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mTunFd, &ev_tun)) {
        ALOGE("epoll add tun error %d: %s", errno, strerror(errno));
        return;
    }


    while (mRunning) {

        struct epoll_event ev[EPOLL_EVENTS];
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS, 1000);

        if (ready > 0) {
            for (int i = 0; i < ready; ++i) {
                checkTun(&ev[i], ip_hdl_s, IP_HDL_SIZE);
            }
        }

    }

    //release resource
    for (int i = 0; i < IP_HDL_SIZE; ++i) {
        delete ip_hdl_s[i];
    }
    free(ip_hdl_s);


}

int proxyEngine::checkTun(epoll_event *pEvent, IpPackage **ip_hdl_s, size_t hdl_size) {
    if (pEvent->events & EPOLLERR) {
        ALOGE("tun error %d: %s", errno, strerror(errno));
        return -1;
    }

    if (pEvent->events & EPOLLIN) {
        uint8_t *buffer = static_cast<uint8_t *>(malloc(mMTU));

        auto length = read(mTunFd, buffer, mMTU);
        if (length < 0) {
            ALOGE("tun %d read error %d: %s", mTunFd, errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN)
                // Retry later
                return 0;
        } else if (length > 0) {
            for (int i = 0; i < hdl_size; ++i) {
                if (ip_hdl_s[i]->handlePackage(buffer, (size_t) length) == IP_HANDLE_SUCCESS) {
                    return 0;
                }
            }
            ALOGW("unhandled package IpPackage version %d", *buffer >> 4);
            return -1;
        } else {
            free(buffer);
            ALOGE("tun %d empty read", mTunFd);
            return -1;
        }


    }

    return 0;
}

void proxyEngine::stopHandleEvents() {
    mRunning = false;
}

bool proxyEngine::isProxyRunning() {
    return mRunning;
}


