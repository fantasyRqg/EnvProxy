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
#include <netinet/in6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>


#include "proxyEngine.h"
#include "log.h"

#define LOG_TAG "proxyEngine"

proxyEngine::proxyEngine(size_t mtu) {
    mMTU = mtu;
}

proxyEngine::~proxyEngine() {
}

void proxyEngine::handleEvents() {
    mRunning = true;
    if (mVpnFd < 0) {
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

    //monitor tun event
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = nullptr;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mVpnFd, &ev_tun)) {
        ALOGE("epoll add tun error %d: %s", errno, strerror(errno));
        return;
    }


    while (mRunning) {

        struct epoll_event ev[EPOLL_EVENTS];
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS, 1000);

        if (ready > 0) {
            for (int i = 0; i < ready; ++i) {
                checkTun(&ev[i]);
            }
        }

    }


}

int proxyEngine::checkTun(epoll_event *pEvent) {
    if (pEvent->events & EPOLLERR) {
        ALOGE("tun error %d: %s", errno, strerror(errno));
        return -1;
    }

    if (pEvent->events & EPOLLIN) {
        uint8_t *buffer = static_cast<uint8_t *>(malloc(mMTU));

        auto length = read(mVpnFd, buffer, mMTU);
        if (length < 0) {
            ALOGE("tun %d read error %d: %s", mVpnFd, errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN)
                // Retry later
                return 0;
        } else if (length > 0) {
            uint8_t protocol;
            void *saddr;
            void *daddr;
            char source[INET6_ADDRSTRLEN + 1];
            char dest[INET6_ADDRSTRLEN + 1];

            uint8_t version = (*buffer) >> 4;
            if (version == 4) {
                //ipv4
                if (length < sizeof(struct iphdr)) {
                    ALOGW("IP4 packet too short length %ld", length);
                    return 0;
                }

                struct iphdr *ip4hdr = (struct iphdr *) buffer;
                protocol = ip4hdr->protocol;
                saddr = &ip4hdr->saddr;
                daddr = &ip4hdr->daddr;



            } else if (version == 6) {

            } else {
                ALOGE("Unknown version %d", version);
                return 0;
            }
        } else {
            free(buffer);
            ALOGE("tun %d empty read", mVpnFd);
            return -1;
        }


    }

    return 0;
}


