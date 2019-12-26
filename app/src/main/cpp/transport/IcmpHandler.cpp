//
// Created by Rqg on 09/04/2018.
//


#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <unistd.h>

#include "IcmpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../proxyEngine.h"
#include "../log.h"
#include "../util.h"
#include "../BufferPool.h"


#define LOG_TAG "IcmpHandler"

struct IcmpStatus {
    uint16_t id;
    int socket;
    bool stop;
};

IcmpHandler::IcmpHandler() {}

IcmpHandler::~IcmpHandler() {

}

TransportPkt *IcmpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || (pkt->protocol != IPPROTO_ICMP && pkt->protocol != IPPROTO_ICMPV6))
        return nullptr;

    struct icmp *icmp = reinterpret_cast<struct icmp *>(pkt->payload);

    if (icmp->icmp_type != ICMP_ECHO) {
        ADDR_TO_STR(pkt);

        ALOGW("ICMP type %d code %d from %s to %s not supported",
              icmp->icmp_type, icmp->icmp_code, source, dest);
        return 0;
    }

    TransportPkt *tPkt = new TransportPkt();
    tPkt->handler = this;
    tPkt->ipPackage = pkt;
    tPkt->sPort = ntohs(icmp->icmp_id);
    tPkt->dPort = tPkt->sPort;
    size_t icmpHdrSize = sizeof(struct icmp);
    tPkt->payloadSize = pkt->payloadSize - icmpHdrSize;
    tPkt->payload = pkt->payload + icmpHdrSize;

    return tPkt;
}


void IcmpHandler::processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) {
    struct icmp *icmp = reinterpret_cast<struct icmp *>(pkt->ipPackage->payload);
    struct IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);

    // Modify ID
    // http://lwn.net/Articles/443051/
    icmp->icmp_id = ~icmp->icmp_id;
    uint16_t csum = 0;
//    if (pkt->ipPackage->version == 6) {
//        // Untested
//        struct ip6_hdr_pseudo pseudo;
//        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
//        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
//        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
//        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
//        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
//        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
//    }
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ~calc_checksum(csum, (uint8_t *) icmp, pkt->payloadSize);


    ADDR_TO_STR(pkt->ipPackage);
    ALOGI("ICMP forward from tun %s to %s type %d code %d id %x seq %d data %zu",
          source, dest,
          icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq, pkt->payloadSize);

    sessionInfo->lastActive = time(nullptr);

    struct sockaddr_in server4;
    struct sockaddr_in6 server6;
    bool isIp4 = pkt->ipPackage->version == IPVERSION;
    if (isIp4) {
        server4.sin_family = AF_INET;
        server4.sin_addr.s_addr = static_cast<__be32>(pkt->ipPackage->dstAddr.ip4);
        server4.sin_port = 0;
    } else {
        server6.sin6_family = AF_INET6;
        memcpy(&server6.sin6_addr, &pkt->ipPackage->dstAddr.ip6, 16);
        server6.sin6_port = 0;
    }

    // Send raw ICMP message
    if (sendto(status->socket, icmp, pkt->payloadSize, MSG_NOSIGNAL,
               isIp4 ? reinterpret_cast<const struct sockaddr *>(&server4 )
                     : reinterpret_cast<const struct sockaddr *>(&server6),
               (socklen_t) (isIp4 ? sizeof(server4) : sizeof(server6)))
        != pkt->payloadSize) {
        ALOGE("ICMP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            status->stop = true;
            return;
        }
    }
}


ssize_t write_icmp(SessionInfo *sessionInfo, IcmpStatus *status,
                   uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct icmp *icmp = (struct icmp *) data;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
//    if (cur->version == 4) {
    len = sizeof(struct iphdr) + datalen;
    buffer = static_cast<u_int8_t *>(malloc(len));
    struct iphdr *ip4 = (struct iphdr *) buffer;
    if (datalen)
        memcpy(buffer + sizeof(struct iphdr), data, datalen);

    // Build IP4 header
    memset(ip4, 0, sizeof(struct iphdr));
    ip4->version = 4;
    ip4->ihl = sizeof(struct iphdr) >> 2;
    ip4->tot_len = htons(len);
    ip4->ttl = IPDEFTTL;
    ip4->protocol = IPPROTO_ICMP;
    ip4->saddr = sessionInfo->dstAddr.ip4;
    ip4->daddr = sessionInfo->srcAddr.ip4;

    // Calculate IP4 checksum
    ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));
//    } else {
//        len = sizeof(struct ip6_hdr) + datalen;
//        buffer = malloc(len);
//        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
//        if (datalen)
//            memcpy(buffer + sizeof(struct ip6_hdr), data, datalen);
//
//        // Build IP6 header
//        memset(ip6, 0, sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
//        ip6->ip6_ctlun.ip6_un2_vfc = IPV6_VERSION;
//        memcpy(&(ip6->ip6_src), &cur->daddr.ip6, 16);
//        memcpy(&(ip6->ip6_dst), &sessionInfo->srcAddr.ip6, 16);
//    }

    bool isIP4 = sessionInfo->version == IPVERSION;
    inet_ntop(isIP4 ? AF_INET : AF_INET6,
              isIP4 ? (const void *) &sessionInfo->srcAddr.ip4
                    : (const void *) &sessionInfo->srcAddr.ip6,
              source, sizeof(source));
    inet_ntop(isIP4 ? AF_INET : AF_INET6,
              isIP4 ? (const void *) &sessionInfo->dstAddr.ip4
                    : (const void *) &sessionInfo->dstAddr.ip6,
              dest, sizeof(dest));

    // Send raw ICMP message
    ALOGW("ICMP sending to tun %d from %s to %s data %zu type %d code %d id %x seq %d",
          sessionInfo->context->tunFd, dest, source, datalen,
          icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq);

    ssize_t res = write(sessionInfo->context->tunFd, buffer, len);

    sessionInfo->context->reportFn(buffer, len);

    // Write PCAP record
    if (res < 0) {
        ALOGW("ICMP write error %d: %s", errno, strerror(errno));
    }
    free(buffer);

    if (res != len) {
        ALOGE("write %zu/%zu", res, len);
        return -1;
    }

    return res;
}


void IcmpHandler::onSocketEvent(SessionInfo *sessionInfo, epoll_event *ev) {
    IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);

    // Check socket error
    if (ev->events & EPOLLERR) {
        sessionInfo->lastActive = time(NULL);

        int serr = 0;
        socklen_t optlen = sizeof(int);
        int err = getsockopt(status->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
                ALOGE("ICMP getsockopt error %d: %s", errno, strerror(errno));
        else if (serr)
                ALOGE("ICMP SO_ERROR %d: %s", serr, strerror(serr));

        status->stop = true;
    } else {
        // Check socket read
        if (ev->events & EPOLLIN) {
            sessionInfo->lastActive = time(NULL);

            uint16_t blen = (uint16_t) (sessionInfo->version == IPVERSION ? ICMP4_MAXMSG
                                                                          : ICMP6_MAXMSG);
            uint8_t *buffer = static_cast<uint8_t *>(malloc(blen));
            ssize_t bytes = recv(status->socket, buffer, blen, 0);
            if (bytes < 0) {
                // Socket error
                ALOGW("ICMP recv error %d: %s", errno, strerror(errno));

                if (errno != EINTR && errno != EAGAIN)
                    status->stop = 1;
            } else if (bytes == 0) {
                ALOGW("ICMP recv eof");
                status->stop = 1;

            } else {
                // Socket read data
                char dest[INET6_ADDRSTRLEN + 1];
                if (sessionInfo->version == IPVERSION)
                    inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
                else
                    inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));

                // status->id should be equal to icmp->icmp_id
                // but for some unexplained reason this is not the case
                // some bits seems to be set extra
                struct icmp *icmp = (struct icmp *) buffer;

                if (status->id == icmp->icmp_id) {
                    ALOGI("ICMP recv bytes %zu from %s for tun type %d code %d id %x/%x seq %d",
                          bytes, dest,
                          icmp->icmp_type, icmp->icmp_code,
                          status->id, icmp->icmp_id, icmp->icmp_seq);
                } else {
                    ALOGW("ICMP recv bytes %zu from %s for tun type %d code %d id %x/%x seq %d",
                          bytes, dest,
                          icmp->icmp_type, icmp->icmp_code,
                          status->id, icmp->icmp_id, icmp->icmp_seq);
                }

                // restore original ID
                icmp->icmp_id = status->id;
                uint16_t csum = 0;
//                if (status->version == 6) {
//                    // Untested
//                    struct ip6_hdr_pseudo pseudo;
//                    memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
//                    memcpy(&pseudo.ip6ph_src, &status->daddr.ip6, 16);
//                    memcpy(&pseudo.ip6ph_dst, &status->saddr.ip6, 16);
//                    pseudo.ip6ph_len = bytes - sizeof(struct ip6_hdr);
//                    pseudo.ip6ph_nxt = IPPROTO_ICMPV6;
//                    csum = calc_checksum(
//                            0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
//                }
                icmp->icmp_cksum = 0;
                icmp->icmp_cksum = ~calc_checksum(csum, buffer, (size_t) bytes);

                // Forward to tun
                if (write_icmp(sessionInfo, status, buffer, (size_t) bytes) < 0)
                    status->stop = 1;
            }
            free(buffer);
        }
    }
}


void *IcmpHandler::createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) {
    IcmpStatus *s = new IcmpStatus();
    s->id = sessionInfo->sPort;
    s->socket = socket(sessionInfo->protocol == IPVERSION ? PF_INET : PF_INET6, SOCK_DGRAM,
                       IPPROTO_ICMP);
    s->stop = false;

    auto success = sessionInfo->context->engine->protectSocket(s->socket);
    if (!success) {
        s->stop = true;
        goto createFail;
    }


    ALOGD("ICMP socket %d id %x", s->socket, s->id);

    // Monitor events
    memset(&sessionInfo->ev, 0, sizeof(struct epoll_event));
    sessionInfo->ev.events = EPOLLIN | EPOLLERR;
    sessionInfo->ev.data.ptr = s;
    if (epoll_ctl(sessionInfo->context->epollFd, EPOLL_CTL_ADD, s->socket, &sessionInfo->ev))
            ALOGE("epoll add icmp error %d: %s", errno, strerror(errno));


    createFail:
    return s;

}

void IcmpHandler::freeStatusData(SessionInfo *sessionInfo) {
    auto data = sessionInfo->tData;
    ALOGI("free ICMP status data %p", data);
    if (data != nullptr) {
        free(data);
    }
}

bool IcmpHandler::isActive(SessionInfo *sessionInfo) {
    IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);
    return !status->stop;
}

int IcmpHandler::monitorSession(SessionInfo *sessionInfo) {
    return 0;
}

int IcmpHandler::checkSession(SessionInfo *sessionInfo) {
    time_t now = time(NULL);
    IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);

    int timeout = getTimeout(sessionInfo);
    if (status->stop || sessionInfo->lastActive + timeout < now) {
        char source[INET6_ADDRSTRLEN + 1];
        char dest[INET6_ADDRSTRLEN + 1];
        if (sessionInfo->version == IPVERSION) {
            inet_ntop(AF_INET, &sessionInfo->srcAddr.ip4, source, sizeof(source));
            inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
        } else {
            inet_ntop(AF_INET6, &sessionInfo->srcAddr.ip6, source, sizeof(source));
            inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));
        }
        ALOGW("ICMP idle %ld/%d sec stop %d from %s to %s",
              now - sessionInfo->lastActive, timeout, status->stop, dest, source);


        if (status->socket > 0) {
            auto ctx = sessionInfo->context;

            if (epoll_ctl(ctx->epollFd, EPOLL_CTL_DEL, status->socket, &sessionInfo->ev)) {
                ALOGE("ICMP epoll del event error %d: %s", errno, strerror(errno));
                // try again
                return 0;
            }

            if (close(status->socket))
                    ALOGE("ICMP close %d error %d: %s", status->socket, errno, strerror(errno));

            status->socket = -1;
        }

        return 1;
    }

    return 0;
}

int IcmpHandler::getTimeout(SessionInfo *sessionInfo) {
    int timeout = ICMP_TIMEOUT;
    auto ctx = sessionInfo->context;
    int scale = 100 - ctx->sessionCount * 100 / ctx->maxSessions;
    timeout = timeout * scale / 100;

    return timeout;
}

time_t IcmpHandler::checkTimeout(SessionInfo *sessionInfo, time_t timeout, int del, time_t now) {
    IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);

    if (!status->stop && !del) {
        time_t stimeout = sessionInfo->lastActive +
                          getTimeout(sessionInfo) - now + 1;
        if (stimeout > 0 && stimeout < timeout)
            timeout = stimeout;
    }

    return timeout;
}


int IcmpHandler::dataToTun(SessionInfo *sessionInfo, DataBuffer *data) {
    return 0;
}

int IcmpHandler::dataToSocket(SessionInfo *sessionInfo, DataBuffer *data) {
    return 0;
}
