//
// Created by Rqg on 09/04/2018.
//

#include <netinet/udp.h>
#include <linux/in.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>

#include "UdpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../log.h"
#include "../proxyEngine.h"
#include "../util.h"

#define LOG_TAG "UdpHandler"


struct UdpStatus {
    int socket;
    uint16_t mss;

    uint64_t sent;
    uint64_t received;
    __be16 dest; // network notation

    uint8_t state;
};

UdpHandler::UdpHandler() {}

UdpHandler::~UdpHandler() {

}

TransportPkt *UdpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || pkt->protocol != IPPROTO_UDP)
        return nullptr;

    struct udphdr *udphdr = reinterpret_cast<struct udphdr *>(pkt->payload);
    TransportPkt *tPkt = new TransportPkt();
    tPkt->handler = this;
    tPkt->ipPackage = pkt;
    tPkt->sPort = ntohs(udphdr->source);
    tPkt->dPort = ntohs(udphdr->dest);
    size_t udphdrSize = sizeof(struct udphdr);
    tPkt->payloadSize = pkt->payloadSize - udphdrSize;
    tPkt->payload = pkt->payload + udphdrSize;

    return tPkt;
}

void UdpHandler::processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) {

    // Get headers
//    const uint8_t version = static_cast<const uint8_t>(sessionInfo->ipVersoin);
//    const struct udphdr *udphdr = (struct udphdr *) pkt->ipPackage->payload;
//    const uint8_t *data = pkt->payload;
//    const size_t datalen = pkt->payloadSize;

    UdpStatus *status = static_cast<UdpStatus *>(sessionInfo->tData);

    ADDR_TO_STR(pkt->ipPackage);

    if (status == nullptr) {
        ALOGE("status not init , UDP ignore session from %s/%u to %s/%u state %d",
              source, pkt->sPort, dest, pkt->dPort, status->state);
        return;
    }


    if (status->state != UDP_ACTIVE) {
        ALOGW("UDP ignore session from %s/%u to %s/%u state %d",
              source, pkt->sPort, dest, pkt->dPort, status->state);
        return;
    }


//    // Check for DNS
//    if (ntohs(udphdr->dest) == 53) {
//        char qname[DNS_QNAME_MAX + 1];
//        uint16_t qtype;
//        uint16_t qclass;
//        if (get_dns_query(args, &cur->udp, data, datalen, &qtype, &qclass, qname) >= 0) {
//            log_android(ANDROID_LOG_DEBUG,
//                        "DNS query qtype %d qclass %d name %s",
//                        qtype, qclass, qname);
//
//            if (0)
//                if (check_domain(args, &cur->udp, data, datalen, qclass, qtype, qname)) {
//                    // Log qname
//                    char name[DNS_QNAME_MAX + 40 + 1];
//                    sprintf(name, "qtype %d qname %s", qtype, qname);
//                    jobject objPacket = create_packet(
//                            args, version, IPPROTO_UDP, "",
//                            source, ntohs(cur->udp.source), dest, ntohs(cur->udp.dest),
//                            name, 0, 0);
//                    log_packet(args, objPacket);
//
//                    // Session done
//                    cur->udp.state = UDP_FINISHING;
//                    return 0;
//                }
//        }
//    }
//
//    // Check for DHCP (tethering)
//    if (ntohs(udphdr->source) == 68 || ntohs(udphdr->dest) == 67) {
//        if (check_dhcp(args, &cur->udp, data, datalen) >= 0)
//            return 1;
//    }

    ALOGI("UDP forward from tun %s/%u to %s/%u data %lu",
          source, pkt->sPort, dest, pkt->dPort, pkt->payloadSize);

    sessionInfo->lastActive = time(NULL);

    int rversion;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
//    if (redirect == NULL) {
    rversion = sessionInfo->ipVersoin;
    if (rversion == IPVERSION) {
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = (__be32) sessionInfo->dstAddr.ip4;
        addr4.sin_port = htons(sessionInfo->dPort);
    } else {
        addr6.sin6_family = AF_INET6;
        memcpy(&addr6.sin6_addr, &sessionInfo->dstAddr.ip6, 16);
        addr6.sin6_port = htons(sessionInfo->dPort);
    }
//    } else {
//        rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
//        log_android(ANDROID_LOG_WARN, "UDP%d redirect to %s/%u",
//                    rversion, redirect->raddr, redirect->rport);
//
//        if (rversion == 4) {
//            addr4.sin_family = AF_INET;
//            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
//            addr4.sin_port = htons(redirect->rport);
//        } else {
//            addr6.sin6_family = AF_INET6;
//            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
//            addr6.sin6_port = htons(redirect->rport);
//        }
//    }

    if (sendto(status->socket, pkt->payload, (socklen_t) pkt->payloadSize, MSG_NOSIGNAL,
               (rversion == IPVERSION ? (const struct sockaddr *) &addr4
                                      : (const struct sockaddr *) &addr6),
               (socklen_t) (rversion == IPVERSION ? sizeof(addr4) : sizeof(addr6))) !=
        pkt->payloadSize) {
        ALOGE("UDP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            status->state = UDP_FINISHING;
            return;
        }
    } else
        status->sent += pkt->payloadSize;

    return;

}


int open_udp_socket(SessionInfo *sessionInfo, UdpStatus *status) {
    int sock;
//    if (redirect == NULL)
//        version = cur->version;
//    else
//        version = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);

    // Get UDP socket
    sock = socket(sessionInfo->ipVersoin == IPVERSION ? PF_INET : PF_INET6, SOCK_DGRAM,
                  IPPROTO_UDP);
    if (sock < 0) {
        ALOGE("UDP socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect socket
    if (!sessionInfo->context->engine->protectSocket(sock)) {
        close(sock);
        ALOGE("protect socket fail");
        return -1;
    }


    // Check for broadcast/multicast
    if (sessionInfo->ipVersoin == IPVERSION) {
        uint32_t broadcast4 = INADDR_BROADCAST;
        if (memcmp(&sessionInfo->dstAddr.ip4, &broadcast4, sizeof(broadcast4)) == 0) {
            ALOGW("UDP4 broadcast");
            int on = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) {
                // just logout error ,and ignore it
                ALOGE("UDP setsockopt SO_BROADCAST error %d: %s", errno, strerror(errno));
            }

        }
    } else {
        // http://man7.org/linux/man-pages/man7/ipv6.7.html
        if (*((uint8_t *) &sessionInfo->dstAddr.ip6) == 0xFF) {
            ALOGW("UDP6 broadcast");

            int loop = 1; // true
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)))
                ALOGE("UDP setsockopt IPV6_MULTICAST_LOOP error %d: %s", errno, strerror(errno));

            int ttl = -1; // route default
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)))
                ALOGE("UDP setsockopt IPV6_MULTICAST_HOPS error %d: %s", errno, strerror(errno));

            struct ipv6_mreq mreq6;
            memcpy(&mreq6.ipv6mr_multiaddr, &sessionInfo->dstAddr.ip6, sizeof(struct in6_addr));
            mreq6.ipv6mr_interface = INADDR_ANY;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)))
                ALOGE("UDP setsockopt IPV6_ADD_MEMBERSHIP error %d: %s", errno, strerror(errno));
        }
    }

    return sock;
}

ssize_t write_udp(const SessionInfo *sessionInfo, const UdpStatus *status,
                  uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct udphdr *udp;
    uint16_t csum;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
//    if (cur->version == 4) {
    len = sizeof(struct iphdr) + sizeof(struct udphdr) + datalen;
    buffer = static_cast<u_int8_t *>(malloc(len));
    struct iphdr *ip4 = (struct iphdr *) buffer;
    udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    if (datalen)
        memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), data, datalen);

    // Build IP4 header
    memset(ip4, 0, sizeof(struct iphdr));
    ip4->version = 4;
    ip4->ihl = sizeof(struct iphdr) >> 2;
    ip4->tot_len = htons(len);
    ip4->ttl = IPDEFTTL;
    ip4->protocol = IPPROTO_UDP;
    ip4->saddr = sessionInfo->dstAddr.ip4;
    ip4->daddr = sessionInfo->srcAddr.ip4;

    // Calculate IP4 checksum
    ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

    // Calculate UDP4 checksum
    struct ippseudo pseudo;
    memset(&pseudo, 0, sizeof(struct ippseudo));
    pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
    pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
    pseudo.ippseudo_p = ip4->protocol;
    pseudo.ippseudo_len = htons(sizeof(struct udphdr) + datalen);

    csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
//    } else {
//        len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + datalen;
//        buffer = malloc(len);
//        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
//        udp = (struct udphdr *) (buffer + sizeof(struct ip6_hdr));
//        if (datalen)
//            memcpy(buffer + sizeof(struct ip6_hdr) + sizeof(struct udphdr), data, datalen);
//
//        // Build IP6 header
//        memset(ip6, 0, sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
//        ip6->ip6_ctlun.ip6_un2_vfc = IPV6_VERSION;
//        memcpy(&(ip6->ip6_src), &sessionInfo->dstAddr.ip6, 16);
//        memcpy(&(ip6->ip6_dst), &sessionInfo->srcAddr.ip6, 16);
//
//        // Calculate UDP6 checksum
//        struct ip6_hdr_pseudo pseudo;
//        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
//        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
//        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
//        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
//        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
//
//        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
//    }

    // Build UDP header
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = htons(sessionInfo->dPort);
    udp->dest = htons(sessionInfo->sPort);
    udp->len = htons(sizeof(struct udphdr) + datalen);

    // Continue checksum
    csum = calc_checksum(csum, (uint8_t *) udp, sizeof(struct udphdr));
    csum = calc_checksum(csum, data, datalen);
    udp->check = ~csum;

    bool isIp4 = sessionInfo->ipVersoin == IPVERSION;
    inet_ntop(isIp4 ? AF_INET : AF_INET6,
              (isIp4 ? (const void *) &sessionInfo->srcAddr.ip4
                     : (const void *) &sessionInfo->srcAddr.ip6),
              source,
              sizeof(source));
    inet_ntop(isIp4 ? AF_INET : AF_INET6,
              (isIp4 ? (const void *) &sessionInfo->dstAddr.ip4
                     : (const void *) &sessionInfo->dstAddr.ip6),
              dest,
              sizeof(dest));

    // Send packet
    ALOGD("UDP sending to tun %d from %s/%u to %s/%u data %lu",
          sessionInfo->context->tunFd, dest, sessionInfo->dPort, source, sessionInfo->sPort, len);

    ssize_t res = write(sessionInfo->context->tunFd, buffer, len);

    // Write PCAP record
    if (res < 0) {
        ALOGW("UDP write error %d: %s", errno, strerror(errno));
    }

    free(buffer);

    if (res != len) {
        ALOGE("write %ld/%lu", res, len);
        return -1;
    }

    return res;
}


void UdpHandler::onSocketDataIncoming(SessionInfo *sessionInfo, epoll_event *ev) {
    UdpStatus *status = static_cast<UdpStatus *>(sessionInfo->tData);

    // Check socket error
    if (ev->events & EPOLLERR) {
        sessionInfo->lastActive = time(NULL);

        int serr = 0;
        socklen_t optlen = sizeof(int);
        int err = getsockopt(status->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
            ALOGE("UDP getsockopt error %d: %s", errno, strerror(errno));
        else if (serr)
            ALOGE("UDP SO_ERROR %d: %s", serr, strerror(serr));

        status->state = UDP_FINISHING;
    } else {
        // Check socket read
        if (ev->events & EPOLLIN) {
            sessionInfo->lastActive = time(NULL);

            uint8_t *buffer = static_cast<uint8_t *>(malloc(status->mss));
            ssize_t bytes = recv(status->socket, buffer, status->mss, 0);
            if (bytes < 0) {
                // Socket error
                ALOGE("UDP recv error %d: %s", errno, strerror(errno));

                if (errno != EINTR && errno != EAGAIN)
                    status->state = UDP_FINISHING;
            } else if (bytes == 0) {
                ALOGW("UDP recv eof");
                status->state = UDP_FINISHING;

            } else {
                // Socket read data
                char dest[INET6_ADDRSTRLEN + 1];
                if (sessionInfo->ipVersoin == IPVERSION)
                    inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
                else
                    inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));
                ALOGI("UDP recv bytes %ld from %s/%u for tun", bytes, dest, ntohs(status->dest));

                status->received += bytes;

//                // Process DNS response
//                if (ntohs(status->dest) == 53)
//                    parse_dns_response(args, &s->udp, buffer, (size_t *) &bytes);

                // Forward to tun
                if (write_udp(sessionInfo, status, buffer, (size_t) bytes) < 0)
                    status->state = UDP_FINISHING;
                else {
                    // Prevent too many open files
                    if (ntohs(status->dest) == 53)
                        status->state = UDP_FINISHING;
                }
            }
            free(buffer);
        }
    }
}

void *UdpHandler::createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) {
    struct udphdr *udphdr = reinterpret_cast<struct udphdr *>(firstPkt->payload);


    ADDR_TO_STR(firstPkt->ipPackage);
    ALOGI("UDP new session from %s/%u to %s/%u",
          source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));


    // Register session
    UdpStatus *status = static_cast<UdpStatus *>(malloc(sizeof(UdpStatus)));

    sessionInfo->lastActive = time(NULL);

    int rversion = sessionInfo->ipVersoin;
//    if (redirect == NULL)
//        rversion = status->version;
//    else
//        rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
    status->mss = (uint16_t) (rversion == IPVERSION ? UDP4_MAXMSG : UDP6_MAXMSG);

    status->sent = 0;
    status->received = 0;

    status->state = UDP_ACTIVE;

    // Open UDP socket
    status->socket = open_udp_socket(sessionInfo, status);
    if (status->socket < 0) {
        status->state = UDP_FINISHING;
    }

    ALOGD("UDP socket %d", status->socket);

    // Monitor events
    memset(&sessionInfo->ev, 0, sizeof(struct epoll_event));
    sessionInfo->ev.events = EPOLLIN | EPOLLERR;
    sessionInfo->ev.data.ptr = sessionInfo;
    if (epoll_ctl(sessionInfo->context->epollFd, EPOLL_CTL_ADD, status->socket, &sessionInfo->ev))
        ALOGE("epoll add udp error %d: %s", errno, strerror(errno));

    return status;
}


void UdpHandler::freeStatusData(void *data) {
    if (data != nullptr)
        free(data);
}

bool UdpHandler::isActive(SessionInfo *sessionInfo) {
    UdpStatus *status = static_cast<UdpStatus *>(sessionInfo->tData);
    return status->state == UDP_ACTIVE;
}

bool UdpHandler::monitorSession(SessionInfo *sessionInfo) {
    return true;
}
