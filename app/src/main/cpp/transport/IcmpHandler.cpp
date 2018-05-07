//
// Created by Rqg on 09/04/2018.
//


#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <errno.h>

#include "IcmpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../proxyEngine.h"
#include "../log.h"


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
    struct icmp *icmp = reinterpret_cast<icmp *>(pkt->ipPackage->payload);
    struct IcmpStatus *status = static_cast<IcmpStatus *>(sessionInfo->tData);

    // Modify ID
    // http://lwn.net/Articles/443051/
    icmp->icmp_id = ~icmp->icmp_id;
    uint16_t csum = 0;
//    if (pkt->ipPackage->versoin == 6) {
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
    ALOGI("ICMP forward from tun %s to %s type %d code %d id %x seq %d data %lu",
          source, dest,
          icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq, pkt->payloadSize);

    sessionInfo->lastActive = time(nullptr);

    struct sockaddr_in server4;
    struct sockaddr_in6 server6;
    bool isIp4 = pkt->ipPackage->versoin == IPVERSION;
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
               static_cast<const sockaddr *>(isIp4 ? &server4 : &server6),
               (socklen_t) (isIp4 ? sizeof(server4) : sizeof(server6)))
        != pkt->payloadSize) {
        ALOGE("ICMP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            status->stop = true;
            return;
        }
    }

}


void *IcmpHandler::createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) {
    IcmpStatus *s = static_cast<IcmpStatus *>(malloc(sizeof(struct IcmpStatus)));
    s->id = sessionInfo->sPort;
    s->socket = socket(sessionInfo->protocol == IPVERSION ? PF_INET : PF_INET6, SOCK_DGRAM,
                       IPPROTO_ICMP);
    s->stop = false;

    auto success = sessionInfo->context->engine->protectSocket(s->socket);

    if (success) {
        return s;
    } else {
        freeStatusData(s);
        return nullptr;
    }
}

void IcmpHandler::freeStatusData(void *data) {
    if (data != nullptr)
        free(data);
}
