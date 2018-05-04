//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "IcmpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../proxyEngine.h"

struct IcmpStatus {
    uint16_t id;
    int socket;

};

IcmpHandler::IcmpHandler() {}

IcmpHandler::~IcmpHandler() {

}

TransportPkt *IcmpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || (pkt->protocol != IPPROTO_ICMP && pkt->protocol != IPPROTO_ICMPV6))
        return nullptr;

    struct icmp *icmp = reinterpret_cast<struct icmp *>(pkt->payload);
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
}


void *IcmpHandler::createStatusData(SessionInfo *sessionInfo) {
    IcmpStatus *s = static_cast<IcmpStatus *>(malloc(sizeof(struct IcmpStatus)));
    s->id = sessionInfo->sPort;
    s->socket = socket(sessionInfo->protocol == IPVERSION ? PF_INET : PF_INET6, SOCK_DGRAM,
                       IPPROTO_ICMP);

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
