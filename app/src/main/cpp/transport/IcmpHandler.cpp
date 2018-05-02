//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "IcmpHandler.h"
#include "../ip/IpHandler.h"

IcmpHandler::IcmpHandler() {}

IcmpHandler::~IcmpHandler() {

}

TransportPkt *IcmpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || (pkt->protocol != IPPROTO_ICMP && pkt->protocol != IPPROTO_ICMPV6))
        return nullptr;

    struct icmp *icmp = reinterpret_cast<struct icmp *>(pkt->payload);
    struct TransportPkt *tPkt = new TransportPkt();
    tPkt->handler = this;
    tPkt->ipPackage = pkt;
    tPkt->sPort = ntohs(icmp->icmp_id);
    tPkt->dPort = tPkt->sPort;
    size_t icmpHdrSize = sizeof(struct icmp);
    tPkt->payloadSize = pkt->payloadSize - icmpHdrSize;
    tPkt->payload = pkt->payload + icmpHdrSize;

    return tPkt;
}
