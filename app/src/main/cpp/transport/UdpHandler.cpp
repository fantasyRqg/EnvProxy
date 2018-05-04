//
// Created by Rqg on 09/04/2018.
//

#include <netinet/udp.h>
#include <linux/in.h>
#include <endian.h>

#include "UdpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"


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

}

void *UdpHandler::createStatusData(SessionInfo *sessionInfo) {
    return nullptr;
}


void UdpHandler::freeStatusData(void *data) {
}
