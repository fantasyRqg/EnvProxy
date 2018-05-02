//
// Created by Rqg on 09/04/2018.
//

#include <netinet/tcp.h>

#include "TcpHandler.h"
#include "../ip/IpHandler.h"

TcpHandler::TcpHandler() {}

TcpHandler::~TcpHandler() {

}

TransportPkt *TcpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || pkt->protocol != IPPROTO_TCP)
        return nullptr;

    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->payload);

    struct TransportPkt *tPkt = new TransportPkt();
    tPkt->ipPackage = pkt;
    tPkt->handler = this;
    tPkt->sPort = tcphdr->source;
    tPkt->dPort = tcphdr->dest;
    size_t tcpHdrSize = sizeof(struct tcphdr);
    tPkt->payloadSize = pkt->payloadSize - tcpHdrSize;
    tPkt->payload = pkt->payload + tcpHdrSize;

    return tPkt;
}
