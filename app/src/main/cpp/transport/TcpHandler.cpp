//
// Created by Rqg on 09/04/2018.
//

#include <netinet/tcp.h>
#include <linux/in.h>
#include <endian.h>

#include "TcpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"


TcpHandler::TcpHandler() {}

TcpHandler::~TcpHandler() {

}

TransportPkt *TcpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || pkt->protocol != IPPROTO_TCP)
        return nullptr;

    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->payload);

    TransportPkt *tPkt = new TransportPkt();
    tPkt->ipPackage = pkt;
    tPkt->handler = this;
    tPkt->sPort = ntohs(tcphdr->source);
    tPkt->dPort = ntohs(tcphdr->dest);
    size_t tcpHdrSize = sizeof(struct tcphdr);
    tPkt->payloadSize = pkt->payloadSize - tcpHdrSize;
    tPkt->payload = pkt->payload + tcpHdrSize;

    return tPkt;
}
