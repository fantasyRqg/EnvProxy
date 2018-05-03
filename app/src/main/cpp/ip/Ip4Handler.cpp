//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "Ip4Handler.h"
#include "../proxyTypes.h"


#define LOG_TAG "IPV4"

Ip4Handler::Ip4Handler(ProxyContext *proxyContext) : IpHandler(proxyContext) {}

IpPackage *Ip4Handler::handlePackage(uint8_t *pkt, size_t pktSize) {
    struct iphdr *ip4hdr = (struct iphdr *) pkt;

    struct IpPackage *p = new IpPackage();

    p->handler = this;
    p->versoin = IPVERSION;
    p->dstAddr.ip4 = ip4hdr->daddr;
    p->srcAddr.ip4 = ip4hdr->saddr;
    p->pkt = pkt;
    p->pktSize = pktSize;
    p->protocol = ip4hdr->protocol;

    uint8_t hdrSize = (uint8_t) (ip4hdr->ihl * 4);
    p->payload = pkt + hdrSize;
    p->payloadSize = pktSize - hdrSize;

    return p;
}

int Ip4Handler::canHandlePackage(uint8_t *pkt, size_t pktSize) {
    struct iphdr *ip4hdr = (struct iphdr *) pkt;

    if (ip4hdr->version != IPVERSION)
        return IP_HANDLE_VERSION_NOT_MATCH;

    if (pktSize < sizeof(struct iphdr)) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }

    if (ip4hdr->frag_off & IP_MF) {
        return IP_HANDLE_NOT_SUPPORT_MF;
    }

    if (ntohs(ip4hdr->tot_len) != pktSize) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }

    return IP_HANDLE_SUCCESS;
}

Ip4Handler::~Ip4Handler() {

}

