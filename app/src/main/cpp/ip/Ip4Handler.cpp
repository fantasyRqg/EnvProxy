//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "Ip4Handler.h"
#include "../log.h"


#define LOG_TAG "IPV4"

Ip4Handler::Ip4Handler(proxyEngine *proxyEngine) : IpHandler(proxyEngine) {}

IpPackage *Ip4Handler::handlePackage(uint8_t *pkt, size_t pktSize) {
    struct iphdr *ip4hdr = (struct iphdr *) pkt;

    IpPackage *p = new IpPackage();

    p->ipHandler = this;
    p->protocol = IPVERSION;
    p->dstAddr.ip4 = ip4hdr->daddr;
    p->srcAddr.ip4 = ip4hdr->saddr;
    p->pkt = pkt;
    p->pktSize = pktSize;

    uint8_t hdrSize = (uint8_t) (ip4hdr->ihl * 4);
    p->payload = pkt + hdrSize;
    p->payloadSize = pktSize - hdrSize;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];


    inet_ntop(AF_INET, &ip4hdr->saddr, source, sizeof(source));
    inet_ntop(AF_INET, &ip4hdr->daddr, dest, sizeof(dest));

    protoent *pp = getprotobynumber(ip4hdr->protocol);

    if (pp != NULL) {
        ALOGD("IPV4 from %s to %s , Protocol %s", source, dest, pp->p_name);
    } else {
        ALOGD("IPV4 from %s to %s , Protocol %d", source, dest, ip4hdr->protocol);
    }


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

