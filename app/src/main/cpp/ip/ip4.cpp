//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ip4.h"
#include "../log.h"


#define LOG_TAG "IPV4"


ip4::~ip4() {

}

ip4::ip4(proxyEngine *proxyEngine, uint8_t *pkt, size_t pktLength) :
        IpPackage(proxyEngine, pkt, pktLength) {

}


int ip4::handlePackage() {
    struct iphdr *ip4hdr = (struct iphdr *) mPkt;


    mSrcAddr.ip4 = ip4hdr->saddr;
    mDstAddr.ip4 = ip4hdr->daddr;
    mProtocol = ip4hdr->protocol;

    uint8_t ipoptlen = (uint8_t) ((ip4hdr->ihl - 5) * 4);
    mPayload = mPkt + sizeof(struct iphdr) + ipoptlen;


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


    return IP_HANDLE_SUCCESS;
}

int ip4::isIpV4Package(uint8_t *pkt, size_t length) {
    struct iphdr *ip4hdr = (struct iphdr *) pkt;

    if (ip4hdr->version != IPVERSION)
        return IP_HANDLE_VERSION_NOT_MATCH;

    if (length < sizeof(struct iphdr)) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }

    if (ip4hdr->frag_off & IP_MF) {
        return IP_HANDLE_NOT_SUPPORT_MF;
    }

    if (ntohs(ip4hdr->tot_len) != length) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }

    return IP_HANDLE_SUCCESS;
}

int ip4::getIpVersion() {
    return IPVERSION;
}
