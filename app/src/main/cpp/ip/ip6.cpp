//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "ip6.h"


#define LOG_TAG "IPV6"


ip6::~ip6() {
}

ip6::ip6(proxyEngine *proxyEngine, uint8_t *pkt, size_t pktLength) :
        IpPackage(proxyEngine, pkt, pktLength) {

}

int ip6::handlePackage() {
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *) mPkt;

    if ((ip6hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
        return IP_HANDLE_VERSION_NOT_MATCH;

    if (mPktLength < sizeof(struct ip6_hdr)) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }
//
//
//    u_int8_t ext_hdr_type = ip6hdr->ip6_nxt;
//
//    if (ip6hdr->frag_off & IP_MF) {
//        return IP_HANDLE_NOT_SUPPORT_MF;
//    }
//
//    if (ntohs(ip4hdr->tot_len) != length) {
//        return IP_HANDLE_HDR_LEN_INVALID;
//    }
//
//    char source[INET6_ADDRSTRLEN + 1];
//    char dest[INET6_ADDRSTRLEN + 1];
//
//    inet_ntop(AF_INET, &ip4hdr->saddr, source, sizeof(source));
//    inet_ntop(AF_INET, &ip4hdr->daddr, dest, sizeof(dest));
//
//    ALOGD("IPV6 from %s to %s", source, dest);

    return IP_HANDLE_SUCCESS;

}

int ip6::isIpV6Package(uint8_t *pkt, size_t length) {
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *) pkt;

    if ((ip6hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
        return IP_HANDLE_VERSION_NOT_MATCH;

    if (length < sizeof(struct ip6_hdr)) {
        return IP_HANDLE_HDR_LEN_INVALID;
    }
    return IP_HANDLE_SUCCESS;
}


int ip6::getIpVersion() {
    return IPV6_VERSION;
}
