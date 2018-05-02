//
// Created by Rqg on 09/04/2018.
//

#include <netinet/ip_icmp.h>

#include "IcmpHandler.h"
#include "../ip/IpHandler.h"
//
//int Icmp::handleProtocol() {
//    struct icmp *icmpHdr = reinterpret_cast<icmp *>(mIpPkt->getPayload());
//    mSrcPort = ntohs(icmpHdr->icmp_id);
//    mDstPort = mSrcPort;
//
//    return 0;
//}

Icmp::~Icmp() {

}

Icmp::Icmp(IpHandler *ipPkt) : Protocol(ipPkt) {

}
