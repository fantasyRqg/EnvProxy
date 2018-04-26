//
// Created by Rqg on 24/04/2018.
//

#include "Protocol.h"

Protocol::Protocol(IpPackage *ipPkt) : mIpPkt(ipPkt) {}

Protocol::~Protocol() {
    delete mIpPkt;
}
