//
// Created by Rqg on 09/04/2018.
//

#include <malloc.h>
#include "IpPackage.h"


IpPackage::IpPackage(int epollFd, int tunFd, uint8_t *pkt, size_t pktLength) :
        epollFd(epollFd), tunFd(tunFd), mPkt(pkt), mPktLength(pktLength) {

}

IpPackage::~IpPackage() {
    free(mPkt);
}
