//
// Created by Rqg on 09/04/2018.
//

#include <malloc.h>
#include "IpPackage.h"


IpPackage::~IpPackage() {
    free(mPkt);
}

IpPackage::IpPackage(proxyEngine *proxyEngine, uint8_t *pkt, size_t pktLength) :
        mProxyEngine(proxyEngine), mPkt(pkt), mPktLength(pktLength) {

}
