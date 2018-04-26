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

proxyEngine *IpPackage::getProxyEngine() const {
    return mProxyEngine;
}

uint8_t *IpPackage::getPkt() const {
    return mPkt;
}

size_t IpPackage::getPktLength() const {
    return mPktLength;
}

const IpAddr &IpPackage::getSrcAddr() const {
    return mSrcAddr;
}

const IpAddr &IpPackage::getDstAddr() const {
    return mDstAddr;
}

uint8_t IpPackage::getAProtocol() const {
    return mProtocol;
}

uint8_t *IpPackage::getPayload() const {
    return mPayload;
}
