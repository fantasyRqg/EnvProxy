//
// Created by Rqg on 24/04/2018.
//

#define LOG_TAG "IpPackageFactory"

#include <stdlib.h>

#include "IpPackageFactory.h"

#include "Ip4Handler.h"
#include "Ip6Handler.h"


IpPackageFactory::IpPackageFactory(proxyEngine *proxyEngine)
        : mProxyEngine(proxyEngine),
          mIp4Handler(new Ip4Handler(proxyEngine)),
          mIp6Handler(new Ip6Handler(proxyEngine)) {
}

IpPackageFactory::~IpPackageFactory() {
    delete mIp4Handler;
    delete mIp6Handler;
}

IpPackage *IpPackageFactory::createIpPackage(uint8_t *pkt, size_t pktSize) {
    struct IpPackage *p = nullptr;

    if (mIp4Handler->canHandlePackage(pkt, pktSize) == IP_HANDLE_SUCCESS) {
        p = mIp4Handler->handlePackage(pkt, pktSize);
    }
//    else if (mIp6Handler->canHandlePackage(pkt, pktSize)) {
//        p = mIp6Handler->handlePackage(pkt, pktSize);
//    }

    return p;
}



