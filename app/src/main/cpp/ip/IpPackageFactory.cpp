//
// Created by Rqg on 24/04/2018.
//

#define LOG_TAG "IpPackageFactory"

#include "IpPackageFactory.h"

#include "Ip4Handler.h"
#include "Ip6Handler.h"
#include "../log.h"


IpHandler *IpPackageFactory::createIpPackage(uint8_t *pkt, size_t length) {
    if (Ip4Handler::isIpV4Package(pkt, length) == IP_HANDLE_SUCCESS) {
        ALOGD("create ipv4 package");
        return new Ip4Handler(mProxyEngine, pkt, length);
//    } else if (Ip6Handler::isIpV6Package(pkt, length) == IP_HANDLE_SUCCESS) {
//        ALOGV("create ipv6 package");
//        return new Ip6Handler(mProxyEngine, pkt, length);
    } else {
        return nullptr;
    }
}

IpPackageFactory::IpPackageFactory(proxyEngine *proxyEngine) : mProxyEngine(proxyEngine) {}

