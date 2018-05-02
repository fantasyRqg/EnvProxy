//
// Created by Rqg on 24/04/2018.
//

#define LOG_TAG "IpPackageFactory"

#include <stdlib.h>

#include "IpPackageFactory.h"

#include "Ip4Handler.h"
#include "Ip6Handler.h"


#define IP_HANDLER_SIZE 1


IpPackageFactory::IpPackageFactory(proxyEngine *proxyEngine) : mProxyEngine(proxyEngine) {

    pIpHandlers = static_cast<IpHandler **>(malloc(sizeof(IpHandler *) * IP_HANDLER_SIZE));
    pIpHandlers[0] = new Ip4Handler(mProxyEngine);
//    pIpHandlers[1] = new Ip6Handler(mProxyEngine);

}

IpPackageFactory::~IpPackageFactory() {
    for (int i = 0; i < IP_HANDLER_SIZE; ++i) {
        delete pIpHandlers[i];
    }

    free(pIpHandlers);
}

IpPackage *IpPackageFactory::createIpPackage(uint8_t *pkt, size_t pktSize) {
    struct IpPackage *p = nullptr;

    for (int i = 0; i < IP_HANDLER_SIZE; ++i) {
        auto handler = pIpHandlers[i];
        if (handler->canHandlePackage(pkt, pktSize) == IP_HANDLE_SUCCESS) {
            p = handler->handlePackage(pkt, pktSize);
        }
    }

    return p;
}



