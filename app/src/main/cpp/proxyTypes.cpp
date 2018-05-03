//
// Created by Rqg on 2018/5/3.
//

#include "proxyTypes.h"
#include "BufferPool.h"
#include "ip/IpHandler.h"

IpPackage::~IpPackage() {
    if (pkt != nullptr) {
        auto context = handler->getProxyContext();
        if (context != nullptr) {
            context->bufferPool->freeBuffer(pkt);
        }
        pkt = nullptr;
    }
}


TransportPkt::~TransportPkt() {
    if (ipPackage != nullptr) {
        delete ipPackage;
        ipPackage = nullptr;
    }
}