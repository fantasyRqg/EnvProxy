//
// Created by Rqg on 2018/5/3.
//


//#define LOG_TAG "ProxyTypes"

#include "proxyTypes.h"
#include "BufferPool.h"
#include "ip/IpHandler.h"

IpPackage::~IpPackage() {
//    ALOGD("IpPackage Destructor call");
    if (pkt != nullptr) {
        auto context = handler->getProxyContext();
        if (context != nullptr) {
            context->bufferPool->freeBuffer(pkt);
        }
        pkt = nullptr;
    }
}


TransportPkt::~TransportPkt() {
//    ALOGD("TransportPkt Destructor call");
    if (ipPackage != nullptr) {
        delete ipPackage;
        ipPackage = nullptr;
    }
}