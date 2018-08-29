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
            free(pkt);
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

void freeLinkDataBuffer(SessionInfo *sessionInfo, DataBuffer *dbuff) {
    auto d = dbuff;
    while (d != nullptr) {
        auto tmp = d;
        d = d->next;

        free(tmp->data);

        delete tmp;
    }
}

DataBuffer *createDataBuffer(SessionInfo *sessionInfo, size_t size) {
    DataBuffer *r = new DataBuffer();
    r->next = nullptr;
    r->size = static_cast<uint16_t>(size);
    r->data = static_cast<uint8_t *>(malloc(r->size));
    r->sent = 0;

    return r;
}
