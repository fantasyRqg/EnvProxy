//
// Created by Rqg on 09/04/2018.
//

#include <malloc.h>
#include "IpHandler.h"
#include "../proxyTypes.h"


IpHandler::IpHandler(ProxyContext *proxyContext) {
    mProxyContext = proxyContext;
}

ProxyContext *IpHandler::getProxyEngine() const {
    return mProxyContext;
}

IpHandler::~IpHandler() {

}

void IpHandler::freeIpPkt(IpPackage *pkt) {
    if (pkt != nullptr) {
        if (pkt->pkt != nullptr) {
            free(pkt->pkt);
        }

        delete pkt;
    }
}
