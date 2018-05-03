//
// Created by Rqg on 09/04/2018.
//

#include <malloc.h>
#include "../proxyEngine.h"
#include "IpHandler.h"

IpHandler::IpHandler(proxyEngine *proxyEngine) {
    mProxyEngine = proxyEngine;
}

proxyEngine *IpHandler::getProxyEngine() const {
    return mProxyEngine;
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
