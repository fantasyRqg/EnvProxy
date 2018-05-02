//
// Created by Rqg on 09/04/2018.
//

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
