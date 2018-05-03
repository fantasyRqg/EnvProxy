//
// Created by Rqg on 09/04/2018.
//

#include <malloc.h>
#include "IpHandler.h"
#include "../proxyTypes.h"


IpHandler::IpHandler(ProxyContext *proxyContext) {
    mProxyContext = proxyContext;
}

IpHandler::~IpHandler() {

}


ProxyContext *IpHandler::getProxyContext() const {
    return mProxyContext;
}
