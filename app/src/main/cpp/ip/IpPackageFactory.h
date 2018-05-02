//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_IPPACKAGEFACTORY_H
#define ENVPROXY_IPPACKAGEFACTORY_H


#include <stdint.h>

class IpHandler;

class proxyEngine;

class IpPackageFactory {
public:

    IpPackageFactory(proxyEngine *proxyEngine);

    IpHandler *createIpPackage(uint8_t *pkt, size_t length);

private:
    proxyEngine *mProxyEngine;

};


#endif //ENVPROXY_IPPACKAGEFACTORY_H
