//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_IPPACKAGEFACTORY_H
#define ENVPROXY_IPPACKAGEFACTORY_H


#include <stdint.h>

class IpHandler;

struct IpPackage;

class proxyEngine;

class IpPackageFactory {
public:

    IpPackageFactory(proxyEngine *proxyEngine);

    IpPackage *createIpPackage(uint8_t *pkt, size_t pktSize);

    virtual ~IpPackageFactory();

private:
    proxyEngine *mProxyEngine;

    IpHandler *mIp4Handler;
    IpHandler *mIp6Handler;


};


#endif //ENVPROXY_IPPACKAGEFACTORY_H
