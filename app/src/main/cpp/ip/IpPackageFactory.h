//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_IPPACKAGEFACTORY_H
#define ENVPROXY_IPPACKAGEFACTORY_H


#include <stdint.h>

class IpHandler;

class IpPackage;

class proxyEngine;

struct ProxyContext;

class IpPackageFactory {
public:

    IpPackageFactory(ProxyContext *proxyContext);

    IpPackage *createIpPackage(uint8_t *pkt, size_t pktSize);

    virtual ~IpPackageFactory();

private:
    ProxyContext *mProxyContext;
    IpHandler *mIp4Handler;
    IpHandler *mIp6Handler;


};


#endif //ENVPROXY_IPPACKAGEFACTORY_H
