//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_IPPACKAGEFACTORY_H
#define ENVPROXY_IPPACKAGEFACTORY_H


#include <stdint.h>

class IpPackage;

class IpPackageFactory {
public:
    IpPackageFactory(int epollFd, int tunFd);

    IpPackage *createIpPackage(uint8_t *pkt, size_t length);

private:
    int mEpollFd;
    int mTunFd;
};


#endif //ENVPROXY_IPPACKAGEFACTORY_H
