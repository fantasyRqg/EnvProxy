//
// Created by Rqg on 24/04/2018.
//

#include "IpPackageFactory.h"

#include "ip4.h"
#include "ip6.h"


IpPackage *IpPackageFactory::createIpPackage(uint8_t *pkt, size_t length) {
    if (ip4::isIpV4Package(pkt, length)) {
        return new ip4(mEpollFd, mTunFd, pkt, length);
    } else if (ip6::isIpV6Package(pkt, length)) {
        return new ip6(mEpollFd, mTunFd, pkt, length);
    } else {
        return nullptr;
    }
}

IpPackageFactory::IpPackageFactory(int epollFd, int tunFd) : mEpollFd(epollFd), mTunFd(tunFd) {

}

