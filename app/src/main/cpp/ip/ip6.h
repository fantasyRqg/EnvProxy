//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP6_H
#define ENVPROXY_IP6_H


#include "IpPackage.h"


class ip6 : public IpPackage {
public:
    ip6(int epollFd, int tunFd, uint8_t *pkt, size_t length);

    static int isIpV6Package(uint8_t *pkt, size_t length);

private:
public:
    int handlePackage() override;

};


#endif //ENVPROXY_IP6_H
