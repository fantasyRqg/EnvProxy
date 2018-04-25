//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP4_H
#define ENVPROXY_IP4_H

#include "IpPackage.h"


class ip4 : public IpPackage {
public:
    ip4(int epollFd, int tunFd, uint8_t *pkt, size_t length);

    ~ip4();

    static int isIpV4Package(uint8_t *pkt, size_t length);

    int handlePackage() override;


};


#endif //ENVPROXY_IP4_H
