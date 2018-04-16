//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP6_H
#define ENVPROXY_IP6_H


#include "ip.h"

class ip6 : public proxy::ip {
public:
    ip6(int epollFd, int tunFd);

private:
    int handlePackage(uint8_t *pkt, size_t length) override;

};


#endif //ENVPROXY_IP6_H
