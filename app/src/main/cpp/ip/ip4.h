//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP4_H
#define ENVPROXY_IP4_H


#include "ip.h"

class ip4 : public proxy::ip {
public:
    ip4(int epollFd, int tunFd);

private:
    int handlePackage(uint8_t *pkt, size_t length) override;

};


#endif //ENVPROXY_IP4_H
