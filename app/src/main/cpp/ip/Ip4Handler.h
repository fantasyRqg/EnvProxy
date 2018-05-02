//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP4_H
#define ENVPROXY_IP4_H

#include "IpHandler.h"


class Ip4Handler : public IpHandler {
public:

    Ip4Handler(proxyEngine *proxyEngine);

    IpPackage *handlePackage(uint8_t *pkt, size_t pktSize) override;

    int canHandlePackage(uint8_t *pkt, size_t pktSize) override;
};


#endif //ENVPROXY_IP4_H
