//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP6_H
#define ENVPROXY_IP6_H


#include "IpHandler.h"


class Ip6Handler : public IpHandler {
public:
    Ip6Handler(proxyEngine *proxyEngine);

    virtual ~Ip6Handler();

    IpPackage *handlePackage(uint8_t *pkt, size_t pktSize) override;

    int canHandlePackage(uint8_t *pkt, size_t pktSize) override;
};


#endif //ENVPROXY_IP6_H
