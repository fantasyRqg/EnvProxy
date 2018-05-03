//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H

#include <stdint.h>

class IpHandler;

struct IpPackage;

struct TransportPkt;

class TransportHandler {

public:
    TransportHandler();

    virtual ~TransportHandler();

    virtual TransportPkt *handleIpPkt(IpPackage *pkt) = 0;

    void freePkt(TransportPkt *pkt);
};


#endif //ENVPROXY_PROTOCOL_H
