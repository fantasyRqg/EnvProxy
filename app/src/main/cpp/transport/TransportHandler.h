//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H

#include <stdint.h>

class IpHandler;

class IpPackage;

class TransportPkt;

struct ProxyContext;

struct SessionInfo;

class TransportHandler {

public:
    TransportHandler();

    virtual ~TransportHandler();

    virtual TransportPkt *handleIpPkt(IpPackage *pkt) = 0;

    virtual void processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) = 0;

    virtual void *createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) = 0;

    virtual void freeStatusData(void *data) = 0;
};


#endif //ENVPROXY_PROTOCOL_H
