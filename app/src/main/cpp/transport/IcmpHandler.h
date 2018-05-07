//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_ICMP_H
#define ENVPROXY_ICMP_H

#include "TransportHandler.h"

class IcmpHandler : public TransportHandler {

public:
    IcmpHandler();

    virtual ~IcmpHandler();

    TransportPkt *handleIpPkt(IpPackage *pkt) override;

    void processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) override;

    void *createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) override;

    void freeStatusData(void *data) override;

};


#endif //ENVPROXY_ICMP_H
