//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_UDP_H
#define ENVPROXY_UDP_H

#include "TransportHandler.h"


class UdpHandler : public TransportHandler {
public:
    UdpHandler();

    virtual ~UdpHandler();

    TransportPkt *handleIpPkt(IpPackage *pkt) override;

    void processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) override;

    void *createStatusData(SessionInfo *sessionInfo) override;

    void freeStatusData(void *data) override;

};


#endif //ENVPROXY_UDP_H
