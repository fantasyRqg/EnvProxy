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

};


#endif //ENVPROXY_UDP_H
