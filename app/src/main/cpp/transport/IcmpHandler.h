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
};


#endif //ENVPROXY_ICMP_H
