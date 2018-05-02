//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_TCP_H
#define ENVPROXY_TCP_H

#include "TransportHandler.h"


class TcpHandler : public TransportHandler {

public:
    TcpHandler();

    virtual ~TcpHandler();

    TransportPkt *handleIpPkt(IpPackage *pkt) override;
};


#endif //ENVPROXY_TCP_H
