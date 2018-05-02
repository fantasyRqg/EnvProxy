//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_ICMP_H
#define ENVPROXY_ICMP_H

#include "ProtocolHandler.h"

class Icmp : public Protocol {

public:
    Icmp(IpHandler *ipPkt);

    virtual ~Icmp();

//    int handleProtocol() override;
};


#endif //ENVPROXY_ICMP_H
