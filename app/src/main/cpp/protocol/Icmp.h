//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_ICMP_H
#define ENVPROXY_ICMP_H

#include "Protocol.h"

class Icmp : public Protocol {

public:
    Icmp(IpPackage *ipPkt);

    virtual ~Icmp();

    int handleProtocol() override;
};


#endif //ENVPROXY_ICMP_H
