//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP4_H
#define ENVPROXY_IP4_H

#include "IpPackage.h"


class ip4 : public IpPackage {
public:
    ip4(proxyEngine *proxyEngine, uint8_t *pkt, size_t pktLength);

    ~ip4();

    static int isIpV4Package(uint8_t *pkt, size_t length);

    int handlePackage() override;

    int getIpVersion() override;


};


#endif //ENVPROXY_IP4_H
