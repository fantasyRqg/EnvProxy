//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H


#include <stdint.h>


class IpPackage;

class Protocol {

public:
    Protocol(IpPackage *ipPkt);

    virtual int handleProtocol() = 0;

    virtual ~Protocol();

protected:
    IpPackage *mIpPkt;
    uint16_t mSrcPort;
    uint16_t mDstPort;
    uint8_t *mPayload;

};


#endif //ENVPROXY_PROTOCOL_H
