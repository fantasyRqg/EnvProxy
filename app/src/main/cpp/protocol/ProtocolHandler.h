//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H


#include <stdint.h>


class IpHandler;

class Protocol {

public:
    Protocol(IpHandler *ipPkt);

//    virtual int handleProtocol() = 0;
//
//    virtual ~Protocol();

protected:
    IpHandler *mIpPkt;
    uint16_t mSrcPort;
    uint16_t mDstPort;
    uint8_t *mPayload;

};


#endif //ENVPROXY_PROTOCOL_H
