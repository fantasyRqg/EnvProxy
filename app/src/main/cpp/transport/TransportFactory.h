//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOLFACTORY_H
#define ENVPROXY_PROTOCOLFACTORY_H

#include "TransportHandler.h"

#include <map>

class TransportHandler;

struct TransportPkt;

class IpPackage;

class TransportFactory {
public:
    TransportFactory();

    virtual ~TransportFactory();

    TransportPkt *handleIpPkt(IpPackage *pkt);

private:
    std::map<int, TransportHandler *> mHandlerMap;

};


#endif //ENVPROXY_PROTOCOLFACTORY_H
