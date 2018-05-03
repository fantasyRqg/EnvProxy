//
// Created by Rqg on 24/04/2018.
//

#include <linux/in.h>
#include "TransportFactory.h"
#include "TcpHandler.h"
#include "UdpHandler.h"
#include "IcmpHandler.h"
#include "../proxyTypes.h"

TransportFactory::TransportFactory() {
    mHandlerMap.insert(std::pair<int, TransportHandler *>(IPPROTO_ICMP, new IcmpHandler()));
    mHandlerMap.insert(std::pair<int, TransportHandler *>(IPPROTO_TCP, new TcpHandler()));
    mHandlerMap.insert(std::pair<int, TransportHandler *>(IPPROTO_UDP, new UdpHandler()));
}

TransportFactory::~TransportFactory() {
    for (auto i = mHandlerMap.begin(); i != mHandlerMap.end(); ++i) {
        delete i->second;
    }
}

TransportPkt *TransportFactory::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr)
        return nullptr;


    TransportPkt *p = nullptr;
    auto handler = mHandlerMap[pkt->protocol];
    if (handler != nullptr) {
        p = handler->handleIpPkt(pkt);
    }

    return p;
}


