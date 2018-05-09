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

    void processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) override;

    void *createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) override;

    void freeStatusData(void *data) override;

    void onSocketDataIncoming(SessionInfo *sessionInfo, epoll_event *ev) override;

    bool isActive(SessionInfo *sessionInfo) override;

    bool monitorSession(SessionInfo *sessionInfo) override;
};


#endif //ENVPROXY_TCP_H
