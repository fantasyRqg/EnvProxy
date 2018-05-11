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

    void freeStatusData(SessionInfo *sessionInfo) override;

    void onSocketEvent(SessionInfo *sessionInfo, epoll_event *ev) override;

    bool isActive(SessionInfo *sessionInfo) override;

    int monitorSession(SessionInfo *sessionInfo) override;

    int checkSession(SessionInfo *sessionInfo) override;

    int getTimeout(SessionInfo *sessionInfo) override;

    time_t checkTimeout(SessionInfo *sessionInfo, time_t timeout, int del, time_t now) override;
};


#endif //ENVPROXY_TCP_H
