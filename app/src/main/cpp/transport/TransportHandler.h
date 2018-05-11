//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H

#include <stdint.h>
#include <sys/epoll.h>

class IpHandler;

class IpPackage;

class TransportPkt;

struct ProxyContext;

struct SessionInfo;

class TransportHandler {

public:
    TransportHandler();

    virtual ~TransportHandler();

    virtual TransportPkt *handleIpPkt(IpPackage *pkt) = 0;

    virtual void processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) = 0;

    virtual void onSocketEvent(SessionInfo *sessionInfo, epoll_event *ev) = 0;

    virtual void *createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) = 0;

    virtual bool isActive(SessionInfo *sessionInfo) = 0;

    virtual int monitorSession(SessionInfo *sessionInfo) = 0;

    virtual int checkSession(SessionInfo *sessionInfo) = 0;

    virtual int getTimeout(SessionInfo *sessionInfo) = 0;

    virtual time_t checkTimeout(SessionInfo *sessionInfo, time_t timeout, int del, time_t now) =0;

    virtual void freeStatusData(SessionInfo *sessionInfo) = 0;
};


#endif //ENVPROXY_PROTOCOL_H
