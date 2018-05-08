//
// Created by Rqg on 2018/5/3.
//

#ifndef ENVPROXY_PROXYTYPES_H
#define ENVPROXY_PROXYTYPES_H


#include <linux/in6.h>
#include <cstdint>
#include <ctime>
#include <malloc.h>
#include <jni.h>
#include <sys/epoll.h>


union IpAddr {
    in6_addr ip6;
    int32_t ip4;
};

class BufferPool;

class proxyEngine;

struct ProxyContext {
    proxyEngine *engine;
    int tunFd;
    int epollFd;
    BufferPool *bufferPool;
    size_t mtu;
};

class IpHandler;

class IpPackage {
public:
    uint8_t *pkt;
    size_t pktSize;
    IpAddr srcAddr;
    IpAddr dstAddr;
    uint8_t protocol;
    uint8_t *payload;
    size_t payloadSize;
    IpHandler *handler;
    int versoin;

public:
    ~IpPackage();
};


class TransportHandler;

class TransportPkt {
public:
    IpPackage *ipPackage;
    uint8_t *payload;
    size_t payloadSize;
    uint16_t sPort;
    uint16_t dPort;
    TransportHandler *handler;

public:
    ~TransportPkt();
};


class Session;

struct SessionInfo {
    TransportHandler *transportHandler;
    IpHandler *ipHandler;
    IpAddr srcAddr;
    IpAddr dstAddr;
    uint8_t protocol;
    uint16_t sPort;
    uint16_t dPort;
    int ipVersoin;
    Session *session;
    time_t lastActive;
    ProxyContext *context;
    SessionInfo *next;
    void *tData;
    epoll_event ev;
};

#endif //ENVPROXY_PROXYTYPES_H
