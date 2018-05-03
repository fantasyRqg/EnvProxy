//
// Created by Rqg on 2018/5/3.
//

#ifndef ENVPROXY_PROXYTYPES_H
#define ENVPROXY_PROXYTYPES_H


#include <linux/in6.h>
#include <cstdint>
#include <ctime>
#include <malloc.h>


union IpAddr {
    in6_addr ip6;
    int32_t ip4;
};

class BufferPool;

struct ProxyContext {
    int tunFd;
    int epollFd;
    BufferPool *bufferPool;
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
};

#endif //ENVPROXY_PROXYTYPES_H
