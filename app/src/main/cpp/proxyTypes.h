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


#define ICMP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define ICMP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)
#define UDP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define UDP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)


#define EPOLL_TIMEOUT 3600 // seconds
#define EPOLL_EVENTS 20
#define EPOLL_MIN_CHECK 100 // milliseconds

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

#define ICMP_TIMEOUT 15 // seconds

#define UDP_TIMEOUT_53 15 // seconds
#define UDP_TIMEOUT_ANY 300 // seconds
#define UDP_KEEP_TIMEOUT 60 // seconds

#define TCP_INIT_TIMEOUT 20 // seconds ~net.inet.tcp.keepinit
#define TCP_IDLE_TIMEOUT 3600 // seconds ~net.inet.tcp.keepidle
#define TCP_CLOSE_TIMEOUT 20 // seconds
#define TCP_KEEP_TIMEOUT 300 // seconds
// https://en.wikipedia.org/wiki/Maximum_segment_lifetime



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
    int maxSessions;
    int sessionCount;
};

#define balloc context->bufferPool->allocBuffer
#define bfree context->bufferPool->freeBuffer


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

struct DataBuffer {
    uint8_t *data;
    uint16_t size;
    void *other;
    char *desc;
    DataBuffer *next;
};

#endif //ENVPROXY_PROXYTYPES_H
