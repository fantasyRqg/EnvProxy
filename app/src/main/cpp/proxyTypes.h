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
#include <openssl/ossl_typ.h>
#include "CertManager.h"


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
    size_t mtu;
    int maxSessions;
    int sessionCount;
    CertManager *certManager;
};

//#define balloc context->bufferPool->allocBuffer
//#define bfree context->bufferPool->freeBuffer


class IpHandler;

class IpPackage {
public:
    uint8_t *pkt = nullptr;
    size_t pktSize;
    IpAddr srcAddr;
    IpAddr dstAddr;
    uint8_t protocol;
    uint8_t *payload = nullptr;
    size_t payloadSize;
    IpHandler *handler = nullptr;
    int version;

public:
    ~IpPackage();
};


class TransportHandler;

class TransportPkt {
public:
    IpPackage *ipPackage = nullptr;
    uint8_t *payload = nullptr;
    size_t payloadSize;
    uint16_t sPort;
    uint16_t dPort;
    TransportHandler *handler = nullptr;

public:
    ~TransportPkt();
};


class Session;

struct SessionInfo {
    TransportHandler *transportHandler = nullptr;
    IpHandler *ipHandler = nullptr;
    IpAddr srcAddr;
    IpAddr dstAddr;
    uint8_t protocol;
    uint16_t sPort;
    uint16_t dPort;
    int version;
    Session *session = nullptr;
    time_t lastActive;
    ProxyContext *context = nullptr;
    SessionInfo *next = nullptr;
    void *tData;
    epoll_event ev;
};

#define DATABUFFER_DST_TUN 0;
#define DATABUFFER_DST_SOCKET 1;


struct DataBuffer {
    uint8_t *data = nullptr;
    uint16_t size;
    uint16_t sent;
    DataBuffer *next = nullptr;
};

void freeLinkDataBuffer(SessionInfo *sessionInfo, DataBuffer *dbuff);

DataBuffer *createDataBuffer(SessionInfo *sessionInfo, size_t size);


// DNS

#define DNS_QCLASS_IN 1
#define DNS_QTYPE_A 1 // IPv4
#define DNS_QTYPE_AAAA 28 // IPv6

#define DNS_QNAME_MAX 255
#define DNS_TTL (10 * 60) // seconds

struct dns_header {
    uint16_t id; // identification number
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd :1; // recursion desired
    uint16_t tc :1; // truncated message
    uint16_t aa :1; // authoritive answer
    uint16_t opcode :4; // purpose of message
    uint16_t qr :1; // query/response flag
    uint16_t rcode :4; // response code
    uint16_t cd :1; // checking disabled
    uint16_t ad :1; // authenticated data
    uint16_t z :1; // its z! reserved
    uint16_t ra :1; // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr :1; // query/response flag
    uint16_t opcode :4; // purpose of message
    uint16_t aa :1; // authoritive answer
    uint16_t tc :1; // truncated message
    uint16_t rd :1; // recursion desired
    uint16_t ra :1; // recursion available
    uint16_t z :1; // its z! reserved
    uint16_t ad :1; // authenticated data
    uint16_t cd :1; // checking disabled
    uint16_t rcode :4; // response code
# else
# error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
} __packed;

typedef struct dns_rr {
    __be16 qname_ptr;
    __be16 qtype;
    __be16 qclass;
    __be32 ttl;
    __be16 rdlength;
} __packed dns_rr;


typedef struct SSLCert {
    SSL_CTX *serverCtx;
    SSL_CTX *clientCtx;
} SSLCert;

#endif //ENVPROXY_PROXYTYPES_H
