//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IPPACKAGE_H
#define ENVPROXY_IPPACKAGE_H


#include <stdint.h>
#include <linux/in6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


#define IP_HANDLE_SUCCESS 0
#define IP_HANDLE_VERSION_NOT_MATCH 1
#define IP_HANDLE_HDR_LEN_INVALID 2
/*not support mf*/
#define IP_HANDLE_NOT_SUPPORT_MF 3
#define IP_HANDLE_TOT_LEN_INVALID 4


class proxyEngine;

union IpAddr {
    in6_addr ip6;
    int32_t ip4;
};

class IpHandler;

struct IpPackage {
    uint8_t *pkt;
    size_t pktSize;
    IpAddr srcAddr;
    IpAddr dstAddr;
    uint8_t protocol;
    uint8_t *payload;
    size_t payloadSize;
    IpHandler *ipHandler;
};


class IpHandler {
public:
    IpHandler(proxyEngine *proxyEngine);

    proxyEngine *getProxyEngine() const;

    virtual IpPackage *handlePackage(uint8_t *pkt, size_t pktSize) = 0;

    virtual int canHandlePackage(uint8_t *pkt, size_t pktSize) = 0;


protected:
    proxyEngine *mProxyEngine;
};

#endif //ENVPROXY_IPPACKAGE_H
