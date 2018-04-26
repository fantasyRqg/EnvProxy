//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IPPACKAGE_H
#define ENVPROXY_IPPACKAGE_H


#include <stdint.h>
#include <linux/in6.h>


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

class IpPackage {
public:
    IpPackage(proxyEngine *proxyEngine, uint8_t *pkt, size_t pktLength);

    virtual ~IpPackage();

    proxyEngine *getProxyEngine() const;

    uint8_t *getPkt() const;

    size_t getPktLength() const;


    const IpAddr &getSrcAddr() const;

    const IpAddr &getDstAddr() const;

    uint8_t getAProtocol() const;

    uint8_t *getPayload() const;



public:
    virtual int handlePackage() = 0;

    virtual int getIpVersion() = 0;


protected:
    proxyEngine *mProxyEngine;
    uint8_t *mPkt;
    size_t mPktLength;
    IpAddr mSrcAddr;
    IpAddr mDstAddr;
    uint8_t mProtocol;
    uint8_t *mPayload;
};

#endif //ENVPROXY_IPPACKAGE_H
