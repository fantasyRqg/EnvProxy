//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IPPACKAGE_H
#define ENVPROXY_IPPACKAGE_H


#define IP_HANDLE_SUCCESS 0
#define IP_HANDLE_VERSION_NOT_MATCH 1
#define IP_HANDLE_HDR_LEN_INVALID 2
/*not support mf*/
#define IP_HANDLE_NOT_SUPPORT_MF 3
#define IP_HANDLE_TOT_LEN_INVALID 4


class proxyEngine;

struct IpPackage;

struct ProxyContext;

class IpHandler {
public:
    IpHandler(ProxyContext *proxyContext);

    virtual ~IpHandler();

    ProxyContext *getProxyEngine() const;

    virtual IpPackage *handlePackage(uint8_t *pkt, size_t pktSize) = 0;

    virtual int canHandlePackage(uint8_t *pkt, size_t pktSize) = 0;

    void freeIpPkt(IpPackage *pkt);

protected:
    ProxyContext *mProxyContext;
};

#endif //ENVPROXY_IPPACKAGE_H
