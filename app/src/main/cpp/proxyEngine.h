//
// Created by Rqg on 03/04/2018.
//

#ifndef ENVPROXY_PROXYENGINE_H
#define ENVPROXY_PROXYENGINE_H


#define SESSION_MAX 255 // number
#define SESSION_LIMIT 30 // percent

#define EPOLL_EVENTS 20

#include <sys/epoll.h>
#include "proxyTypes.h"

class IpPackageFactory;

class IpPackage;

struct ProxyContext;

class proxyEngine {
public:
    proxyEngine(size_t mtu);

    ~proxyEngine();

    void handleEvents();

    void stopHandleEvents();

    bool isProxyRunning();

public:
    int mTunFd = -1;
    bool mRunning = false;
    size_t mMTU = 1000;

private:
    IpPackage *
    checkTun(ProxyContext *context, epoll_event *pEvent, IpPackageFactory *ipPackageFactory);

    void logPkt(const IpPackage *ipPkt, const TransportPkt *tPkt) const;
};


#endif //ENVPROXY_PROXYENGINE_H
