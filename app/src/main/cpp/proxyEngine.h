//
// Created by Rqg on 03/04/2018.
//

#ifndef ENVPROXY_PROXYENGINE_H
#define ENVPROXY_PROXYENGINE_H


#define SESSION_MAX 255 // number
#define SESSION_LIMIT 30 // percent

#define EPOLL_EVENTS 20

#include <sys/epoll.h>

class IpPackageFactory;

class IpHandler;


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
    IpHandler *checkTun(epoll_event *pEvent, IpPackageFactory *ipPackageFactory);


};


#endif //ENVPROXY_PROXYENGINE_H
