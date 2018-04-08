//
// Created by Rqg on 03/04/2018.
//

#ifndef ENVPROXY_PROXYENGINE_H
#define ENVPROXY_PROXYENGINE_H


#define SESSION_MAX 255 // number
#define SESSION_LIMIT 30 // percent

#define EPOLL_EVENTS 20


class proxyEngine {
public:
    proxyEngine(size_t mtu);

    ~proxyEngine();

    void handleEvents();

public:
    int mVpnFd = -1;
    bool mRunning = false;
    size_t mMTU = 1000;

private:
    int checkTun(epoll_event *pEvent);
};


#endif //ENVPROXY_PROXYENGINE_H
