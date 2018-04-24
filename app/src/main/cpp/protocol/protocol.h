//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_PROTOCOL_H
#define ENVPROXY_PROTOCOL_H


#include <stdint.h>

class protocol {


private:
    int mEpollFd;
    int mTunFd;
    uint8_t *mPkt;
    int mIpVersion;


};


#endif //ENVPROXY_PROTOCOL_H
