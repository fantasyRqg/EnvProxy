//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP_H
#define ENVPROXY_IP_H


#include <stdint.h>


#define IP_HANDLE_SUCCESS 0
#define IP_HANDLE_VERSION_NOT_MATCH 1
#define IP_HANDLE_HDR_LEN_INVALID 2
/*not support mf*/
#define IP_HANDLE_NOT_SUPPORT_MF 3
#define IP_HANDLE_TOT_LEN_INVALID 4

class IpPackage {
public:
    IpPackage(int epollFd, int tunFd, uint8_t *pkt, size_t length);

public:
    virtual int handlePackage() = 0;

protected:
    int epollFd;
    int tunFd;
    uint8_t *mPkt;
    size_t mPktLength;

};

#endif //ENVPROXY_IP_H
