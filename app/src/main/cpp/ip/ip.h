//
// Created by Rqg on 09/04/2018.
//

#ifndef ENVPROXY_IP_H
#define ENVPROXY_IP_H


#include <stdint.h>
#include <cstring>


#define IP_HANDLE_SUCCESS 0
#define IP_HANDLE_VERSION_NOT_MATCH 1
#define IP_HANDLE_HDR_LEN_INVALID 2
/*not support mf*/
#define IP_HANDLE_NOT_SUPPORT_MF 3
#define IP_HANDLE_TOT_LEN_INVALID 4

namespace proxy {
    class ip {
    public:
        ip(int epollFd, int tunFd);

    public:

        virtual int handlePackage(uint8_t *pkt, size_t length) = 0;

    protected:
        int epollFd;
        int tunFd;

    };


}

#endif //ENVPROXY_IP_H
