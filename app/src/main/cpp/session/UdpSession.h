//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKUDP_H
#define ENVPROXY_TASKUDP_H


#include "Session.h"

class UdpSession : public Session {
public:

    UdpSession(SessionInfo *sessionInfo);

    virtual ~UdpSession();
};


#endif //ENVPROXY_TASKUDP_H
