//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKTCP_H
#define ENVPROXY_TASKTCP_H


#include "Session.h"

class TcpSession : public Session {
public:

    TcpSession(SessionInfo *sessionInfo);

    virtual ~TcpSession();

};


#endif //ENVPROXY_TASKTCP_H
