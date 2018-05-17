//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKHTTP_H
#define ENVPROXY_TASKHTTP_H


#include "Session.h"

class HttpSession : public Session {
public:

    HttpSession(SessionInfo *sessionInfo);

    virtual ~HttpSession();

    int onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

    int onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

};


#endif //ENVPROXY_TASKHTTP_H
