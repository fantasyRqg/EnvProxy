//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKHTTPS_H
#define ENVPROXY_TASKHTTPS_H


#include "Session.h"

class TlsSession: Session {
public:
    TlsSession();

    virtual ~TlsSession();
};


#endif //ENVPROXY_TASKHTTPS_H
