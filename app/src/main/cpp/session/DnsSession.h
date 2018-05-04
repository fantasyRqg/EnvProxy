//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKDNS_H
#define ENVPROXY_TASKDNS_H


#include "Session.h"

class DnsSession : public Session {
public:
    DnsSession();

    virtual ~DnsSession();

};


#endif //ENVPROXY_TASKDNS_H
