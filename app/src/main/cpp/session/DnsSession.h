//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKDNS_H
#define ENVPROXY_TASKDNS_H


#include "Session.h"

class DnsSession : public Session {
public:

    DnsSession(SessionInfo *sessionInfo);

    virtual ~DnsSession();

    int onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

    int onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

protected:
    void parseDnsResponse(const SessionInfo *sessionInfo, const uint8_t *data, size_t datalen);

    int getDnsQuery(const SessionInfo *sessionInfo, const uint8_t *data, const size_t datalen,
                    uint16_t *qtype, uint16_t *qclass, char *qname);
};


#endif //ENVPROXY_TASKDNS_H
