//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKHTTPS_H
#define ENVPROXY_TASKHTTPS_H


#include "Session.h"


struct TlsCtx;

struct DataBuffer;

class TlsSession : public Session {
public:
    TlsSession();

    virtual ~TlsSession();

    int onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

    int onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) override;

    int onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) override;

    void releaseResource(SessionInfo *sessionInfo) override;

private:
    TlsCtx *mTunServer;
    TlsCtx *mClient;
    DataBuffer *mPenddingData;


    int handlePendingData(SessionInfo *sessionInfo);

    void appendPendingData(DataBuffer *db);

    int outClientData(SessionInfo *sessionInfo);
};


#endif //ENVPROXY_TASKHTTPS_H
