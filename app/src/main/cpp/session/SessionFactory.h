//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASKFACTORY_H
#define ENVPROXY_TASKFACTORY_H


struct SessionInfo;

class TransportPkt;

class SessionFactory {
public:

    SessionFactory(int maxSessionSize);

    struct SessionInfo *findOrCreateSession(TransportPkt *pkt);

    virtual ~SessionFactory();

    void freeSession(SessionInfo *si);

    SessionInfo *getSessions() const;

    int getSessionCount() const;

private:
    struct SessionInfo *createSession(TransportPkt *pkt);

private:
    int mMaxSessionSize;
    SessionInfo *mSessions;
    int mSessionCount;
};


#endif //ENVPROXY_TASKFACTORY_H
