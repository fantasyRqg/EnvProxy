//
// Created by Rqg on 24/04/2018.
//

#include <arpa/inet.h>
#include <netinet/in6.h>
#include <netinet/ip.h>


#include "HttpSession.h"
#include "../log.h"
#include "../proxyTypes.h"

#define LOG_TAG "HttpSession"


HttpSession::HttpSession(SessionInfo *sessionInfo) : Session(sessionInfo) {}

HttpSession::~HttpSession() {

}

int HttpSession::onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    ADDR_TO_STR(sessionInfo)
    ALOGD("onTunDown %p new from %s:%d to %s:%d , data size = %u", this, source, sessionInfo->sPort,
          dest,
          sessionInfo->dPort, downData->size);

    ALOGV("%s", downData->data);

    return onTunUp(sessionInfo, downData);
}

int HttpSession::onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    return prev->onTunUp(sessionInfo, upData);
}

int HttpSession::onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    ADDR_TO_STR(sessionInfo)
    ALOGV("onSocketDown %p new from %s:%d to %s:%d , data size = %u", this, source,
          sessionInfo->sPort,
          dest,
          sessionInfo->dPort, downData->size);

    ALOGV("%s", downData->data);

    return onSocketUp(sessionInfo, downData);
}

int HttpSession::onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    return prev->onSocketUp(sessionInfo, upData);
}
