//
// Created by Rqg on 24/04/2018.
//

#include "HttpSession.h"

HttpSession::HttpSession() {}

HttpSession::~HttpSession() {

}

int HttpSession::onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    return onTunUp(sessionInfo, downData);
}

int HttpSession::onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    return prev->onTunUp(sessionInfo, upData);
}

int HttpSession::onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    return onSocketUp(sessionInfo, downData);
}

int HttpSession::onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    return prev->onSocketUp(sessionInfo, upData);
}
