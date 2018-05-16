//
// Created by Rqg on 24/04/2018.
//

#include "Session.h"
#include "../proxyTypes.h"
#include "../transport/TransportHandler.h"

Session::Session() : next(nullptr), prev(nullptr) {

}

Session::~Session() {

}

int Session::onTunDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    if (next == nullptr) {
        return onTunUp(sessionInfo, downData);
    } else {
        return next->onTunDown(sessionInfo, downData);
    }
}

int Session::onTunUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    if (prev == nullptr) {
        return sessionInfo->transportHandler->dataToSocket(sessionInfo, upData);
    } else {
        return prev->onTunUp(sessionInfo, upData);
    }

}

int Session::onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData) {
    if (next == nullptr) {
        return onSocketUp(sessionInfo, downData);
    } else {
        return next->onSocketDown(sessionInfo, downData);
    }
}

int Session::onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData) {
    if (prev == nullptr) {
        return sessionInfo->transportHandler->dataToTun(sessionInfo, upData);
    } else {
        return prev->onSocketUp(sessionInfo, upData);
    }
}
