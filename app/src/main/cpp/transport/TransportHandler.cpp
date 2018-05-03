//
// Created by Rqg on 24/04/2018.
//

#include <stdlib.h>

#include "TransportHandler.h"
#include "../proxyTypes.h"


TransportHandler::TransportHandler() {

}

TransportHandler::~TransportHandler() {

}

void TransportHandler::freePkt(TransportPkt *pkt) {
    if (pkt != nullptr) {
        if (pkt->ipPackage != nullptr) {
            if (pkt->ipPackage->pkt != nullptr) {
                free(pkt->ipPackage->pkt);
            }
            delete pkt->ipPackage;
        }
        delete pkt;
    }
}
