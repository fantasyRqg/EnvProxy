//
// Created by Rqg on 24/04/2018.
//

#define LOG_TAG "TransportHandler"

#include <jni.h>


#include "TransportHandler.h"
#include "../proxyTypes.h"
#include "../log.h"


TransportHandler::TransportHandler() {

}

TransportHandler::~TransportHandler() {

}

uint16_t TransportHandler::calc_checksum(uint16_t start, const uint8_t *buffer, size_t length) {
    register uint32_t sum = start;
    register uint16_t *buf = (uint16_t *) buffer;
    register size_t len = length;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len > 0)
        sum += *((uint8_t *) buf);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) sum;
}
