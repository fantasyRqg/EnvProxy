//
// Created by Rqg on 2018/5/8.
//

#include "util.h"

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length) {
    uint32_t sum = start;
    uint16_t *buf = (uint16_t *) buffer;
    size_t len = length;

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