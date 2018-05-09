//
// Created by Rqg on 2018/5/8.
//

#include <linux/time.h>
#include <time.h>
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


long long get_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1e6LL;
}
