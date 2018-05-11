//
// Created by Rqg on 2018/5/3.
//



#include <stdlib.h>
#include <cstring>

#include "BufferPool.h"
#include "log.h"

#define LOG_TAG "BufferPool"

#define BUFFER_POOL_IDLE 1
#define BUFFER_POOL_IN_USE 2

#define MAP_BUFFER_SIZE_INTERVAL 512

struct Buffer {
    uint8_t *buf;
    uint8_t *realBuf;
    size_t size;
    int state;
    Buffer *next;
};

BufferPool::BufferPool() {

}


size_t mapSize(size_t size) {
    return (size / MAP_BUFFER_SIZE_INTERVAL + 1) * MAP_BUFFER_SIZE_INTERVAL;
}

BufferPool::~BufferPool() {
    for (auto i = mBuffMap.begin(); i != mBuffMap.end(); ++i) {
        Buffer *b = static_cast<Buffer *>(i->second);
        Buffer *tmp = nullptr;

        while (b != nullptr) {
            tmp = b;
            b = b->next;

            free(tmp->realBuf);
            free(tmp);
        }
    }
}


uint8_t *BufferPool::allocBuffer(size_t size) {
    size = mapSize(size);

    Buffer *lb = static_cast<Buffer *>(mBuffMap[size]);
    Buffer *idle = nullptr;

    while (lb != nullptr) {
        if (lb->state == BUFFER_POOL_IDLE) {
            idle = lb;
            break;
        }
        lb = lb->next;
    }

    if (idle == nullptr) {
        idle = static_cast<Buffer *>(malloc(sizeof(Buffer)));

        idle->realBuf = static_cast<uint8_t *>(malloc(size + sizeof(size_t)));
        size_t *sizeP = reinterpret_cast<size_t *>(idle->realBuf);
        *sizeP = size;
        idle->size = size;
        idle->buf = idle->realBuf + sizeof(size_t);
        idle->state = BUFFER_POOL_IDLE;
        idle->next = static_cast<Buffer *>(mBuffMap[size]);
        mBuffMap[size] = idle;
    }

    idle->state = BUFFER_POOL_IN_USE;
    memset(idle->buf, 0, idle->size);

    ALOGD("allocate buffer %p", idle->buf);
    return idle->buf;
}

void BufferPool::freeBuffer(uint8_t *buf) {
    ALOGV("freeBuffer %p", buf);
    size_t *p = reinterpret_cast<size_t *>(buf - sizeof(size_t));
    size_t size = *p;

    if (size % MAP_BUFFER_SIZE_INTERVAL != 0) {
        ALOGE("buffer header has been modify, size not correct");
    }

    Buffer *lb = static_cast<Buffer *>(mBuffMap[size]);
    bool putBack = false;

    while (lb != nullptr) {
        if (lb->buf == buf) {
            putBack = true;
            lb->state = BUFFER_POOL_IDLE;
        }
        lb = lb->next;
    }

    if (!putBack) {
        ALOGE("put back buf error, can not find buf location");
    }
}
