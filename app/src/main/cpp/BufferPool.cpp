//
// Created by Rqg on 2018/5/3.
//



#include <stdlib.h>

#include "BufferPool.h"


#define BUFFER_POOL_IDLE 1
#define BUFFER_POOL_IN_USE 2


BufferPool::BufferPool(size_t bufCount, size_t maxBufBytesSize) : mBufCount(bufCount),
                                                                  mMaxBufSize(maxBufBytesSize) {
    mBufArray = static_cast<void **>(malloc(sizeof(void *) * mBufCount));
    mBufUsage = static_cast<short *>(malloc(sizeof(short) * mBufCount));
    for (int i = 0; i < mMaxBufSize; ++i) {
        mBufArray[i] = malloc(mMaxBufSize);
        mBufUsage[i] = BUFFER_POOL_IDLE;
    }
}

BufferPool::~BufferPool() {
    for (int i = 0; i < mMaxBufSize; ++i) {
        free(mBufArray[i]);
    }
    free(mBufArray);
}

size_t BufferPool::getBufCount() const {
    return mBufCount;
}

size_t BufferPool::getMaxBufSize() const {
    return mMaxBufSize;
}


void *BufferPool::allocBuffer(void) {
    for (int i = 0; i < mBufCount; ++i) {
        if (mBufUsage[i] == BUFFER_POOL_IDLE) {
            mBufUsage[i] = BUFFER_POOL_IN_USE;
            memset(mBufArray[i], 0, mMaxBufSize);
            return mBufArray[i];
        }
    }

    return nullptr;
}

void BufferPool::freeBuffer(void *buf) {
    for (int i = 0; i < mBufCount; ++i) {
        if (mBufArray[i] == buf) {
            mBufUsage[i] = BUFFER_POOL_IDLE;
            return;
        }
    }
}

size_t BufferPool::getRemainBufCount() {
    size_t c = 0;

    for (int i = 0; i < mBufCount; ++i) {
        if (mBufUsage[i] == BUFFER_POOL_IDLE) {
            c++;
        }
    }
    return c;
}
