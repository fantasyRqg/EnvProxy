//
// Created by Rqg on 2018/5/3.
//

#ifndef ENVPROXY_PROXYBUFFER_H
#define ENVPROXY_PROXYBUFFER_H


#include <cstring>

class BufferPool {
public:
    BufferPool(size_t bufCount, size_t maxBufBytesSize);

    size_t getBufCount() const;

    size_t getMaxBufSize() const;


    void *allocBuffer(void);

    void freeBuffer(void *buf);

    virtual ~BufferPool();

    size_t getRemainBufCount();

private:
    size_t mBufCount;
    size_t mMaxBufSize;
    void **mBufArray;
    short *mBufUsage;
};


#endif //ENVPROXY_PROXYBUFFER_H
