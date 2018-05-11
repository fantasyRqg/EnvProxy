//
// Created by Rqg on 2018/5/3.
//

#ifndef ENVPROXY_PROXYBUFFER_H
#define ENVPROXY_PROXYBUFFER_H

#include <map>

class BufferPool {
public:
    BufferPool();

    uint8_t * allocBuffer(size_t size);

    void freeBuffer(uint8_t *buf);

    virtual ~BufferPool();

private:
    std::map<size_t, void *> mBuffMap;
};


#endif //ENVPROXY_PROXYBUFFER_H
