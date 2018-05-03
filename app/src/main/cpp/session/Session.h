//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASK_H
#define ENVPROXY_TASK_H


#include <ctime>


struct SessionInfo;
struct TransportPkt;


class Session {
public:
    Session();

    virtual int onReceive(uint8_t *data) = 0;


public:
    Session *next;
};


#endif //ENVPROXY_TASK_H
