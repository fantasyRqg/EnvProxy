//
// Created by Rqg on 24/04/2018.
//

#ifndef ENVPROXY_TASK_H
#define ENVPROXY_TASK_H


#include <ctime>


struct SessionInfo;

class TransportPkt;


class Session {
public:
    Session();

    virtual ~Session();

//    virtual int onTunDown(uint8_t *data);


public:
    Session *next;
    Session *prev;
};


#endif //ENVPROXY_TASK_H
