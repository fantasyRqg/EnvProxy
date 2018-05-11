//
// Created by Rqg on 24/04/2018.
//

/**
 *
 *                    Tun                                            socket
 *                     /\                                               /\
 *                    /  \                                             /  \
 *                   /    \                                           /    \
 *                  /      \                                         /      \
 *                 ∨        \                                       ∨        \
 *           onTunDown    onSockUp                           onSocketDown  onTunUp
 *               |           ∧                                    |           ∧
 *               ∨           |                                    ∨           |
 *          --------------------------------------------------------------------------------
 *         |      session  1    <..........................>                                |
 *          --------------------------------------------------------------------------------
 *               |           ∧                                    |           ∧
 *               |           |                                    |           |
 *           onTunDown    onSockUp                           onSocketDown  onTunUp
 *               |           |                                    |           |
 *               ∨           |                                    ∨           |
 *          --------------------------------------------------------------------------------
 *         |      session   2   <..........................>                                |
 *          --------------------------------------------------------------------------------
 *               |           ∧                                    |           ∧
 *               |           |          send data to tun          |           |
 *               |           |-------------------<----------------∨           |
 *               |                                                            |
 *               ∨----------------------------->-------------------------------
 *                                      send data to socket
 *
 */

#ifndef ENVPROXY_TASK_H
#define ENVPROXY_TASK_H


#include <ctime>


struct SessionInfo;

class TransportPkt;

struct ProxyContext;

struct DataBuffer;

class Session {
public:
    Session();

    virtual ~Session();

//
//    virtual DataBuffer * onTunDown(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, DataBuffer *);
//
//    /**
//     *
//     * @param ctx context
//     * @param _in_data in data ptr
//     * @param _in_size in data size
//     * @param _out_size out data size
//     * @return out data ptr
//     */
//    virtual uint8_t *
//    onTunUp(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size);
//
//    /**
//     *
//     * @param ctx context
//     * @param _in_data in data ptr
//     * @param _in_size in data size
//     * @param _out_size out data size
//     * @return out data ptr
//     */
//    virtual uint8_t *
//    onSocketDown(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size);
//
//    /**
//     *
//     * @param ctx context
//     * @param _in_data in data ptr
//     * @param _in_size in data size
//     * @param _out_size out data size
//     * @return out data ptr
//     */
//    virtual uint8_t *
//    onSocketUp(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size);


public:
    Session *next;
    Session *prev;
};


#endif //ENVPROXY_TASK_H
