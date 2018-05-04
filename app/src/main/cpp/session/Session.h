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
 *         |      session  1                                                                |
 *          --------------------------------------------------------------------------------
 *               |           ∧                                    |           ∧
 *               |           |                                    |           |
 *           onTunDown    onSockUp                           onSocketDown  onTunUp
 *               |           |                                    |           |
 *               ∨           |                                    ∨           |
 *          --------------------------------------------------------------------------------
 *         |      session   2                                                               |
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

class Session {
public:
    Session();

    virtual ~Session();

    /**
     * data flow tun -> socket
     * @param ctx
     * @param data
     * @return
     */
    virtual uint8_t *onTunDown(ProxyContext *ctx, uint8_t *data);

    /**
     *
     * @param ctx
     * @param data
     * @return
     */
    virtual uint8_t *onTunUp(ProxyContext *ctx, uint8_t *data);

    /**
     *
     * @param ctx
     * @param data
     * @return
     */
    virtual uint8_t *onSocketDown(ProxyContext *ctx, uint8_t *data);

    /**
     *
     * @param ctx
     * @param data
     * @return
     */
    virtual uint8_t *onSocketUp(ProxyContext *ctx, uint8_t *data);


public:
    Session *next;
    Session *prev;
};


#endif //ENVPROXY_TASK_H
