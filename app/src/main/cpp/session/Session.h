//
// Created by Rqg on 24/04/2018.
//

/**
 *
 *                    Tun                                            socket
 *                     /∧                                               /∧
 *                    /  \                                             /  \
 *                   /    \                                           /    \
 *                  /      \                                         /      \
 *                 ∨        \                                       ∨        \
 *           onTunDown   onSocketUp                          onSocketDown  onTunUp
 *               |           ∧                                    |           ∧
 *               ∨           |                                    ∨           |
 *          --------------------------------------------------------------------------------
 *         |      session  1    <..........................>                                |
 *          --------------------------------------------------------------------------------
 *               |           ∧                                    |           ∧
 *               |           |                                    |           |
 *           onTunDown   onSocketUp                          onSocketDown  onTunUp
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
 *
 *
 * 所有函数，输入内存即无需外部管理释放，输出内存由外部释放
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
    Session(SessionInfo *sessionInfo);

    virtual ~Session();


    /**
     * 所有函数，输入内存即无需外部管理释放，输出内存由外部释放
     *
     * @param sessionInfo session info
     * @param _in_data input data
     * @param _in_size input data size
     * @param upData directly to up layer data,out
     */
    virtual int onTunDown(SessionInfo *sessionInfo, DataBuffer *downData);

    /**
     * 所有函数，输入内存即无需外部管理释放，输出内存由外部释放
     *
     * @param sessionInfo
     * @param upData
     * @return
     */
    virtual int onTunUp(SessionInfo *sessionInfo, DataBuffer *upData);

    /**
     * 所有函数，输入内存即无需外部管理释放，输出内存由外部释放
     *
     * @param sessionInfo
     * @param _in_data
     * @param _in_size
     * @param upData out
     * @return
     */
    virtual int onSocketDown(SessionInfo *sessionInfo, DataBuffer *downData);

    /**
     * 所有函数，输入内存即无需外部管理释放，输出内存由外部释放
     *
     * @param sessionInfo
     * @param upData
     * @return
     */
    virtual int onSocketUp(SessionInfo *sessionInfo, DataBuffer *upData);


    virtual void releaseResource(SessionInfo *sessionInfo);

public:
    Session *next;
    Session *prev;
};


#endif //ENVPROXY_TASK_H
