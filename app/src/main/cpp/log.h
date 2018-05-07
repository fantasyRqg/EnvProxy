//
// Created by Rqg on 03/04/2018.
//

#ifndef ENVPROXY_LOG_H
#define ENVPROXY_LOG_H

#include <android/log.h>
#include <netinet/ip6.h>


#define ENABLE_LOG


#ifdef ENABLE_LOG

#define ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define ADDR_TO_STR(ipPkt)      char source[INET6_ADDRSTRLEN + 1]; \
                                char dest[INET6_ADDRSTRLEN + 1]; \
                                if (ipPkt->versoin == IPVERSION) { \
                                    inet_ntop(AF_INET, &ipPkt->srcAddr.ip4, source, sizeof(source)); \
                                    inet_ntop(AF_INET, &ipPkt->dstAddr.ip4, dest, sizeof(dest)); \
                                } else if (ipPkt->versoin == IPV6_VERSION) { \
                                    inet_ntop(AF_INET6, &ipPkt->srcAddr.ip6, source, sizeof(source)); \
                                    inet_ntop(AF_INET6, &ipPkt->dstAddr.ip6, dest, sizeof(dest)); \
                                }

#else

#define ALOGV(...)
#define ALOGD(...)
#define ALOGI(...)
#define ALOGW(...)
#define ALOGE(...)

#endif

#endif //ENVPROXY_LOG_H
