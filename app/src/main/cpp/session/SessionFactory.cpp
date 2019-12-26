//
// Created by Rqg on 24/04/2018.
//

#define LOG_TAG "SessionFactory"

#include <netinet/ip.h>
#include <cstring>
#include <netinet/ip6.h>
#include <string>

#include "SessionFactory.h"
#include "../proxyTypes.h"
#include "Session.h"
#include "../ip/IpHandler.h"
#include "../transport/TransportHandler.h"
#include "../log.h"
#include "TcpSession.h"
#include "UdpSession.h"
#include "IcmpSession.h"
#include "DnsSession.h"
#include "HttpSession.h"
#include "TlsSession.h"


SessionFactory::SessionFactory(int maxSessionSize) : mMaxSessionSize(maxSessionSize),
                                                     mSessions(nullptr),
                                                     mSessionCount(0) {

}

SessionFactory::~SessionFactory() {
    SessionInfo *s = mSessions;
    //release sessionInfo
    while (s != nullptr) {
        auto tmp = s;
        s = s->next;
        auto ss = tmp->session;

        //release session
        while (ss != nullptr) {
            auto ssTmp = ss->next;
            ss = ss->next;
            delete ssTmp;
        }

        delete tmp;
    }
}


static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2) {
    return memcmp(a1, a2, sizeof(struct in6_addr));
}

static inline bool matchSession(struct SessionInfo *session, TransportPkt *pkt) {
    if (pkt->ipPackage->version != session->version)
        return false;

    if (pkt->ipPackage->version == IPVERSION) {
        return session->protocol == pkt->ipPackage->protocol
               && session->srcAddr.ip4 == pkt->ipPackage->srcAddr.ip4
               && session->dstAddr.ip4 == pkt->ipPackage->dstAddr.ip4
               && session->sPort == pkt->sPort
               && session->dPort == pkt->dPort;
    } else if (pkt->ipPackage->version == IPV6_VERSION) {
        return session->protocol == pkt->ipPackage->protocol
               && ipv6_addr_cmp(&session->srcAddr.ip6, &pkt->ipPackage->srcAddr.ip6) == 0
               && ipv6_addr_cmp(&session->dstAddr.ip6, &pkt->ipPackage->dstAddr.ip6) == 0
               && session->sPort == pkt->sPort
               && session->dPort == pkt->dPort;
    }

    return false;
}

struct SessionInfo *SessionFactory::findOrCreateSession(TransportPkt *pkt) {
    struct SessionInfo *s = mSessions;
    struct SessionInfo *curr = nullptr;
    while (s != nullptr) {
        if (matchSession(s, pkt)) {
            curr = s;
            break;
        }
        s = s->next;
    }

    if (curr == nullptr) {
        curr = createSession(pkt);
    }
    return curr;
}

//add session process
static void buildSessionProcess(SessionInfo *si) {
    switch (si->protocol) {
        case IPPROTO_ICMP: {
            auto icmp = new IcmpSession(si);
            icmp->prev = nullptr;
            si->session = icmp;

            icmp->next = nullptr;

        }
            break;
        case IPPROTO_TCP: {
            auto tcp = new TcpSession(si);
            tcp->prev = nullptr;
            si->session = tcp;
            tcp->next = nullptr;

//            if (si->dPort == 80) {
//                auto http = new HttpSession(si);
//                http->prev = tcp;
//                http->next = nullptr;
//
//                tcp->next = http;
//            }
//            else if (si->dPort == 443) {
//                auto tls = new TlsSession(si);
//                auto http = new HttpSession(si);
//                tls->next = http;
//                http->next = nullptr;
//                tls->prev = tcp;
//                http->prev = tls;
//
//                tcp->next = tls;
//            }
//            else {
//                tcp->next = nullptr;
//            }
        }
            break;
        case IPPROTO_UDP: {
            auto udp = new UdpSession(si);
            udp->prev = nullptr;
            si->session = udp;

            udp->next = nullptr;

//            if (si->dPort == 53) {
//                auto dns = new DnsSession(si);
//                dns->next = nullptr;
//                dns->prev = udp;
//
//                udp->next = dns;
//            } else {
//                udp->next = nullptr;
//            }
        }
            break;
        default:
            break;
    }
}


struct SessionInfo *SessionFactory::createSession(TransportPkt *pkt) {
//    if (mSessionCount >= mMaxSessionSize) {
//        ALOGW("reach max session size limit, can not create session");
//        return nullptr;
//    }

    struct SessionInfo *s = new SessionInfo();
    s->next = mSessions;
    mSessions = s;

    IpPackage *ip = pkt->ipPackage;
    s->version = ip->version;
    s->dstAddr = ip->dstAddr;
    s->srcAddr = ip->srcAddr;
    s->protocol = ip->protocol;
    s->version = ip->version;
    s->context = ip->handler->getProxyContext();
    s->ipHandler = ip->handler;

    s->sPort = pkt->sPort;
    s->dPort = pkt->dPort;
    s->transportHandler = pkt->handler;

    s->lastActive = time(nullptr);
    s->tData = s->transportHandler->createStatusData(s, pkt);

    buildSessionProcess(s);


    ALOGV("create session %p / %p", s, s->tData);

    mSessionCount++;
    return s;
}

void SessionFactory::freeSession(SessionInfo *si) {
    if (si != nullptr) {
        ALOGI("free session %p / %p", si, si->tData);

        SessionInfo *s = mSessions;
        SessionInfo *ps = nullptr;
        while (s != nullptr && s != si) {
            ps = s;
            s = s->next;
        }

        if (s == si) {
            //find si in session link
            if (mSessions == si) {
                mSessions = si->next;
            } else {
                //ps never be nullptr
                ps->next = si->next;
            }

            mSessionCount--;
        } else {
            ALOGE("session find error");
        }

        //free session
        if (si->tData != nullptr && si->transportHandler != nullptr) {
            si->transportHandler->freeStatusData(si);
            si->tData = nullptr;
        }

        auto ss = si->session;
        while (ss != nullptr) {
            auto ssTmp = ss;
            ss = ss->next;

            ssTmp->releaseResource(si);
            delete ssTmp;
        }

        delete si;
    } else {
        ALOGE("freeSession free nullptr");
    }


}

SessionInfo *SessionFactory::getSessions() const {
    return mSessions;
}

int SessionFactory::getSessionCount() const {
    return mSessionCount;
}
