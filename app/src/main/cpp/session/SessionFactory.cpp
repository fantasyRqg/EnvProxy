//
// Created by Rqg on 24/04/2018.
//

#include <netinet/ip.h>
#include <cstring>
#include <netinet/ip6.h>

#include "SessionFactory.h"
#include "../proxyTypes.h"
#include "Session.h"
#include "../ip/IpHandler.h"


SessionFactory::SessionFactory(int maxSessionSize) : mMaxSessionSize(maxSessionSize),
                                                     mSessions(nullptr) {

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
    if (pkt->ipPackage->versoin != session->ipVersoin)
        return false;

    if (pkt->ipPackage->versoin == IPVERSION) {
        return session->protocol == pkt->ipPackage->protocol
               && session->srcAddr.ip4 == pkt->ipPackage->srcAddr.ip4
               && session->dstAddr.ip4 == pkt->ipPackage->dstAddr.ip4
               && session->sPort == pkt->sPort
               && session->dPort == pkt->dPort;
    } else if (pkt->ipPackage->versoin == IPV6_VERSION) {
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
//            si->session = new IcmpSession();
        }
            break;
        case IPPROTO_TCP: {
//            si->session = new TcpSession();
        }
            break;
        case IPPROTO_UDP: {
//            si->session = new UdpSession();
        }
            break;

        default:
            break;
    }
}


struct SessionInfo *SessionFactory::createSession(TransportPkt *pkt) {
    struct SessionInfo *s = new SessionInfo();
    s->next = mSessions;
    mSessions = s;

    IpPackage *ip = pkt->ipPackage;
    s->ipVersoin = ip->versoin;
    s->dstAddr = ip->dstAddr;
    s->srcAddr = ip->srcAddr;
    s->protocol = ip->protocol;
    s->ipVersoin = ip->versoin;
    s->context = ip->handler->getProxyContext();
    s->ipHandler = ip->handler;

    s->sPort = pkt->sPort;
    s->dPort = pkt->dPort;
    s->transportHandler = pkt->handler;

    s->lastActive = time(nullptr);


    buildSessionProcess(s);
    return s;
}
