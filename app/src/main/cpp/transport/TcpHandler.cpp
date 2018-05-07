//
// Created by Rqg on 09/04/2018.
//

#include <netinet/tcp.h>
#include <linux/in.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <cstring>

#include "TcpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../log.h"
#include "../BufferPool.h"


#define LOG_TAG "TcpHandler"


struct segment {
    uint32_t seq;
    uint16_t len;
    uint16_t sent;
    int psh;
    uint8_t *data;
    struct segment *next;
};

struct TcpStatus {
    int socket;
    bool stop;

    uint16_t mss;
    uint8_t recv_scale;
    uint8_t send_scale;
    uint32_t recv_window; // host notation, scaled
    uint32_t send_window; // host notation, scaled

    uint32_t remote_seq; // confirmed bytes received, host notation
    uint32_t local_seq; // confirmed bytes sent, host notation
    uint32_t remote_start;
    uint32_t local_start;

    uint32_t acked; // host notation
    long long last_keep_alive;

    uint64_t sent;
    uint64_t received;
    uint8_t state;
    struct segment *forward;
};


TcpHandler::TcpHandler() {}

TcpHandler::~TcpHandler() {

}

TransportPkt *TcpHandler::handleIpPkt(IpPackage *pkt) {
    if (pkt == nullptr || pkt->protocol != IPPROTO_TCP)
        return nullptr;

    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->payload);

    if (tcphdr->urg) {
        ALOGW("drop URG data");
        return nullptr;
    }

    TransportPkt *tPkt = new TransportPkt();
    tPkt->ipPackage = pkt;
    tPkt->handler = this;
    tPkt->sPort = ntohs(tcphdr->source);
    tPkt->dPort = ntohs(tcphdr->dest);
    size_t tcpHdrSize = sizeof(struct tcphdr);
    tPkt->payloadSize = pkt->payloadSize - tcpHdrSize;
    tPkt->payload = pkt->payload + tcpHdrSize;

    return tPkt;
}

void getPackageStr(TransportPkt *pkt, struct TcpStatus *status, char *pktStr) {
    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->ipPackage->payload);


    char flags[10];
    int flen = 0;
    if (tcphdr->syn)
        flags[flen++] = 'S';
    if (tcphdr->ack)
        flags[flen++] = 'A';
    if (tcphdr->psh)
        flags[flen++] = 'P';
    if (tcphdr->fin)
        flags[flen++] = 'F';
    if (tcphdr->rst)
        flags[flen++] = 'R';
    if (tcphdr->urg)
        flags[flen++] = 'U';
    flags[flen] = 0;

    ADDR_TO_STR(pkt->ipPackage);


    sprintf(pktStr,
            "TCP %s %s/%u > %s/%u seq %u ack %u data %lu win %u",
            flags,
            source, ntohs(tcphdr->source),
            dest, ntohs(tcphdr->dest),
            ntohl(tcphdr->seq) - (status == NULL ? 0 : status->remote_start),
            tcphdr->ack ? ntohl(tcphdr->ack_seq) - (status == NULL ? 0 : status->local_start) : 0,
            pkt->ipPackage->payloadSize, ntohs(tcphdr->window));
}

void TcpHandler::processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) {

    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->ipPackage->payload);
    struct TcpStatus *status = reinterpret_cast<struct TcpStatus *>(sessionInfo->tData);


    char packet[250];
    getPackageStr(pkt, status, packet);

    ALOGD(packet);

}

uint16_t get_default_mss(ProxyContext *ctx, int version) {
    if (version == IPVERSION)
        return (uint16_t) (ctx->mtu - sizeof(struct iphdr) - sizeof(struct tcphdr));
    else
        return (uint16_t) (ctx->mtu - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));
}

void *TcpHandler::createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) {
    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(firstPkt->ipPackage->payload);

    TcpStatus *s = static_cast<TcpStatus *>(malloc(sizeof(struct TcpStatus)));
    s->stop = false;

    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    size_t tcphdrSize = sizeof(struct tcphdr);
    const uint8_t *tcpoptions = firstPkt->ipPackage->payload + tcphdrSize;
    const uint8_t *data = firstPkt->payload + tcpoptlen;
    const uint16_t datalen = static_cast<const uint16_t>(firstPkt->payloadSize - tcpoptlen);

    if (tcphdr->syn) {
        // Decode options
        // http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
        uint16_t mss = get_default_mss(sessionInfo->context, firstPkt->ipPackage->versoin);
        uint8_t ws = 0;
        int optlen = tcpoptlen;
        uint8_t *options = (uint8_t *) tcpoptions;
        while (optlen > 0) {
            uint8_t kind = *options;
            uint8_t len = *(options + 1);
            if (kind == 0) // End of options list
                break;

            if (kind == 2 && len == 4)
                mss = ntohs(*((uint16_t *) (options + 2)));

            else if (kind == 3 && len == 3)
                ws = *(options + 2);

            if (kind == 1) {
                optlen--;
                options++;
            } else {
                optlen -= len;
                options += len;
            }
        }

        char packet[250];
        getPackageStr(firstPkt, nullptr, packet);

        ALOGW("%s new session mss %u ws %u window %u", packet, mss, ws,
              ntohs(tcphdr->window) << ws);

        // Register session
        sessionInfo->protocol = IPPROTO_TCP;
        sessionInfo->lastActive = time(NULL);
        sessionInfo->ipVersoin = firstPkt->ipPackage->versoin;

        s->mss = mss;
        s->recv_scale = ws;
        s->send_scale = ws;
        s->send_window = ((uint32_t) ntohs(tcphdr->window)) << s->send_scale;
        s->remote_seq = ntohl(tcphdr->seq); // ISN remote
        s->local_seq = (uint32_t) rand(); // ISN local
        s->remote_start = s->remote_seq;
        s->local_start = s->local_seq;
        s->acked = 0;
        s->last_keep_alive = 0;
        s->sent = 0;
        s->received = 0;


        s->state = TCP_LISTEN;
        s->forward = NULL;

        if (datalen) {
            ALOGW("%s SYN data", packet);
            s->forward = reinterpret_cast<segment *>(malloc(sizeof(struct segment)));
            s->forward->seq = s->remote_seq;
            s->forward->len = datalen;
            s->forward->sent = 0;
            s->forward->psh = tcphdr->psh;
            s->forward->data = sessionInfo->context->bufferPool->allocBuffer(datalen);
//            memcpy(s->tcp.forward->data, data, datalen);
            s->forward->next = NULL;
        }

        // Open socket
        s->socket = open_tcp_socket(args, &s->tcp, redirect);
        if (s->socket < 0) {
            // Remote might retry
            free(s);
            return 0;
        }

        s->tcp.recv_window = get_receive_window(s);

        log_android(ANDROID_LOG_DEBUG, "TCP socket %d lport %d",
                    s->socket, get_local_port(s->socket));

        // Monitor events
        memset(&s->ev, 0, sizeof(struct epoll_event));
        s->ev.events = EPOLLOUT | EPOLLERR;
        s->ev.data.ptr = s;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->socket, &s->ev))
            log_android(ANDROID_LOG_ERROR, "epoll add tcp error %d: %s",
                        errno, strerror(errno));

        s->next = args->ctx->ng_session;
        args->ctx->ng_session = s;

        if (!allowed) {
            log_android(ANDROID_LOG_WARN, "%s resetting blocked session", packet);
            write_rst(args, &s->tcp);
        }
    } else {
        log_android(ANDROID_LOG_WARN, "%s unknown session", packet);

        struct tcp_session rst;
        memset(&rst, 0, sizeof(struct tcp_session));
        rst.version = 4;
        rst.local_seq = ntohl(tcphdr->ack_seq);
        rst.remote_seq = ntohl(tcphdr->seq) + datalen + (tcphdr->syn || tcphdr->fin ? 1 : 0);

        if (version == 4) {
            rst.saddr.ip4 = (__be32) ip4->saddr;
            rst.daddr.ip4 = (__be32) ip4->daddr;
        } else {
            memcpy(&rst.saddr.ip6, &ip6->ip6_src, 16);
            memcpy(&rst.daddr.ip6, &ip6->ip6_dst, 16);
        }

        rst.source = tcphdr->source;
        rst.dest = tcphdr->dest;

        write_rst(args, &rst);
        return 0;
    }

    return nullptr;
}

void TcpHandler::freeStatusData(void *data) {
}
