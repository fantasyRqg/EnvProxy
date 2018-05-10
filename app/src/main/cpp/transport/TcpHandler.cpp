//
// Created by Rqg on 09/04/2018.
//

#include <netinet/tcp.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <cstring>
#include <errno.h>
#include <bits/fcntl.h>
#include <unistd.h>

#include <asm-generic/ioctls.h>
#include <linux/sockios.h>
#include <linux/in.h>


#include "TcpHandler.h"
#include "../ip/IpHandler.h"
#include "../proxyTypes.h"
#include "../log.h"
#include "../proxyEngine.h"
#include "../util.h"

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
    bool skipFirst;
    bool socketConnected;

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


uint16_t get_default_mss(ProxyContext *ctx, int version);

int open_tcp_socket(const struct SessionInfo *sessionInfo);

int get_receive_buffer(TcpStatus *s);

uint32_t get_receive_window(TcpStatus *s);


int32_t get_local_port(const int sock);


ssize_t write_tcp(const SessionInfo *sessionInfo, const TcpStatus *status,
                  const uint8_t *data, size_t datalen,
                  int syn, int ack, int fin, int rst);

void write_rst(SessionInfo *sessionInfo, TcpStatus *status);

int writeForwardData(SessionInfo *sessionInfo, TcpStatus *status);

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
            "TCP %s %s/%u > %s/%u seq %u ack %u data %u win %u",
            flags,
            source, ntohs(tcphdr->source),
            dest, ntohs(tcphdr->dest),
            ntohl(tcphdr->seq) - (status == nullptr ? 0 : status->remote_start),
            tcphdr->ack ? ntohl(tcphdr->ack_seq) - (status == nullptr ? 0 : status->local_start)
                        : 0,
            pkt->ipPackage->payloadSize, ntohs(tcphdr->window));
}

const char *strstate(const int state) {
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

int compare_u32(uint32_t s1, uint32_t s2) {
    // https://tools.ietf.org/html/rfc1982
    if (s1 == s2)
        return 0;

    int i1 = s1;
    int i2 = s2;
    if ((i1 < i2 && i2 - i1 < 0x7FFFFFFF) ||
        (i1 > i2 && i1 - i2 > 0x7FFFFFFF))
        return -1;
    else
        return 1;
}


void queue_tcp(const SessionInfo *sessionInfo,
               const struct tcphdr *tcphdr,
               const char *str_session, TcpStatus *status,
               const uint8_t *data, uint16_t datalen) {
    uint32_t seq = ntohl(tcphdr->seq);
    if (compare_u32(seq, status->remote_seq) < 0)
        ALOGW("%s already forwarded %u..%u",
              str_session,
              seq - status->remote_start,
              seq + datalen - status->remote_start);
    else {
        struct segment *p = nullptr;
        struct segment *s = status->forward;
        while (s != nullptr && compare_u32(s->seq, seq) < 0) {
            p = s;
            s = s->next;
        }

        if (s == nullptr || compare_u32(s->seq, seq) > 0) {
//            ALOGD("%s queuing %u...%u",
//                  str_session,
//                  seq - status->remote_start,
//                  seq + datalen - status->remote_start);

            struct segment *n = reinterpret_cast<segment *>(malloc(sizeof(struct segment)));
            n->seq = seq;
            n->len = datalen;
            n->sent = 0;
            n->psh = tcphdr->psh;
            n->data = reinterpret_cast<uint8_t *>(malloc(datalen));
            memcpy(n->data, data, datalen);
            n->next = s;
            if (p == nullptr)
                status->forward = n;
            else
                p->next = n;
        } else if (s != nullptr && s->seq == seq) {
            if (s->len == datalen)
                ALOGW("%s segment already queued %u..%u",
                      str_session,
                      s->seq - status->remote_start,
                      s->seq + s->len - status->remote_start);
            else if (s->len < datalen) {
                ALOGW("%s segment smaller %u..%u > %u",
                      str_session,
                      s->seq - status->remote_start,
                      s->seq + s->len - status->remote_start,
                      s->seq + datalen - status->remote_start);
                free(s->data);
                s->data = reinterpret_cast<uint8_t *>(malloc(datalen));
                memcpy(s->data, data, datalen);
            } else
                ALOGE("%s segment larger %u..%u < %u",
                      str_session,
                      s->seq - status->remote_start, s->seq + s->len - status->remote_start,
                      s->seq + datalen - status->remote_start);
        }
    }
}

int write_syn_ack(const SessionInfo *sessionInfo, TcpStatus *status) {
    if (write_tcp(sessionInfo, status, nullptr, 0, 1, 1, 0, 0) < 0) {
        status->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_ack(const SessionInfo *sessionInfo, TcpStatus *status) {
    if (write_tcp(sessionInfo, status, nullptr, 0, 0, 1, 0, 0) < 0) {
        status->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_data(const SessionInfo *sessionInfo, TcpStatus *status,
               const uint8_t *buffer, size_t length) {
    if (write_tcp(sessionInfo, status, buffer, length, 0, 1, 0, 0) < 0) {
        status->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_fin_ack(const SessionInfo *sessionInfo, TcpStatus *status) {
    if (write_tcp(sessionInfo, status, nullptr, 0, 0, 1, 1, 0) < 0) {
        status->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

void TcpHandler::processTransportPkt(SessionInfo *sessionInfo, TransportPkt *pkt) {

    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(pkt->ipPackage->payload);
    struct TcpStatus *status = reinterpret_cast<struct TcpStatus *>(sessionInfo->tData);

    char packet[250];
    getPackageStr(pkt, status, packet);

    if (status->skipFirst) {
        status->skipFirst = false;
        // first pkt handle by createStatus
        ALOGV("%s, skip first pkt process", packet);
        return;
    }

    ALOGD("%s", packet);

    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    size_t tcphdrSize = sizeof(struct tcphdr);
    const uint8_t *tcpoptions = pkt->ipPackage->payload + tcphdrSize;
    const uint8_t *data = pkt->payload + tcpoptlen;
    const uint16_t datalen = static_cast<const uint16_t>(pkt->payloadSize - tcpoptlen);


    char str_session[250];
    sprintf(str_session,
            "%s %s loc %u rem %u acked %u",
            packet,
            strstate(status->state),
            status->local_seq - status->local_start,
            status->remote_seq - status->remote_start,
            status->acked - status->local_start);

    // Session found
    if (status->state == TCP_CLOSING || status->state == TCP_CLOSE) {
        ALOGW("%s was closed", str_session);
        write_rst(sessionInfo, status);
        return;
    } else {
        int oldstate = status->state;
        uint32_t oldlocal = status->local_seq;
        uint32_t oldremote = status->remote_seq;

        ALOGD("%s handling", str_session);

        if (!tcphdr->syn)
            sessionInfo->lastActive = time(nullptr);
        status->send_window = ((uint32_t) ntohs(tcphdr->window)) << status->send_scale;

        // Do not change the order of the conditions

        // Queue data to forward
        if (datalen) {
            if (status->socket < 0) {
                ALOGE("%s data while local closed", str_session);
                write_rst(sessionInfo, status);
                return;
            }
            if (status->state == TCP_CLOSE_WAIT) {
                ALOGE("%s data while remote closed", str_session);
                write_rst(sessionInfo, status);
                return;
            }
            queue_tcp(sessionInfo, tcphdr, str_session, status, data, datalen);
        }

        if (tcphdr->rst /* +ACK */) {
            // No sequence check
            // http://tools.ietf.org/html/rfc1122#page-87
            ALOGW("%s received reset", str_session);
            status->state = TCP_CLOSING;
            return;
        } else {
            if (!tcphdr->ack || ntohl(tcphdr->ack_seq) == status->local_seq) {
                if (tcphdr->syn) {
                    ALOGW("%s repeated SYN", str_session);
                    // The socket is probably not opened yet

                } else if (tcphdr->fin /* +ACK */) {
                    if (status->state == TCP_ESTABLISHED) {
                        ALOGW("%s FIN received", str_session);
                        if (status->forward == nullptr) {
                            status->remote_seq++; // remote FIN
                            if (write_ack(sessionInfo, status) >= 0)
                                status->state = TCP_CLOSE_WAIT;
                        } else
                            status->state = TCP_CLOSE_WAIT;
                    } else if (status->state == TCP_CLOSE_WAIT) {
                        ALOGW("%s repeated FIN", str_session);
                        // The socket is probably not closed yet
                    } else if (status->state == TCP_FIN_WAIT1) {
                        ALOGW("%s last ACK", str_session);
                        status->remote_seq++; // remote FIN
                        if (write_ack(sessionInfo, status) >= 0)
                            status->state = TCP_CLOSE;
                    } else {
                        ALOGE("%s invalid FIN", str_session);
                        return;
                    }

                } else if (tcphdr->ack) {
                    status->acked = ntohl(tcphdr->ack_seq);

                    if (status->state == TCP_SYN_RECV)
                        status->state = TCP_ESTABLISHED;

                    else if (status->state == TCP_ESTABLISHED) {
                        // Do nothing
                    } else if (status->state == TCP_LAST_ACK)
                        status->state = TCP_CLOSING;

                    else if (status->state == TCP_CLOSE_WAIT) {
                        // ACK after FIN/ACK
                    } else if (status->state == TCP_FIN_WAIT1) {
                        // Do nothing
                    } else {
                        ALOGE("%s invalid state", str_session);
                        return;
                    }
                } else {
                    ALOGE("%s unknown packet", str_session);
                    return;
                }
            } else {
                uint32_t ack = ntohl(tcphdr->ack_seq);
                if ((uint32_t) (ack + 1) == status->local_seq) {
                    // Keep alive
                    if (status->state == TCP_ESTABLISHED) {
                        int on = 1;
                        if (setsockopt(status->socket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)))
                            ALOGE("%s setsockopt SO_KEEPALIVE error %d: %s",
                                  str_session, errno, strerror(errno));
                        else
                            ALOGW("%s enabled keep alive", str_session);
                    } else
                        ALOGW("%s keep alive", str_session);

                } else if (compare_u32(ack, status->local_seq) < 0) {
                    if (compare_u32(ack, status->acked) <= 0)

                        if (status->acked) {
                            ALOGW("%s repeated ACK %u/%u",
                                  str_session,
                                  ack - status->local_start,
                                  status->acked - status->local_start);
                        } else {
                            ALOGE("%s repeated ACK %u/%u",
                                  str_session,
                                  ack - status->local_start,
                                  status->acked - status->local_start);
                        }

                    else {
                        ALOGW("%s previous ACK %u",
                              str_session, ack - status->local_seq);
                        status->acked = ack;
                    }

                    return;
                } else {
                    ALOGE("%s future ACK", str_session);
                    write_rst(sessionInfo, status);
                    return;
                }
            }
        }

        if (status->state != oldstate ||
            status->local_seq != oldlocal ||
            status->remote_seq != oldremote)
            ALOGI("%s > %s loc %u rem %u",
                  str_session,
                  strstate(status->state),
                  status->local_seq - status->local_start,
                  status->remote_seq - status->remote_start);

//        writeForwardData(sessionInfo, status);
    }
}


uint32_t get_receive_window(TcpStatus *s) {
    // Get data to forward size
    uint32_t toforward = 0;
    struct segment *q = s->forward;
    while (q != nullptr) {
        toforward += (q->len - q->sent);
        q = q->next;
    }

    uint32_t window = (uint32_t) get_receive_buffer(s);

    uint32_t max = ((uint32_t) 0xFFFF) << s->recv_scale;
    if (window > max)
        window = max;

    window = (toforward < window ? window - toforward : 0);
    if ((window >> s->recv_scale) == 0)
        window = 0;

    return window;
}

int get_receive_buffer(TcpStatus *s);

int open_tcp_socket(const struct SessionInfo *sessionInfo) {
    int sock;
    int version = sessionInfo->ipVersoin;
//    if (redirect == nullptr) {
//        if (*socks5_addr && socks5_port)
//            version = (strstr(socks5_addr, ":") == nullptr ? 4 : 6);
//        else
//            version = status->version;
//    } else
//        version = (strstr(redirect->raddr, ":") == nullptr ? 4 : 6);

    // Get TCP socket
    if ((sock = socket(version == IPVERSION ? PF_INET : PF_INET6, SOCK_STREAM, 0)) < 0) {
        ALOGE("socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect

    if (!sessionInfo->context->engine->protectSocket(sock)) {
        ALOGE("protect socket fail");
        close(sock);
        return -1;
    }

    int on = 1;
    if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        ALOGE("setsockopt TCP_NODELAY error %d: %s", errno, strerror(errno));
        close(sock);
        return -1;
    }

    // Set non blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        ALOGE("fcntl socket O_NONBLOCK error %d: %s", errno, strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

uint16_t get_default_mss(ProxyContext *ctx, int version) {
    if (version == IPVERSION)
        return (uint16_t) (ctx->mtu - sizeof(struct iphdr) - sizeof(struct tcphdr));
    else
        return (uint16_t) (ctx->mtu - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));
}

int get_receive_buffer(TcpStatus *s) {
    if (s->socket < 0)
        return 0;

    // Get send buffer size
    // /proc/sys/net/core/wmem_default
    int sendbuf = 0;
    int sendbufsize = sizeof(sendbuf);
    if (getsockopt(s->socket, SOL_SOCKET, SO_SNDBUF, &sendbuf, (socklen_t *) &sendbufsize) < 0)
        ALOGW("getsockopt SO_RCVBUF %d: %s", errno, strerror(errno));

    if (sendbuf == 0)
        sendbuf = 16384; // Safe default

    // Get unsent data size
    int unsent = 0;
    if (ioctl(s->socket, SIOCOUTQ, &unsent))
        ALOGW("ioctl SIOCOUTQ %d: %s", errno, strerror(errno));

    return (unsent < sendbuf / 2 ? sendbuf / 2 - unsent : 0);
}

int32_t get_local_port(const int sock) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *) &sin, &len) < 0) {
        ALOGE("getsockname error %d: %s", errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

ssize_t write_tcp(const SessionInfo *sessionInfo, const TcpStatus *status, const uint8_t *data,
                  size_t datalen, int syn, int ack, int fin, int rst) {
    size_t len;
    u_int8_t *buffer;
    struct tcphdr *tcp;
    uint16_t csum;


    // Build packet
    int optlen = (syn ? 4 + 3 + 1 : 0);
    uint8_t *options;
    bool isIp4 = sessionInfo->ipVersoin == IPVERSION;
    if (isIp4) {
        len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen + datalen;
        buffer = static_cast<u_int8_t *>(malloc(len));
        struct iphdr *ip4 = (struct iphdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        options = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        // Build IP4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_TCP;
        ip4->saddr = sessionInfo->dstAddr.ip4;
        ip4->daddr = sessionInfo->srcAddr.ip4;

        // Calculate IP4 checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        // Calculate TCP4 checksum
        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct tcphdr) + optlen + datalen);

        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    } else {
        return -1;
//        len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen + datalen;
//        buffer = malloc(len);
//        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
//        tcp = (struct tcphdr *) (buffer + sizeof(struct ip6_hdr));
//        options = buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
//        if (datalen)
//            memcpy(buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen, data, datalen);
//
//        // Build IP6 header
//        memset(ip6, 0, sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
//        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
//        ip6->ip6_ctlun.ip6_un2_vfc = 0x60;
//        memcpy(&(ip6->ip6_src), &status->daddr.ip6, 16);
//        memcpy(&(ip6->ip6_dst), &status->saddr.ip6, 16);
//
//        // Calculate TCP6 checksum
//        struct ip6_hdr_pseudo pseudo;
//        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
//        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
//        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
//        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
//        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
//
//        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
    }


    // Build TCP header
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(sessionInfo->dPort);
    tcp->dest = htons(sessionInfo->sPort);
    tcp->seq = htonl(status->local_seq);
    tcp->ack_seq = htonl((uint32_t) (status->remote_seq));
    tcp->doff = (__u16) ((sizeof(struct tcphdr) + optlen) >> 2);
    tcp->syn = (__u16) syn;
    tcp->ack = (__u16) ack;
    tcp->fin = (__u16) fin;
    tcp->rst = (__u16) rst;
    tcp->window = htons(status->recv_window >> status->recv_scale);

    if (!tcp->ack)
        tcp->ack_seq = 0;

    // TCP options
    if (syn) {
        *(options) = 2; // MSS
        *(options + 1) = 4; // total option length
        *((uint16_t *) (options + 2)) = get_default_mss(sessionInfo->context,
                                                        sessionInfo->ipVersoin);

        *(options + 4) = 3; // window scale
        *(options + 5) = 3; // total option length
        *(options + 6) = status->recv_scale;

        *(options + 7) = 0; // End, padding
    }

    // Continue checksum
    csum = calc_checksum(csum, (uint8_t *) tcp, sizeof(struct tcphdr));
    csum = calc_checksum(csum, options, (size_t) optlen);
    csum = calc_checksum(csum, data, datalen);
    tcp->check = ~csum;


    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(isIp4 ? AF_INET : AF_INET6,
              isIp4 ? (const void *) &sessionInfo->srcAddr.ip4
                    : (const void *) &sessionInfo->srcAddr.ip6,
              source, sizeof(source));

    inet_ntop(isIp4 ? AF_INET : AF_INET6,
              isIp4 ? (const void *) &sessionInfo->dstAddr.ip4
                    : (const void *) &sessionInfo->dstAddr.ip6,
              dest, sizeof(dest));

    // Send packet
    ALOGD("TCP sending%s%s%s%s to tun %s/%u seq %u ack %u data %u",
          (tcp->syn ? " SYN" : ""),
          (tcp->ack ? " ACK" : ""),
          (tcp->fin ? " FIN" : ""),
          (tcp->rst ? " RST" : ""),
          dest, ntohs(tcp->dest),
          sessionInfo->sPort,
//          ntohl(tcp->seq) - status->local_start,
          ntohl(tcp->ack_seq) - status->remote_start,
          datalen);

    ssize_t res = write(sessionInfo->context->tunFd, buffer, len);

    // Write pcap record
    if (res < 0) {
        ALOGE("TCP write%s%s%s%s data %u error %u: %s",
              (tcp->syn ? " SYN" : ""),
              (tcp->ack ? " ACK" : ""),
              (tcp->fin ? " FIN" : ""),
              (tcp->rst ? " RST" : ""),
              datalen,
              errno, strerror((errno)));
    }


    free(buffer);

    if (res != len) {
        ALOGE("TCP write %u/%u", res, len);
        return -1;
    }

    return res;
}

void write_rst(SessionInfo *sessionInfo, TcpStatus *status) {
    // https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/
    int ack = 0;
    if (status->state == TCP_LISTEN) {
        ack = 1;
        status->remote_seq++; // SYN
    }
    write_tcp(sessionInfo, status, nullptr, 0, 0, ack, 0, 1);
    if (status->state != TCP_CLOSE)
        status->state = TCP_CLOSING;
}


uint32_t get_send_window(const TcpStatus *status) {
    uint32_t behind;
    if (status->acked <= status->local_seq)
        behind = (status->local_seq - status->acked);
    else
        behind = (0x10000 + status->local_seq - status->acked);
    uint32_t window = (behind < status->send_window ? status->send_window - behind : 0);
    return window;
}

void TcpHandler::onSocketEvent(SessionInfo *sessionInfo, epoll_event *ev) {
    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);


    int oldstate = status->state;
    uint32_t oldlocal = status->local_seq;
    uint32_t oldremote = status->remote_seq;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (sessionInfo->ipVersoin == IPVERSION) {
        inet_ntop(AF_INET, &sessionInfo->srcAddr.ip4, source, sizeof(source));
        inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &sessionInfo->srcAddr.ip6, source, sizeof(source));
        inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));
    }
    char str_session[250];
    sprintf(str_session, "TCP socket from %s/%u to %s/%u %s loc %u rem %u",
            source, sessionInfo->sPort, dest, sessionInfo->dPort,
            strstate(status->state),
            status->local_seq - status->local_start,
            status->remote_seq - status->remote_start);

    // Check socket error
    if (ev->events & EPOLLERR) {
        sessionInfo->lastActive = time(nullptr);

        int serr = 0;
        socklen_t optlen = sizeof(int);
        int err = getsockopt(status->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
        if (err < 0)
            ALOGE("%s getsockopt error %d: %s", str_session, errno, strerror(errno));
        else if (serr)
            ALOGE("%s SO_ERROR %d: %s", str_session, serr, strerror(serr));

        write_rst(sessionInfo, status);

        // Connection refused
//        if (0)
//            if (err >= 0 && (serr == ECONNREFUSED || serr == EHOSTUNREACH)) {
//                struct icmp icmp;
//                memset(&icmp, 0, sizeof(struct icmp));
//                icmp.icmp_type = ICMP_UNREACH;
//                if (serr == ECONNREFUSED)
//                    icmp.icmp_code = ICMP_UNREACH_PORT;
//                else
//                    icmp.icmp_code = ICMP_UNREACH_HOST;
//                icmp.icmp_cksum = 0;
//                icmp.icmp_cksum = ~calc_checksum(0, (const uint8_t *) &icmp, 4);
//
//                struct icmp_session sicmp;
//                memset(&sicmp, 0, sizeof(struct icmp_session));
//                sicmp.version = status->version;
//                if (status->version == 4) {
//                    sicmp.saddr.ip4 = (__be32) status->saddr.ip4;
//                    sicmp.daddr.ip4 = (__be32) status->daddr.ip4;
//                } else {
//                    memcpy(&sicmp.saddr.ip6, &status->saddr.ip6, 16);
//                    memcpy(&sicmp.daddr.ip6, &status->daddr.ip6, 16);
//                }
//
//                write_icmp(args, &sicmp, (uint8_t *) &icmp, 8);
//            }
    } else {
        // Assume socket okay
        if (status->state == TCP_LISTEN) {
            status->remote_seq++; // remote SYN
            if (write_syn_ack(sessionInfo, status) >= 0) {
                sessionInfo->lastActive = time(NULL);
                status->local_seq++; // local SYN
                status->state = TCP_SYN_RECV;
            }
            status->socketConnected = true;
            ALOGV("write tun syn act");
        } else {

            // Always forward data
            int fwd = 0;
            if (ev->events & EPOLLOUT) {
                if (writeForwardData(sessionInfo, status) > 0) {
                    fwd = 1;
                }
            }

            // Get receive window
            uint32_t window = get_receive_window(status);
            uint32_t prev = status->recv_window;
            status->recv_window = window;
            if ((prev == 0 && window > 0) || (prev > 0 && window == 0))
                ALOGW("%s recv window %u > %u", str_session, prev, window);

            // Acknowledge forwarded data
            if (fwd || (prev == 0 && window > 0)) {
                if (fwd && status->forward == nullptr && status->state == TCP_CLOSE_WAIT) {
                    ALOGW("%s confirm FIN", str_session);
                    status->remote_seq++; // remote FIN
                }
                if (write_ack(sessionInfo, status) >= 0)
                    sessionInfo->lastActive = time(nullptr);
            }

            if (status->state == TCP_ESTABLISHED || status->state == TCP_CLOSE_WAIT) {
                // Check socket read
                // Send window can be changed in the mean time
                uint32_t send_window = get_send_window(status);
                if ((ev->events & EPOLLIN) && send_window > 0) {
                    sessionInfo->lastActive = time(nullptr);

                    uint32_t buffer_size = (send_window > status->mss
                                            ? status->mss : send_window);
                    uint8_t *buffer = static_cast<uint8_t *>(malloc(buffer_size));
                    ssize_t bytes = recv(status->socket, buffer, (size_t) buffer_size, 0);
                    if (bytes < 0) {
                        // Socket error
                        ALOGE("%s recv error %d: %s", str_session, errno, strerror(errno));

                        if (errno != EINTR && errno != EAGAIN)
                            write_rst(sessionInfo, status);
                    } else if (bytes == 0) {
                        ALOGW("%s recv eof", str_session);

                        if (status->forward == nullptr) {
                            if (write_fin_ack(sessionInfo, status) >= 0) {
                                ALOGW("%s FIN sent", str_session);
                                status->local_seq++; // local FIN
                            }

                            if (status->state == TCP_ESTABLISHED)
                                status->state = TCP_FIN_WAIT1;
                            else if (status->state == TCP_CLOSE_WAIT)
                                status->state = TCP_LAST_ACK;
                            else
                                ALOGE("%s invalid close", str_session);
                        } else {
                            // There was still data to send
                            ALOGE("%s close with queue", str_session);
                            write_rst(sessionInfo, status);
                        }

                        if (close(status->socket))
                            ALOGE("%s close error %d: %s", str_session, errno, strerror(errno));
                        status->socket = -1;

                    } else {
                        // Socket read data
                        ALOGD("%s recv bytes %u", str_session, bytes);
                        status->received += bytes;

                        // Forward to tun
                        if (write_data(sessionInfo, status, buffer, (size_t) bytes) >= 0)
                            status->local_seq += bytes;
                    }
                    free(buffer);
                }
            }
        }
    }
    if (status->state != oldstate || status->local_seq != oldlocal ||
        status->remote_seq != oldremote)
        ALOGD("%s new state", str_session);
}

int writeForwardData(SessionInfo *sessionInfo, TcpStatus *status) {
    int fwdCount = 0;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (sessionInfo->ipVersoin == IPVERSION) {
        inet_ntop(AF_INET, &sessionInfo->srcAddr.ip4, source, sizeof(source));
        inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &sessionInfo->srcAddr.ip6, source, sizeof(source));
        inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));
    }
    char str_session[250];
    sprintf(str_session, "TCP socket from %s/%u to %s/%u %s loc %u rem %u",
            source, sessionInfo->sPort, dest, sessionInfo->dPort,
            strstate(status->state),
            status->local_seq - status->local_start,
            status->remote_seq - status->remote_start);


    uint32_t buffer_size = (uint32_t) get_receive_buffer(status);
    while (status->forward != nullptr &&
           status->forward->seq + status->forward->sent == status->remote_seq &&
           status->forward->len - status->forward->sent < buffer_size) {
        ALOGD("%s fwd %u...%u sent %u",
              str_session,
              status->forward->seq - status->remote_start,
              status->forward->seq + status->forward->len - status->remote_start,
              status->forward->sent);

        ssize_t sent = send(status->socket,
                            status->forward->data + status->forward->sent,
                            status->forward->len - status->forward->sent,
                            (unsigned int) (MSG_NOSIGNAL | (status->forward->psh
                                                            ? 0
                                                            : MSG_MORE)));
        if (sent < 0) {
            ALOGE("%s send error %d: %s", str_session, errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN) {
                // Retry later
                break;
            } else {
                write_rst(sessionInfo, status);
                break;
            }
        } else {
            fwdCount += sent;
            buffer_size -= sent;
            status->sent += sent;
            status->forward->sent += sent;
            status->remote_seq = status->forward->seq + status->forward->sent;

            if (status->forward->len == status->forward->sent) {
                struct segment *p = status->forward;
                status->forward = status->forward->next;
                free(p->data);
                free(p);
            } else {
                ALOGW("%s partial send %u/%u",
                      str_session, status->forward->sent, status->forward->len);
                break;
            }
        }
    }

    // Log data buffered
    struct segment *seg = status->forward;
    while (seg != nullptr) {
        ALOGW("%s queued %u...%u sent %u",
              str_session,
              seg->seq - status->remote_start,
              seg->seq + seg->len - status->remote_start,
              seg->sent);

        seg = seg->next;
    }
    return fwdCount;
}

void *TcpHandler::createStatusData(SessionInfo *sessionInfo, TransportPkt *firstPkt) {
    struct tcphdr *tcphdr = reinterpret_cast<struct tcphdr *>(firstPkt->ipPackage->payload);

    TcpStatus *status = static_cast<TcpStatus *>(malloc(sizeof(struct TcpStatus)));
    status->socketConnected = false;
    status->skipFirst = true;

    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    size_t tcphdrSize = sizeof(struct tcphdr);
    const uint8_t *tcpoptions = firstPkt->ipPackage->payload + tcphdrSize;
    const uint8_t *data = firstPkt->payload + tcpoptlen;
    const uint16_t datalen = static_cast<const uint16_t>(firstPkt->payloadSize - tcpoptlen);

    char packet[250];
    getPackageStr(firstPkt, nullptr, packet);

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


        ALOGI("%s new session mss %u ws %u window %u", packet, mss, ws,
              ntohs(tcphdr->window) << ws);

        // Register session
        sessionInfo->protocol = IPPROTO_TCP;
        sessionInfo->lastActive = time(nullptr);
        sessionInfo->ipVersoin = firstPkt->ipPackage->versoin;

        status->mss = mss;
        status->recv_scale = ws;
        status->send_scale = ws;
        status->send_window = ((uint32_t) ntohs(tcphdr->window)) << status->send_scale;
        status->remote_seq = ntohl(tcphdr->seq); // ISN remote
        status->local_seq = (uint32_t) rand(); // ISN local
        status->remote_start = status->remote_seq;
        status->local_start = status->local_seq;
        status->acked = 0;
        status->last_keep_alive = 0;
        status->sent = 0;
        status->received = 0;


        status->state = TCP_LISTEN;
        status->forward = nullptr;

        if (datalen) {
            ALOGW("%s SYN data", packet);
            status->forward = reinterpret_cast<segment *>(malloc(sizeof(struct segment)));
            status->forward->seq = status->remote_seq;
            status->forward->len = datalen;
            status->forward->sent = 0;
            status->forward->psh = tcphdr->psh;
            status->forward->data = static_cast<uint8_t *>(malloc(datalen));
            memcpy(status->forward->data, data, datalen);
            status->forward->next = nullptr;
        }

        // Open socket
        status->socket = open_tcp_socket(sessionInfo);
        if (status->socket < 0) {
            // Remote might retry
            status->state = TCP_CLOSING;
            goto createFail;
//            freeStatusData(status);
//            return nullptr;
        }

        status->recv_window = get_receive_window(status);

        ALOGD("TCP socket %d lport %d", status->socket, get_local_port(status->socket));

        // Monitor events
        memset(&sessionInfo->ev, 0, sizeof(struct epoll_event));
        sessionInfo->ev.events = EPOLLOUT | EPOLLERR;
        sessionInfo->ev.data.ptr = sessionInfo;
        if (epoll_ctl(sessionInfo->context->epollFd, EPOLL_CTL_ADD, status->socket,
                      &sessionInfo->ev)) {
            status->state = TCP_CLOSING;
            ALOGE("epoll add tcp error %d: %s", errno, strerror(errno));
            goto createFail;
        }


        // Build target address
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
//    if (redirect == nullptr) {
//        if (*socks5_addr && socks5_port) {
//            log_android(ANDROID_LOG_WARN, "TCP%d SOCKS5 to %s/%u",
//                        version, socks5_addr, socks5_port);
//
//            if (version == 4) {
//                addr4.sin_family = AF_INET;
//                inet_pton(AF_INET, socks5_addr, &addr4.sin_addr);
//                addr4.sin_port = htons(socks5_port);
//            } else {
//                addr6.sin6_family = AF_INET6;
//                inet_pton(AF_INET6, socks5_addr, &addr6.sin6_addr);
//                addr6.sin6_port = htons(socks5_port);
//            }
//        } else {
        if (sessionInfo->ipVersoin == IPVERSION) {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) sessionInfo->dstAddr.ip4;
            addr4.sin_port = htons(sessionInfo->dPort);
        } else {
            addr6.sin6_family = AF_INET6;
            memcpy(&addr6.sin6_addr, &sessionInfo->dstAddr.ip6, 16);
            addr6.sin6_port = htons(sessionInfo->dPort);
        }
//}
//    } else {
//        log_android(ANDROID_LOG_WARN, "TCP%d redirect to %s/%u",
//                    version, redirect->raddr, redirect->rport);
//
//        if (version == 4) {
//            addr4.sin_family = AF_INET;
//            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
//            addr4.sin_port = htons(redirect->rport);
//        } else {
//            addr6.sin6_family = AF_INET6;
//            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
//            addr6.sin6_port = htons(redirect->rport);
//        }
//    }

// Initiate connect
        int err = connect(status->socket,
                          (sessionInfo->ipVersoin == IPVERSION ? (const struct sockaddr *) &addr4
                                                               : (const struct sockaddr *) &addr6),
                          (socklen_t) (sessionInfo->ipVersoin == IPVERSION
                                       ? sizeof(struct sockaddr_in)
                                       : sizeof(struct sockaddr_in6)));
        if (err < 0 && errno != EINPROGRESS) {
            ALOGE("connect error %d: %s", errno, strerror(errno));
            close(status->socket);
            status->state = TCP_CLOSING;
            goto createFail;
        }

    } else {
        ALOGW("%s unknown session", packet);
        memset(status, 0, sizeof(TcpStatus));

        status->local_seq = ntohl(tcphdr->ack_seq);
        status->remote_seq = ntohl(tcphdr->seq) + datalen + (tcphdr->syn || tcphdr->fin ? 1 : 0);

        write_rst(sessionInfo, status);
        status->state = TCP_CLOSING;
        goto createFail;
//        freeStatusData(status);
//        return nullptr;
    }


    createFail:
    return status;
}

void TcpHandler::freeStatusData(void *data) {
    ALOGI("free TCP status data %p", data);

    if (data != nullptr) {
        TcpStatus *s = static_cast<TcpStatus *>(data);
        if (s->forward != nullptr) {
            segment *sf = s->forward;
            while (sf != nullptr) {
                auto tmp = sf;
                sf = sf->next;
                if (tmp->data != nullptr) {
                    free(tmp->data);
                }
                free(tmp);
            }
        }

        free(data);
    }
}

bool TcpHandler::monitorSession(SessionInfo *sessionInfo) {
    bool recheck = false;
    unsigned int events = EPOLLERR;

    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);


    if (status->state == TCP_LISTEN) {
        // Check for connected = writable
        if (status->socketConnected) {
            events = events | EPOLLOUT;
        }
        events = events | EPOLLOUT;
    } else if (status->state == TCP_ESTABLISHED || status->state == TCP_CLOSE_WAIT) {

        // Check for incoming data
        if (get_send_window(status) > 0)
            events = events | EPOLLIN;
        else {
            recheck = 1;

            long long ms = get_ms();
            if (ms - status->last_keep_alive > EPOLL_MIN_CHECK) {
                status->last_keep_alive = ms;
                ALOGW("Sending keep alive to update send window");
                status->remote_seq--;
                write_ack(sessionInfo, status);
                status->remote_seq++;
            }
        }

        // Check for outgoing data
        if (status->forward != NULL) {
            uint32_t buffer_size = (uint32_t) get_receive_buffer(status);
            if (status->forward->seq + status->forward->sent == status->remote_seq &&
                status->forward->len - status->forward->sent < buffer_size)
                events = events | EPOLLOUT;
            else
                recheck = 1;
        }
    }

    if (events != sessionInfo->ev.events) {
        sessionInfo->ev.events = events;
        if (epoll_ctl(sessionInfo->context->epollFd, EPOLL_CTL_MOD, status->socket,
                      &sessionInfo->ev)) {
            status->state = TCP_CLOSING;
            ALOGE("epoll mod tcp error %d: %s", errno, strerror(errno));
        } else
            ALOGD("epoll mod tcp socket %d in %d out %d",
                  status->socket, (events & EPOLLIN) != 0, (events & EPOLLOUT) != 0);
    }

    return recheck;
}


bool TcpHandler::isActive(SessionInfo *sessionInfo) {
    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);
    return (status->state != TCP_CLOSING && status->state != TCP_CLOSE && status->socket > 0);

}


int TcpHandler::checkSession(SessionInfo *sessionInfo) {
    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);
    time_t now = time(NULL);

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (sessionInfo->ipVersoin == IPVERSION) {
        inet_ntop(AF_INET, &sessionInfo->srcAddr.ip4, source, sizeof(source));
        inet_ntop(AF_INET, &sessionInfo->dstAddr.ip4, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &sessionInfo->srcAddr.ip6, source, sizeof(source));
        inet_ntop(AF_INET6, &sessionInfo->dstAddr.ip6, dest, sizeof(dest));
    }

    char session[250];
    sprintf(session, "TCP socket from %s/%u to %s/%u %s socket %d",
            source, sessionInfo->sPort, dest, sessionInfo->dPort,
            strstate(status->state), status->socket);

    int timeout = getTimeout(sessionInfo);

    // Check session timeout
    if (status->state != TCP_CLOSING && status->state != TCP_CLOSE &&
        sessionInfo->lastActive + timeout < now) {
        ALOGW("%s idle %ld/%d sec ", session, now - sessionInfo->lastActive, timeout);
        if (status->state == TCP_LISTEN)
            status->state = TCP_CLOSING;
        else
            write_rst(sessionInfo, status);
    }

    // Check closing sessions
    if (status->state == TCP_CLOSING) {
        // eof closes socket
        if (status->socket >= 0) {
            auto ctx = sessionInfo->context;

            if (epoll_ctl(ctx->epollFd, EPOLL_CTL_DEL, status->socket, &sessionInfo->ev)) {
                ALOGE("ICMP epoll del event error %d: %s", errno, strerror(errno));
            }

            if (close(status->socket))
                ALOGE("%s close error %d: %s", session, errno, strerror(errno));
            else
                ALOGW("%s close", session);
            status->socket = -1;
        }

        sessionInfo->lastActive = time(NULL);
        status->state = TCP_CLOSE;
    }

    if ((status->state == TCP_CLOSING || status->state == TCP_CLOSE) &&
        (status->sent || status->received)) {
//        account_usage(args, status->version, IPPROTO_TCP,
//                      dest, ntohs(status->dest), status->uid, status->sent, status->received);
        status->sent = 0;
        status->received = 0;
    }

    // Cleanup lingering sessions
//    if (status->state == TCP_CLOSE && sessionInfo->lastActive + TCP_KEEP_TIMEOUT < now)
    if (status->state == TCP_CLOSE)
        return 1;

    return 0;
}

int TcpHandler::getTimeout(SessionInfo *sessionInfo) {
    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);

    int timeout;
    if (status->state == TCP_LISTEN || status->state == TCP_SYN_RECV)
        timeout = TCP_INIT_TIMEOUT;
    else if (status->state == TCP_ESTABLISHED)
        timeout = TCP_IDLE_TIMEOUT;
    else
        timeout = TCP_CLOSE_TIMEOUT;

    auto ctx = sessionInfo->context;
    int scale = 100 - ctx->sessionCount * 100 / ctx->maxSessions;
    timeout = timeout * scale / 100;

    return timeout;
}

time_t TcpHandler::checkTimeout(SessionInfo *sessionInfo, time_t timeout, int del, time_t now) {
    TcpStatus *status = static_cast<TcpStatus *>(sessionInfo->tData);

    if (status->state != TCP_CLOSING && status->state != TCP_CLOSE && !del) {
        time_t stimeout = sessionInfo->lastActive +
                          getTimeout(sessionInfo) - now + 1;
        if (stimeout > 0 && stimeout < timeout)
            timeout = stimeout;
    }

    return timeout;
}
