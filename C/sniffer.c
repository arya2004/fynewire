/*
 *  Build:
 *      gcc -fPIC -c sniffer.c &&
 *      gcc -shared -o libsniffer.so sniffer.o -lpcap
 */
#include "sniffer.h"
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MLD_LISTENER_QUERY
#   define MLD_LISTENER_QUERY   130
#endif
#ifndef MLD_LISTENER_REPORT
#   define MLD_LISTENER_REPORT  131
#endif
#ifndef MLD_LISTENER_DONE
#   define MLD_LISTENER_DONE    132
#endif
#ifndef TH_PUSH
#   define TH_PUSH 0x08
#endif


#define HEX_DUMP_BYTES   64   /* max bytes to include in hex pane          */
#define APPEND_MIN_GROW  512  /* initial / doubling size for append()      */

static pcap_t *handle = NULL;

static void     mac_to_str(const u_char *mac, char *out);
static void     append(char **dst, size_t *cap, const char *fmt, ...);
static char    *hex_dump(const u_char *p, size_t len);
static const char *icmp6_name(uint8_t type);
static void     tcp_kv(const struct tcphdr *tcp, char *out, size_t cap);
static void     udp_kv(const struct udphdr *udp, char *out, size_t cap);

int snf_open(const char *dev, int snap, int promisc, int to_ms)
{
    char err[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, snap, promisc, to_ms, err);
    return handle ? 0 : -1;
}

int snf_next_pkt(char **summary, char **detail)
{
    struct pcap_pkthdr  *h;
    const u_char        *pkt;

    if (pcap_next_ex(handle, &h, &pkt) != 1)
        return 0;                     

    char s_buf[256]  = {0};        
    char p_view[512] = {0};            
    size_t cap = 0; *detail = NULL;   

    const struct ether_header *eth = (const struct ether_header *)pkt;
    uint16_t etype = ntohs(eth->ether_type);
    const u_char *pay = pkt + sizeof *eth;

    char smac[18], dmac[18];
    mac_to_str(eth->ether_shost, smac);
    mac_to_str(eth->ether_dhost, dmac);
    append(detail, &cap, "Ethernet src=%s dst=%s type=0x%04x\n", smac, dmac, etype);

    if (etype == ETHERTYPE_VLAN) {
        uint16_t tci = ntohs(*(uint16_t *)pay);
        etype = ntohs(*(uint16_t *)(pay + 2));
        pay  += 4;
        append(detail, &cap,
               "802.1Q vid=%u pcp=%u dei=%u\n",
               tci & 0x0FFF, (tci >> 13) & 0x07, (tci >> 12) & 0x01);
    }

    if (etype == ETHERTYPE_IP) {
        const struct ip *ip = (const struct ip *)pay;
        char src[16], dst[16];
        strcpy(src, inet_ntoa(ip->ip_src));
        strcpy(dst, inet_ntoa(ip->ip_dst));

        if (ip->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp = (const struct tcphdr *)(pay + ip->ip_hl * 4);
            snprintf(s_buf, sizeof s_buf, "IPv4 TCP %s:%u -> %s:%u",
                     src, ntohs(tcp->source), dst, ntohs(tcp->dest));
            tcp_kv(tcp, p_view, sizeof p_view);

        } else if (ip->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp = (const struct udphdr *)(pay + ip->ip_hl * 4);
            snprintf(s_buf, sizeof s_buf, "IPv4 UDP %s:%u -> %s:%u",
                     src, ntohs(udp->source), dst, ntohs(udp->dest));
            udp_kv(udp, p_view, sizeof p_view);

        } else {
            snprintf(s_buf, sizeof s_buf, "IPv4 %s -> %s proto=%u",
                     src, dst, ip->ip_p);
        }
    }

    else if (etype == ETHERTYPE_IPV6) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)pay;
        char src[46], dst[46];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof src);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof dst);

        if (ip6->ip6_nxt == IPPROTO_TCP) {
            const struct tcphdr *tcp = (const struct tcphdr *)(pay + sizeof *ip6);
            snprintf(s_buf, sizeof s_buf, "IPv6 TCP %s:%u -> %s:%u",
                     src, ntohs(tcp->source), dst, ntohs(tcp->dest));
            tcp_kv(tcp, p_view, sizeof p_view);

        } else if (ip6->ip6_nxt == IPPROTO_UDP) {
            const struct udphdr *udp = (const struct udphdr *)(pay + sizeof *ip6);
            snprintf(s_buf, sizeof s_buf, "IPv6 UDP %s:%u -> %s:%u",
                     src, ntohs(udp->source), dst, ntohs(udp->dest));
            udp_kv(udp, p_view, sizeof p_view);

        } else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
            const struct icmp6_hdr *icmp = (const struct icmp6_hdr *)(pay + sizeof *ip6);
            uint8_t type = icmp->icmp6_type, code = icmp->icmp6_code;

            snprintf(s_buf, sizeof s_buf, "IPv6 ICMPv6 %s %s -> %s",
                     icmp6_name(type), src, dst);

            if (type == ND_NEIGHBOR_SOLICIT || type == ND_NEIGHBOR_ADVERT) {
                char tgt[46];
                inet_ntop(AF_INET6, (icmp + 1), tgt, sizeof tgt);
                snprintf(p_view, sizeof p_view,
                         "protocol=ICMPv6 type=%s code=%u target=%s",
                         icmp6_name(type), code, tgt);
            } else {
                snprintf(p_view, sizeof p_view,
                         "protocol=ICMPv6 type=%s code=%u",
                         icmp6_name(type), code);
            }
        } else {
            snprintf(s_buf, sizeof s_buf, "IPv6 %s -> %s next=%u",
                     src, dst, ip6->ip6_nxt);
        }
    }

    else {
        snprintf(s_buf, sizeof s_buf, "EtherType 0x%04x len=%u", etype, h->caplen);
    }

    *summary = strdup(s_buf);
    append(detail, &cap, "%s\n", p_view);

    char *hex = hex_dump(pay, h->caplen - (size_t)(pay - pkt));
    append(detail, &cap, "%s", hex);
    free(hex);

    return 1;
}

void snf_close(void)
{
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
}

static void mac_to_str(const u_char *mac, char *out)
{
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void append(char **dst, size_t *cap, const char *fmt, ...)
{
    if (*dst == NULL) {                  
        *cap = APPEND_MIN_GROW;
        *dst = calloc(1, *cap);
    }
    size_t used = strlen(*dst);

    if (used + 256 > *cap) {
        *cap *= 2;
        *dst = realloc(*dst, *cap);
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(*dst + used, fmt, ap);      
    va_end(ap);
}

// Wireshark hex + ASCII pane (first 64 bytes) 
static char *hex_dump(const u_char *p, size_t len)
{
    size_t want  = len > HEX_DUMP_BYTES ? HEX_DUMP_BYTES : len;
    size_t lines = (want + 15) / 16;

    char *buf = calloc(1, lines * 80);   
    // 80 bytes per line is plenty    
    char line[80];

    for (size_t l = 0; l < lines; ++l) {
        size_t off   = l * 16;
        size_t chunk = want - off > 16 ? 16 : want - off;
        char *o = line;

        //hex
        for (size_t i = 0; i < 16; ++i)
            o += sprintf(o, i < chunk ? "%02x " : "   ", p[off + i]);

        //ascii
        o += sprintf(o, " |");
        for (size_t i = 0; i < 16; ++i) {
            *o++ = (i < chunk && isprint(p[off + i])) ? p[off + i] : '.';
        }
        *o++ = '|';
        *o   = '\0';

        sprintf(buf + strlen(buf), "%04zx  %s\n", off, line);
    }
    return buf;
}

static const char *icmp6_name(uint8_t t)
{
    switch (t) {
    case ND_ROUTER_SOLICIT:   return "Router_Solicit";
    case ND_ROUTER_ADVERT:    return "Router_Advert";
    case ND_NEIGHBOR_SOLICIT: return "Neighbour_Solicit";
    case ND_NEIGHBOR_ADVERT:  return "Neighbour_Advert";
    case ND_REDIRECT:         return "Redirect";
    case ICMP6_ECHO_REQUEST:  return "Echo_Request";
    case ICMP6_ECHO_REPLY:    return "Echo_Reply";
    case MLD_LISTENER_QUERY:  return "MLD_Query";
    case MLD_LISTENER_REPORT: return "MLD_Report";
    case MLD_LISTENER_DONE:   return "MLD_Done";
    default:                  return "ICMPv6";
    }
}

static void tcp_kv(const struct tcphdr *tcp, char *out, size_t cap)
{
    uint16_t f = tcp->th_flags;
    snprintf(out, cap,
        "protocol=TCP src_port=%u dst_port=%u seq=%u ack=%u "
        "flags=%s%s%s%s%s%s win=%u urp=%u",
        ntohs(tcp->source), ntohs(tcp->dest),
        ntohl(tcp->seq),     ntohl(tcp->ack_seq),
        (f & TH_SYN)  ? "SYN "  : "",
        (f & TH_ACK)  ? "ACK "  : "",
        (f & TH_FIN)  ? "FIN "  : "",
        (f & TH_RST)  ? "RST "  : "",
        (f & TH_PUSH) ? "PSH "  : "",
        (f & TH_URG)  ? "URG "  : "",
        ntohs(tcp->window), ntohs(tcp->urg_ptr));
}

static void udp_kv(const struct udphdr *udp, char *out, size_t cap)
{
    snprintf(out, cap,
        "protocol=UDP src_port=%u dst_port=%u len=%u checksum=0x%04x",
        ntohs(udp->source), ntohs(udp->dest),
        ntohs(udp->len),    ntohs(udp->check));
}
