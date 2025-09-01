#define _GNU_SOURCE
#include "arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* ETH_P_ARP, ETH_P_ALL */
#include <netinet/if_ether.h> /* struct ether_arp */

#define MAX_HOSTS 65536


/* Helper: get interface index and MAC & IPv4 */
static int get_iface_info(const char *ifname, int *ifindex, unsigned char mac[6], uint32_t *ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) { close(fd); return -1; }
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) { 
        // interface may not have IPv4
        *ip_addr = 0;
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *ip_addr = sin->sin_addr.s_addr;
    }

    close(fd);
    return 0;
}



/* Build an Ethernet+ARP request frame, put into buffer, return length */
static int build_arp_request(unsigned char *buf, const unsigned char src_mac[6], uint32_t src_ip, uint32_t target_ip) {
    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xff, 6);             // broadcast
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip, 4);
    memset(arp->arp_tha, 0x00, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    return sizeof(struct ether_header) + sizeof(struct ether_arp);
}


/* Build ARP reply frame (answering target_ip->target_mac with our src_mac) */
static int build_arp_reply(unsigned char *buf, const unsigned char src_mac[6], uint32_t src_ip,
                           const unsigned char target_mac[6], uint32_t target_ip) {
    struct ether_header *eth = (struct ether_header *)buf;
    memcpy(eth->ether_dhost, target_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY);

    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip, 4);
    memcpy(arp->arp_tha, target_mac, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    return sizeof(struct ether_header) + sizeof(struct ether_arp);
}


/* Convert dotted IP to uint32_t (network byte order) */
static int ip_str_to_uint32(const char *s, uint32_t *out) {
    struct in_addr a;
    if (inet_aton(s, &a) == 0) return -1;
    *out = a.s_addr;
    return 0;
}

/* Parse CIDR "10.0.2.0/24" into base IP (network byte order) and host count */
static int parse_cidr(const char *cidr, uint32_t *base_net, int *prefix_len) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    int plen = atoi(slash+1);
    if (plen < 0 || plen > 32) return -1;
    uint32_t net;
    if (ip_str_to_uint32(buf, &net) < 0) return -1;
    *base_net = net & htonl( (~0u) << (32 - plen) ); // masked network (network order)
    *prefix_len = plen;
    return 0;
}


/* Simple struct to store discovered hosts */
struct arp_entry {
    uint32_t ip; // network order
    unsigned char mac[6];
};

static void mac_to_str(const unsigned char mac[6], char *out, size_t outlen) {
    snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

/* ARP scan implementation */
int arp_scan(const char *ifname, const char *cidr, int timeout_seconds) {
    int ifindex;
    unsigned char my_mac[6];
    uint32_t my_ip;
    if (get_iface_info(ifname, &ifindex, my_mac, &my_ip) < 0) {
        fprintf(stderr, "Failed to get interface info for %s: %s\n", ifname, strerror(errno));
        return -1;
    }

    uint32_t base_net;
    int prefix;
    if (parse_cidr(cidr, &base_net, &prefix) < 0) {
        fprintf(stderr, "Invalid CIDR: %s\n", cidr);
        return -1;
    }

    int host_bits = 32 - prefix;
    if (host_bits <= 0) {
        fprintf(stderr, "CIDR too small\n");
        return -1;
    }
    uint32_t host_count = (host_bits >= 31) ? 0xFFFFFFFFu : ((1u << host_bits) - 1u);
    if (host_count > 65534) host_count = 65534; // safety


    /* Create raw socket for ARP (ETH_P_ARP) */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket"); return -1; }

    /* Bind to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock); return -1;
    }
      /* Build target IP list (skip network & broadcast) and send ARP requests */
    unsigned char buf[1500];
    uint32_t base_h = ntohl(base_net); // host-order base
    uint32_t sent_count = 0;

    // listen loop prepare: we'll poll recv after sending bursts
    fd_set readfds;
    struct timeval tv;
    time_t start = time(NULL);
    struct arp_entry *table = calloc(65536, sizeof(struct arp_entry));
    int table_count = 0;

      // Send ARP requests in batches
    for (uint32_t i = 1; i < host_count; ++i) {
        uint32_t host = base_h + i;
        uint32_t tgt = htonl(host);
        // skip our own IP (if in same net)
        if (tgt == my_ip) continue;

        int frame_len = build_arp_request(buf, my_mac, my_ip, tgt);

        struct sockaddr_ll dst;
        memset(&dst, 0, sizeof(dst));
        dst.sll_family = AF_PACKET;
        dst.sll_ifindex = ifindex;
        dst.sll_halen = ETH_ALEN;
        memset(dst.sll_addr, 0xff, 6); // broadcast

        ssize_t r = sendto(sock, buf, frame_len, 0, (struct sockaddr*)&dst, sizeof(dst));
        if (r <= 0) {
            // non-fatal
        } else {
            sent_count++;
        }

        // throttle a bit to avoid flooding
        if ((sent_count % 256) == 0) usleep(20000); // sleep 20ms every 256
        // allow early exit due to time
        if (time(NULL) - start > timeout_seconds/2) break;
    }

     // Now receive replies until timeout_seconds
    time_t deadline = start + timeout_seconds;
    while (time(NULL) < deadline) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(sock+1, &readfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(sock, &readfds)) {
            unsigned char rbuf[2048];
            ssize_t len = recvfrom(sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (len <= 0) continue;
            if (len < (ssize_t)(sizeof(struct ether_header) + sizeof(struct ether_arp))) continue;
            struct ether_header *reth = (struct ether_header *)rbuf;
            if (ntohs(reth->ether_type) != ETH_P_ARP) continue;
            struct ether_arp *rearp = (struct ether_arp *)(rbuf + sizeof(struct ether_header));
            if (ntohs(rearp->ea_hdr.ar_op) != ARPOP_REPLY) continue;

            uint32_t rip;
            memcpy(&rip, rearp->arp_spa, 4);
            // check for duplicate
            int found = 0;
            for (int k = 0; k < table_count; ++k) {
                if (table[k].ip == rip) { found = 1; break; }
            }
            if (!found) {
                memcpy(table[table_count].mac, rearp->arp_sha, 6);
                table[table_count].ip = rip;
                table_count++;
            }
        }
    }
        // Print results
    printf("ARP scan results on %s (%s/%d):\n", ifname, cidr, prefix);
    for (int i = 0; i < table_count; ++i) {
        struct in_addr a; a.s_addr = table[i].ip;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
        char macs[32];
        mac_to_str(table[i].mac, macs, sizeof(macs));
        printf("  %s -> %s\n", ipstr, macs);
    }

    free(table);
    close(sock);
    return 0;
}


/* Responder: reply to ARP requests for ip_to_answer using local MAC */
static volatile int keep_running = 1;
static void int_handler(int s) { (void)s; keep_running = 0; }

int arp_responder(const char *ifname, const char *ip_to_answer) {
    int ifindex;
    unsigned char my_mac[6];
    uint32_t my_ip;
    if (get_iface_info(ifname, &ifindex, my_mac, &my_ip) < 0) {
        fprintf(stderr, "get_iface_info failed: %s\n", strerror(errno));
        return -1;
    }