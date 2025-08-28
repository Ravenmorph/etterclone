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