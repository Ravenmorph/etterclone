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