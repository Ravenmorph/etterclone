#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <errno.h>

#include "netinfo.h"



/* Read MAC for an interface name using ioctl SIOCGIFHWADDR (Linux) */
static int get_mac_ioctl(const char *ifname, char *mac_str, size_t mac_str_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return -1;
    }
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    mac_to_str(mac, mac_str, mac_str_len);
    close(fd);
    return 0;
}