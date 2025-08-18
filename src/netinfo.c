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

/* Convert MAC bytes to printable string */
static void mac_to_str(unsigned char *mac, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

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


/* Parse /proc/net/route to find the default gateway for the interface */
static int get_default_gateway(const char *ifname, char *gw_str, size_t gw_len) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[256];

    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long dest, gateway;
        int flags, refcnt, use, metric, mask;
        if (sscanf(line, "%63s %lx %lx %X %d %d %d %lx", iface, &dest, &gateway, &flags, &refcnt, &use, &metric, &mask) >= 3) {
            if (strcmp(ifname, iface) == 0) {
                if (dest == 0) { /* default route */
                    struct in_addr gw;
                    gw.s_addr = gateway;
                    /* gateway is in hex */
                    unsigned char *b = (unsigned char *)&gateway;
                    unsigned char bytes[4] = { b[0], b[1], b[2], b[3] };
                    struct in_addr gw2;
                    gw2.s_addr = gateway;
                    /* To be safe, use inet_ntoa on a constructed addr via bytes: */
                    char buf[INET_ADDRSTRLEN];
                    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (unsigned)bytes[0], (unsigned)bytes[1], (unsigned)bytes[2], (unsigned)bytes[3]);
                    strncpy(gw_str, buf, gw_len-1);
                    gw_str[gw_len-1] = 0;
                    fclose(f);
                    return 0;
                }
            }
        }
    }
    fclose(f);
    return -1;
}


/* Main routine: list interfaces and print IPv4, MAC, flags and gateway if present */
int list_interfaces_and_print(void) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    printf("Interfaces found:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;

        /* We will print per-interface once for AF_INET entries */
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN] = {0};
            char netmask[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            if (nm) inet_ntop(AF_INET, &nm->sin_addr, netmask, sizeof(netmask));

            /* Flags */
            unsigned int flags = ifa->ifa_flags;
            printf("  %s:\n", ifa->ifa_name);
            printf("    IPv4: %s\n", ip);
            printf("    Netmask: %s\n", netmask);
            printf("    Flags: %s%s%s%s\n",
                   (flags & IFF_UP) ? "UP " : "",
                   (flags & IFF_BROADCAST) ? "BROADCAST " : "",
                   (flags & IFF_LOOPBACK) ? "LOOPBACK " : "",
                   (flags & IFF_RUNNING) ? "RUNNING " : "");

            /* MAC */
            char mac[32] = "??:??:??:??:??:??";
            if (get_mac_ioctl(ifa->ifa_name, mac, sizeof(mac)) == 0) {
                printf("    MAC: %s\n", mac);
            } else {
                printf("    MAC: (unavailable)\n");
            }

            /* Default gateway for this interface */
            char gw[INET_ADDRSTRLEN] = {0};
            if (get_default_gateway(ifa->ifa_name, gw, sizeof(gw)) == 0) {
                printf("    Default gateway: %s\n", gw);
            } else {
                printf("    Default gateway: (none)\n");
            }
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}