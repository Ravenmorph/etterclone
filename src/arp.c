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