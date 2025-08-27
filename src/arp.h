#ifndef ARP_H
#define ARP_H

int arp_scan(const char *ifname, const char *cidr, int timeout_seconds);
int arp_responder(const char *ifname, const char *ip_to_answer); // run until Ctrl+C

#endif
