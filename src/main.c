// src/main.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netinfo.h"  // W1
#include "sniff.h"    // W2 (start_capture)
#include "arp.h"      // W3 (arp_scan, arp_responder)

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s sniff <iface> <bpf filter> <out.pcap>\n", argv[0]);
        fprintf(stderr, "  %s scan <iface> <cidr> <timeout>\n", argv[0]);
        fprintf(stderr, "  %s responder <iface> <ip>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "sniff") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s sniff <iface> \"<bpf filter>\" <out.pcap>\n", argv[0]);
            list_interfaces_and_print();
            return 1;
        }
        const char *dev = argv[2];
        const char *filter = argv[3];
        const char *out = argv[4];
        int snaplen = 65535;

        if (geteuid() != 0) {
            fprintf(stderr, "Warning: usually you should run this as root for capturing on interfaces.\n");
        }

        if (start_capture(dev, filter, out, snaplen) != 0) {
            fprintf(stderr, "Capture failed\n");
            return 1;
        }
        printf("Capture finished. Saved to %s\n", out);
        return 0;
    }

    else if (strcmp(argv[1], "scan") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s scan <iface> <cidr> <timeout>\n", argv[0]);
            return 1;
        }
        const char *iface = argv[2];
        const char *cidr = argv[3];
        int timeout = atoi(argv[4]);
        return arp_scan(iface, cidr, timeout);
    }

    else if (strcmp(argv[1], "responder") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s responder <iface> <ip>\n", argv[0]);
            return 1;
        }
        const char *iface = argv[2];
        const char *ip = argv[3];
        return arp_responder(iface, ip);
    }

    else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }
}

