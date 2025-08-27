#include <unistd.h>   // for getuid()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netinfo.h"  // your W1 module
#include "sniff.h"

int main(int argc, char **argv) {
    printf("W2: capture tool\n\n");

    /* Option A: take device from argv[1], filter from argv[2], out file argv[3]
       Usage: sudo ./etterclone_w2 <interface> "<bpf filter>" <out.pcap>
       Example: sudo ./etterclone_w2 wlp2s0 "not udp port 5353 and not udp port 1900" capture.pcap
    */
    if (argc < 4) {
        printf("Usage: sudo %s <interface> \"<bpf filter>\" <out.pcap>\n", argv[0]);
        printf("Example filters:\n");
        printf("  \"udp port 53\"                 (DNS only)\n");
        printf("  \"tcp port 443 or udp port 443\" (HTTPS/QUIC-ish)\n");
        printf("  \"not (udp port 5353 or udp port 5355 or udp port 1900)\"  (exclude mDNS/LLMNR/SSDP noise)\n\n");
        printf("Available interfaces (from W1):\n");
        list_interfaces_and_print();   /* show interfaces discovered in W1 */
        return 1;
    }

    const char *dev = argv[1];
    const char *filter = argv[2];
    const char *out = argv[3];
    int snaplen = 65535;

    if (getuid() != 0) {
        fprintf(stderr, "Warning: usually you should run this as root for capturing on interfaces.\n");
    }

    if (start_capture(dev, filter, out, snaplen) != 0) {
        fprintf(stderr, "Capture failed\n");
        return 1;
    }

    printf("Capture finished. Saved to %s\n", out);
    return 0;
}
