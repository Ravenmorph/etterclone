#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include "sniff.h"


static pcap_t *pcap_handle = NULL;
static pcap_dumper_t *pcap_dumper = NULL;

/* Ctrl+C handler to stop capture gracefully */
static void handle_sigint(int sig) {
    (void)sig;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
}


/* simple hexdump for first n bytes */
static void small_hexdump(const u_char *data, int len, int max_bytes) {
    int to = len < max_bytes ? len : max_bytes;
    for (int i = 0; i < to; i += 16) {
        printf("%04x  ", i);
        for (int j = 0; j < 16; ++j) {
            if (i + j < to) printf("%02x ", data[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (int j = 0; j < 16 && i + j < to; ++j) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}