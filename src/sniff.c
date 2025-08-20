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

/* callback called by pcap_loop for each captured packet */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    /* write to pcap file */
    if (pcap_dumper) pcap_dump((u_char *)pcap_dumper, h, bytes);

    /* one-line summary */
    time_t t = h->ts.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &tm);
    printf("[%s.%06ld] len=%u cap=%u\n", timestr, (long)h->ts.tv_usec, (unsigned)h->len, (unsigned)h->caplen);

    /* print small hex-dump of first 128 bytes */
    int max_bytes = 128;
    small_hexdump(bytes, (int)h->caplen, max_bytes);

    printf("\n");
}