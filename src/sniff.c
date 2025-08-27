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


/* Start live capture on device `dev` with BPF filter `bpf_filter`, save to out_pcap.
 * snaplen is the capture snapshot length in bytes (e.g., 65535) */
int start_capture(const char *dev, const char *bpf_filter, const char *out_pcap, int snaplen) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0, mask = 0;
    struct bpf_program fp;

    if (!dev) {
        fprintf(stderr, "No device specified\n");
        return -1;
    }

    /* open device for capturing */
    pcap_handle = pcap_open_live(dev, snaplen, 1 /* promiscuous */, 1000 /* ms timeout */, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return -1;
    }

    /* get network & mask for compiling filter (best-effort) */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

    if (bpf_filter && strlen(bpf_filter) > 0) {
        if (pcap_compile(pcap_handle, &fp, bpf_filter, 1, mask) == -1) {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap_handle));
            pcap_close(pcap_handle);
            pcap_handle = NULL;
            return -1;
        }
        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap_handle));
            pcap_freecode(&fp);
            pcap_close(pcap_handle);
            pcap_handle = NULL;
            return -1;
        }
        pcap_freecode(&fp);
    }

    /* open pcap dump file */
    pcap_dumper = pcap_dump_open(pcap_handle, out_pcap);
    if (!pcap_dumper) {
        fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return -1;
    }

    /* install Ctrl+C handler */
    signal(SIGINT, handle_sigint);

    printf("Capturing on %s... Press Ctrl+C to stop.\n", dev);

    /* start packet capture loop (-1 = infinite) */
    if (pcap_loop(pcap_handle, -1, packet_handler, NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap_handle));
    }

    /* cleanup */
    if (pcap_dumper) {
        pcap_dump_close(pcap_dumper);
        pcap_dumper = NULL;
    }
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }

    return 0;
}