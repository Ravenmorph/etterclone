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