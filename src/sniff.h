#ifndef SNIFF_H
#define SNIFF_H

int start_capture(const char *dev, const char *bpf_filter, const char *out_pcap, int snaplen);

#endif
