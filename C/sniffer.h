#pragma once
#include <pcap/pcap.h>


int  snf_open(const char *dev, int snaplen, int promisc, int to_ms);
int  snf_next_pkt(char **summary, char **detail);   /* 1 = pkt, 0 timeout, <0 err */
void snf_close(void);