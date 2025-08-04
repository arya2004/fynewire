#pragma once
#include <pcap/pcap.h>


int snf_open(const char *dev, int snaplen, int promisc, int mc);
void snf_close(void);
int snf_next_pkt(char **summary, char **detail);
