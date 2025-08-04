#include "sniffer.h"    
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>


static pcap_t *handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];

int snf_open(const char *dev, int snaplen, int promsc, int ms) {
    
    handle = pcap_open_live(dev, snaplen, promsc, ms, errbuf);
    
    return handle ? 0 : -1;
}

void snf_close(void) {
    if(handle) {
        pcap_close(handle);
        handle = NULL;
    }
}


int snf_next_pkt(char **summary, char **detail) {

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int r = pcap_next_ex(handle, &hdr, &data);

    //returns 0 for timeout, -1/-2 for errors
    if(r != 1) {
        return r;
    }

    //summary
    char *sum = malloc(64);
    snprintf(sum, 64,"len=%u first=%02x%02x%02x%02x…", hdr->len, data[0], data[1], data[2], data[3] );

    //raw
    int max = 64;
    if(hdr->len > 64) {
        max = 64;
    } else {
        max = hdr->len;
    }

    char *det = malloc(max * 3 + 1);

    for (int i = 0; i < max; i++)
    {
        sprintf(det + i * 3, "%02x", data[i]);
    }

    *summary = sum;
    *detail  = det;
    return  1;
    



}