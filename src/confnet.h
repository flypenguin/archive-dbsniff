#ifndef __confnet_h
#define __confnet_h

extern pcap_t        *adhandle;

extern unsigned int   NetMask;                 // both will be extracted from
extern unsigned int   OurHost;                 // interface information ...


void
setup_sniff();

void
list_net_devices();

#endif
