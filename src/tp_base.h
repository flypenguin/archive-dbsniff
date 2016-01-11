#ifndef __tp_base_h
#define __tp_base_h

void
std_tp_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
void
std_tp_handler_first(u_char*, const struct pcap_pkthdr*, const u_char*);

void
win_tp_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

void setup_throughput();
void std_tp_handler_last();


#pragma pack(1)
typedef struct {
    time_t       time;
    unsigned int bps;
    unsigned int pps;
}TPData;
#pragma pack()


#endif
