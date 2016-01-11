#ifndef __tp_ext_h
#define __tp_ext_h

#include <time.h>

void
ext_throughput_handler(u_char*, const struct pcap_pkthdr*, const u_char *);

void
setup_ext_throughput(char *);


#pragma pack(1)
typedef struct{
    unsigned int pack_size;
    unsigned int pack_count;
    unsigned int pack_udp_size;
    unsigned int pack_udp_count;
    unsigned int pack_push;
    unsigned int size_dist[16];
}etp_time_data;
#pragma pack()


#pragma pack(1)
typedef struct{
    time_t          time;
    unsigned int    pack_size;
	unsigned int	pay_size;
    unsigned int    pack_count;
    unsigned int    pack_udp_size;
    unsigned int    pack_udp_count;
    unsigned int    payload_dist[1501];
    unsigned int    size_dist[1501];
    unsigned int    pack_push;
    unsigned int    pack_syn; 
    unsigned int    pack_fin;
    unsigned int    pack_rst;
    unsigned int    pack_urg;
	float           avg_pck_distance;
}etp_gen_data;
#pragma pack()


#endif
