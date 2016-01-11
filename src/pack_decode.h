#ifndef __pack_decode_h
#define __pack_decode_h

#include "extsniff.h"


#define PROT_UNK 0
#define PROT_TCP 1
#define PROT_UDP 2

typedef struct{
    unsigned int        protocol;
    struct in_addr      src_addr;
    struct in_addr      dst_addr;
    unsigned short      src_port;
    unsigned short      dst_port;
    unsigned int        len;
    unsigned int        ip_hlen;
    unsigned int        tcp_hlen;
    unsigned int        paylen;
    unsigned int        seq;
    unsigned int        ack;
    unsigned int        win;
    unsigned int        ttl;
    char                psh;
    char                rst;
    char                syn;
    char                fin;
    char                urg;
    char                ecn;
}packet_info;

int decode_packet(const u_char*, ip_header**, tcp_header**, udp_header**);

void print_packet_info(ip_header *, tcp_header *, udp_header *);

void fill_packet_info(ip_header *, tcp_header *, udp_header *, packet_info *);


#endif
