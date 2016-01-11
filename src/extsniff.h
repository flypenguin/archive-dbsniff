#ifndef extsniff_h
#define extsniff_h

/*
 * THIS COPYRIGHT NOTICE IS NECESSARY BECAUSE THIS APPLICATION IS A MODIFICATION
 * OF AN EXAMPLE PROGRAM OF WINPCAP.
 * MOST PARTS HAVE BEEN REWRITTEN, THOUGH :-)
 *
 * ALL REWRITTEN / ADDED PARTS ARE (c) AXEL BOCK, AND - AS FAR AS LEGALLY 
 * POSSIBLE - GPL RESTRICTIONS APPLY.
 *
 * Copyright (c) 1999 - 2002
 *  Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
   the tcp header format:
   
    0               1               2               3  
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   remember: data_offset = header length in number of 32BIT (!!) words

*/
/*
   the ip header format:
   
    0               1               2               3  
    0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   remember: IHL = header length in number of 32BIT (!!) words, min = 5 !!

*/
 
#ifdef WIN32
#include <winsock2.h>
#else 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

//#include "pcap.h"

#define TCP_PROTOCOL 0x06 // (dec  6)
#define UDP_PROTOCOL 0x11 // (dec 17)

#define PROTO_MAIL_POP       110
#define PROTO_MAIL_IMAP      143
#define PROTO_MAIL_IMAPS     993
#define PROTO_HTTP            80
#define PROTO_HTTPS          443
#define PROTO_JBF           1083
#define PROTO_SMB            445
#define PROTO_FTP_1           21
#define PROTO_FTP_2           22
#define PROTO_SSH             25

#define bytes_tcp_in  0
#define bytes_tcp_out 1
#define bytes_udp_in  2
#define bytes_udp_out 3
#define pckts_tcp_in  4
#define pckts_tcp_out 5
#define pckts_udp_in  6
#define pckts_udp_out 7

#define BTI bytes_tcp_in
#define BTO bytes_tcp_out
#define BUI bytes_udp_in
#define BUO bytes_udp_out
#define PTI pckts_tcp_in
#define PTO pckts_tcp_out
#define PUI pckts_udp_in
#define PUO pckts_udp_out


/* structs for key und value of the database */

#pragma pack(1)
typedef struct db_key{
    unsigned int    timestamp;
    unsigned int    port;
    unsigned int    IP;
}db_key;

typedef struct db_val{
    unsigned int    values[8];                 // is: tcp_bytes_in  0
                                               //        _bytes_out 1
                                               //     udp_bytes_in  2
                                               //        _bytes_out 3
                                               //     tcp_pckts_in  4
                                               //        _pckts out 5
                                               //     udp_pckts_in  6
                                               //        _pckts_out 7
}db_val;
#pragma pack()


/* structs for the different network headers */


/* the following code is from winpcap */
/* 4 bytes IP address */
#pragma pack(1)
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;
#pragma pack()


/* IPv4 header */
#pragma pack(1)
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;   // Source address
    struct in_addr daddr;   // Destination address
    u_int       op_pad;     // Option + Padding
}ip_header;
#pragma pack()

/* TCP header */
#pragma pack(1)
typedef struct tcp_header{
    u_short sport;
    u_short dport;
    u_int   seq_no;
    u_int   ack_no;
    u_char  data_offset;
    u_char  flags;
    u_short window;
    u_short checksum;
    u_short urgent;
    u_int   options;
    u_char  *data;
}tcp_header;  
#pragma pack()

/* UDP header*/
#pragma pack(1)
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;
#pragma pack()



#endif
