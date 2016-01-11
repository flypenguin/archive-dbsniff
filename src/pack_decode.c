#include "inc_pcap.h"
#ifdef WIN32
#include <winsock2.h>
#endif
#include "extsniff.h"
#include "pack_decode.h"
#include "littlehelpers.h"

#include "linwrap.h"

#ifdef __cplusplus
inline
#endif
void
header_hostify(ip_header *ih, tcp_header *th, udp_header *uh)
{
    if (ih)
    {
        ih->tlen            = ntohs(ih->tlen);
        ih->identification  = ntohs(ih->identification);
        ih->flags_fo        = ntohs(ih->flags_fo);
        ih->crc             = ntohs(ih->crc);
    }
    if (th)
    {
        th->sport           = ntohs(th->sport);
        th->dport           = ntohs(th->dport);
        th->seq_no          = ntohl(th->seq_no);
        th->ack_no          = ntohl(th->ack_no);
        th->window          = ntohs(th->window);
        th->checksum        = ntohs(th->checksum);
        th->urgent          = ntohs(th->urgent);
    }
    if (uh)
    {
        uh->sport           = ntohs(uh->sport);
        uh->dport           = ntohs(uh->dport);
        uh->len             = ntohs(uh->len);
        uh->crc             = ntohs(uh->crc);
    }
}



int
decode_packet(const u_char *pkt_data,
              ip_header **IH, tcp_header **TH, udp_header **UH)
{
    ip_header      *ih = NULL;
    udp_header     *uh = NULL;
    tcp_header     *th = NULL;
    unsigned int    ip_len, ip_hlen;
	int retval = 0;

    ih      = (ip_header *) (pkt_data + 14);   // get IP header pointer
    *IH     = ih;
    ip_hlen = (ih->ver_ihl & 0xf) * 4;         // get IP header len
    ip_len  = ntohs(ih->tlen);                 // total length of the IP packet
    if (ih->proto == UDP_PROTOCOL)             // fill s-/dport with values ...
    {
        *TH     = NULL;
        uh      = ((udp_header*)((u_char*)ih + ip_hlen));
        *UH     = uh;
		retval  = 1;
    }
    else if (ih->proto == TCP_PROTOCOL)
    {
        *UH     = NULL;
        th      = ((tcp_header*)((u_char*)ih + ip_hlen));
        *TH     = th;
		retval  = 1;
	}
    header_hostify(ih, th, uh);
    return retval;
}



/* note that the headers given here have to be made host-compatible 
 * by header_hostify() !!
 */
void
print_packet_info(ip_header *ih, tcp_header *th, udp_header *uh)
{
    int sport, dport;
    char    *push = ".";
    char    *prot = "";
    int     paylen;
    if (th)      
    { 
        sport=th->sport; 
        dport=th->dport; 
        paylen = ih->tlen - ((ih->ver_ihl & 15) * 4) - (th->data_offset >> 4);
        // not at byte boundary. see http://www.networksorcery.com/enp/protocol/tcp.htm
        if (th->flags & 8) push ="P"; else push=".";
        prot="TCP";
    }
    else if (uh) 
    { 
        sport=uh->sport; 
        dport=uh->dport; 
        paylen = ih->tlen - ((ih->ver_ihl & 15) * 4) - uh->len;  
        push = "-";
        prot="UDP";
    }
    else         
    { 
        sport  = 0;
        dport  = 0; 
        paylen = 0;
        prot   = "IP ";
        push   = "-";

    }
    fprintf(stdout, "%15s -> %15s %5d > %5d  %s %s  len:%d pay:%d\n", 
        inet_ntoa(ih->saddr),
        inet_ntoa(ih->daddr),
        sport, dport,
        prot, push,
        ih->tlen, paylen);
}


void
fill_packet_info(ip_header *ih, tcp_header *th, udp_header *uh, packet_info *pi)
{
    unsigned int tlen;

    //print_hex_dump((unsigned char*)&(ih->saddr), 16);
    *((unsigned int*)&(pi->src_addr)) = *((unsigned int*)&(ih->saddr)); 
    *((unsigned int*)&(pi->dst_addr)) = *((unsigned int*)&(ih->daddr));
    pi->ttl     = ih->ttl;
    pi->len     = ih->tlen;
    pi->ip_hlen = (ih->ver_ihl & 15) * 4;

    tlen = ih->tlen;
    if (uh)
    {
        pi->protocol = PROT_UDP;
        pi->dst_port = uh->dport;
        pi->src_port = uh->sport;
        pi->paylen   = tlen - pi->ip_hlen - 8;
    }
    else if (th)
    {
        pi->protocol    = PROT_TCP;
        pi->dst_port    = th->dport;
        pi->src_port    = th->sport;
        pi->tcp_hlen    = ((th->data_offset & 240) / 4);
        pi->paylen      = tlen - pi->ip_hlen - pi->tcp_hlen;
        pi->seq         = th->seq_no;
        if (th->flags & 16) pi->ack = th->ack_no;
        else                pi->ack = 0;
        pi->win         = th->window;
        pi->fin         = th->flags & 1;
        pi->syn         = th->flags & 2;
        pi->rst         = th->flags & 4;
        pi->psh         = th->flags & 8;
        pi->urg         = th->flags & 32;
    }
    else
    {
        pi->protocol = PROT_UNK;
        return;
    }
}


