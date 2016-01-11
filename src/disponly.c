/* 
 * display only mode
 * will dispay the header information of each packet
 */

/* globals and private definitions for ext_throughput_handler */

#include "inc_pcap.h"

#include "extsniff.h"
#include "params.h"

#include "tp_ext.h"
#include "pack_decode.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

static char PF[] = "      \0";
static struct timeval start_time;
static struct timeval last_time;



/** 
 * displays (almost) all header information available in a tcp/udp packet
 * header on screen.
 */
void
disp_only_handler(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
	struct timeval since_start;
	struct timeval since_last;
    ip_header      *ih;
    tcp_header     *th;
    udp_header     *uh;
    packet_info     pi;

    if (!decode_packet(pkt_data, &ih, &th, &uh)) return;
	fill_packet_info(ih, th, uh, &pi);

	if (pi.protocol != PROT_TCP && pi.protocol != PROT_UDP)
        return;

	// calculate "relative" time - time elapsed since first packet
	since_start.tv_usec = header->ts.tv_usec - start_time.tv_usec;
	if (since_start.tv_usec < 0)
	{
		since_start.tv_usec *= -1;	// make positive;
		since_start.tv_sec = -1;    // subtract one
		since_start.tv_sec += header->ts.tv_sec - start_time.tv_sec;
	}
	else 
		since_start.tv_sec = header->ts.tv_sec - start_time.tv_sec;

    // calculate time since last packet
	since_last.tv_usec = header->ts.tv_usec - last_time.tv_usec;
	if (since_last.tv_usec < 0)
	{
		since_last.tv_usec *= -1;	// make positive;
		since_last.tv_sec = -1;    // subtract one
		since_last.tv_sec += header->ts.tv_sec - last_time.tv_sec;
	}
	else 
		since_last.tv_sec = header->ts.tv_sec - last_time.tv_sec;
	last_time.tv_sec = header->ts.tv_sec;
	last_time.tv_usec = header->ts.tv_usec;

	// prints sec.msec sec.msec (abs, rel)
	fprintf(STDOUT, "%lu.%6.6lu%s%lu.%6.6lu%s", 
		header->ts.tv_sec, header->ts.tv_usec, Separat,
		since_start.tv_sec, since_start.tv_usec, Separat);
	// prints sec.msec (since last)
	if (FlagScreenAdd > 0)
		fprintf(STDOUT, "%lu.%6.6lu%s", 
			since_last.tv_sec, since_last.tv_usec, Separat);
    // ... src-addr.src-port
	fprintf(STDOUT, "%15s.%-5u%s",
        inet_ntoa(pi.src_addr), pi.src_port, Separat);
	// ... dst-addr.dst-port ttl
    fprintf(STDOUT, "%15s.%-5u%s%3u%s", 
        inet_ntoa(pi.dst_addr), pi.dst_port, Separat, 
        pi.ttl, Separat);
    if (pi.protocol == PROT_TCP)
    {
		// packet-length payload-length win seq ack
        fprintf(STDOUT, "T%s%5u%s%5u%s%5u%s%10u%s%10u%s", 
            Separat,
            pi.len, Separat, pi.paylen, Separat, 
            pi.win, Separat, pi.seq,    Separat,
            pi.ack, Separat);
		// prints Fin Syn Rst Psh Ack Urg (only 1st letter, or ".")
        if (pi.fin) PF[0]='F'; else PF[0]='.'; 
        if (pi.syn) PF[1]='S'; else PF[1]='.'; 
        if (pi.rst) PF[2]='R'; else PF[2]='.'; 
        if (pi.psh) PF[3]='P'; else PF[3]='.'; 
        if (pi.ack) PF[4]='A'; else PF[4]='.'; 
        if (pi.urg) PF[5]='U'; else PF[5]='.'; 
        fprintf(STDOUT, "%s\n", PF);
    }
	else if (pi.protocol == PROT_UDP)
    {
		// ... packet-length payload-length
        fprintf(STDOUT, "U%s%5u%s%5u\n", 
            Separat,
            pi.len, Separat, pi.paylen);
    }
	else
	{
		// ... packet-length payload-length
        fprintf(STDOUT, "O%s%5u", 
            Separat,
            pi.len);
	}
}

/** 
 * wrapper for disp_content_handler. sets the start time of the first packet seen.
 */
void
disp_only_handler_first(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
	start_time.tv_sec = header->ts.tv_sec;
	start_time.tv_usec = header->ts.tv_usec;
	last_time.tv_sec = header->ts.tv_sec;
	last_time.tv_usec = header->ts.tv_usec;
	disp_only_handler(param, header, pkt_data);
}




void
disp_content_handler(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
	ip_header      *ih;
    tcp_header     *th;
    udp_header     *uh;
    packet_info     pi;
	unsigned int	c, i;
	u_char		   *payload;
	unsigned int	paylen;
    static unsigned int p1, p2;
    static unsigned int i1, i2;

    decode_packet(pkt_data, &ih, &th, &uh);
    fill_packet_info(ih, th, uh, &pi);

    if (pi.paylen == 0) return;

	paylen = pi.paylen;
    if (th) payload = (u_char*) th + pi.tcp_hlen;
    else    payload = (u_char*) uh + 8;

    if (! (i1 == pi.src_addr.s_addr && 
        i2 == pi.dst_addr.s_addr && 
        p1 == pi.src_port && 
        p2 == pi.dst_port) )
    {
        fprintf(STDOUT, "\n\n---------- %s:%d -> ", inet_ntoa(pi.src_addr), pi.src_port);
        fprintf(STDOUT, "%s:%d ----------\n", inet_ntoa(pi.dst_addr), pi.dst_port);
        i1 = pi.src_addr.s_addr;
        i2 = pi.dst_addr.s_addr;
        p1 = pi.src_port;
        p2 = pi.dst_port;
    }
	for (i=0; i < paylen; i++)
	{
		c = *(payload + i);
		if ((c > 15 && c < 128) || c == 13 || c == 10) putc(c, STDOUT);
        else fprintf(STDOUT, "[%d]", c);
	}
    //fprintf(STDOUT, "\n");
}


void
disp_content_cleanup()
{
	fprintf(stdout, "\n");
}

void
setup_disp_only()
{
}


