/* extended throughput mode
 *
 * time-base logged:
 *
 *     - packets (number)
 *     - packets (size)
 *     - packets (size distribution % 100)
 *
 * logged in general:
 *
 *     - packets (number)
 *     - packets (size)
 *     - packets (size distribution)
 *    (- TTL)
 */

/* globals and private definitions for ext_throughput_handler */

#include "inc_pcap.h"
#include <assert.h>

#include "extsniff.h"
#include "params.h"

#include "tp_ext.h"
#include "pack_decode.h"

#include "linwrap.h"

extern char           *IP;
extern unsigned int    IPnum;

static FILE    *tpfile = NULL;
etp_time_data   tp_data_time[2];
etp_gen_data    tp_data_gen[2];
int             etpIP;
time_t          time_dot;
time_t          time_now;


static void
safe_exit(void)
{
    size_t tmp;
    fprintf(stderr, "tp_ext.c: safe_exit called\n");
    tp_data_gen[1].time = time(NULL);
    time_dot += TimeSpan;
    // den letzten datensatz noch schreiben. der vollständigkeit halber ... 
	if (tpfile)
    {
        tmp  = fwrite((void*)&time_dot, sizeof(time_dot), 1, tpfile);
        tmp += fwrite((void*)&(tp_data_time[0]), sizeof(etp_time_data), 1, tpfile);
        tmp += fwrite((void*)&(tp_data_time[1]), sizeof(etp_time_data), 1, tpfile);
        if (tmp != 3)
            fprintf(stderr, "\n\nWARNING: save file corrupt. will be unusable!\n\n");
        // hier NICHT sizeof(tp_data_gen) angeben, das ist - weil array - genau
        // doppelt so gross wie's sein sollte (genau wie unten. vorsicht also!)
        tmp  = fwrite((void*)&(tp_data_gen[0]), sizeof(etp_gen_data), 1, tpfile);
        tmp += fwrite((void*)&(tp_data_gen[1]), sizeof(etp_gen_data), 1, tpfile);
        if (tmp != 2)
            fprintf(stderr, "\n\nWARNING: save file corrupt. will be unusable!\n\n");
        fprintf(stderr, "%s written.\n", DBFile);
    }
    fprintf(stderr, "\nSUMMARY;\n\n");
    fprintf(stderr, "Start time: %s\n", ctime(&(tp_data_gen[0].time)));
    fprintf(stderr, "End   time: %s\n", ctime(&(tp_data_gen[1].time)));
    fprintf(stderr, "%15s %15s %15s %15s\n", "", "OUT", "IN", "SUM");
    fprintf(stderr, "%15s %15d %15d %15d\n", "#pckts", 
        tp_data_gen[0].pack_count, tp_data_gen[1].pack_count,
        tp_data_gen[0].pack_count + tp_data_gen[1].pack_count);
    fprintf(stderr, "%15s %15d %15d %15d\n", "pckt_size", 
        tp_data_gen[0].pack_size, tp_data_gen[1].pack_size,
        tp_data_gen[0].pack_size + tp_data_gen[1].pack_size);
    fprintf(stderr, "%15s %15d %15d %15d\n", "#PSH pckts", 
        tp_data_gen[0].pack_push, tp_data_gen[1].pack_push,
        tp_data_gen[0].pack_push + tp_data_gen[1].pack_push);
    fprintf(stderr, "\n");
    fflush(tpfile);
    fclose(tpfile);
}



void
ext_throughput_handler(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
    ip_header      *ih;
    tcp_header     *th;
    udp_header     *uh;
    size_t          tmp;
    int             payload;
    int             push;
    int             inout;
    
    time_now = header->ts.tv_sec;
    if (time_now - time_dot > TimeSpan)             // are we in new interval?
    {
        time_dot += TimeSpan;
        tmp  = fwrite((void*)&time_dot, sizeof(time_dot), 1, tpfile);
        // hier NICHT sizeof(tp_data_time) angeben, das ist - weil array - genau
        // doppelt so gross wie's sein sollte ... :-)
        tmp += fwrite((void*)&(tp_data_time[0]), sizeof(etp_time_data), 1, tpfile);
        tmp += fwrite((void*)&(tp_data_time[1]), sizeof(etp_time_data), 1, tpfile);
        if (tmp != 3)
        {
            fprintf(stderr,
                "ERROR:\n\terror in writing data set.\n\texiting\n\n");
            exit(-1);
        }
        memset(&tp_data_time, 0, sizeof(tp_data_time));
        time_dot  = time_now;
        time_dot -= (time_dot % TimeSpan);
   }
    if (!decode_packet(pkt_data, &ih, &th, &uh))
    {
        fprintf(stderr, "WARNING: illegal packet encountered!\n");
        return;
    }
    if (FlagScreenAdd)
        print_packet_info(ih, th, uh);
    if (th)
    {
        payload = ih->tlen - (th->data_offset & 240);
        // not at byte boundary. see http://www.networksorcery.com/enp/protocol/tcp.htm
        push = th->flags & 8;
    }
    else if (uh)
    {
        payload = ih->tlen - 8;
        push    = 0;
    }
    else
    {
        fprintf(stderr, "\nERROR:\npacket unhandled state!\nexiting.\n\n");
        exit(-1);
    }
    // determine whether it's in or out
    if (*((unsigned int*)&(ih->saddr)) == IPnum)
        inout = 0;
    else
        inout = 1;
    // time based size distribution
    tmp = ih->tlen / 100 + 1;
    if (tmp > 16) tmp = 16;
    tp_data_time[inout].size_dist[tmp] += 1;
    // size distribution in detail, general
    if (ih->tlen > 1500) tmp = 1500;
    else                 tmp = ih->tlen;
    tp_data_gen[inout].size_dist[tmp] += 1;
    // size and packet count, both
    tp_data_gen[inout].pack_count++;
    tp_data_time[inout].pack_count++;
    tp_data_gen[inout].pack_size += payload;
    tp_data_time[inout].pack_size += payload;
    // push packets, general and time based
    if (push)
    {
        tp_data_gen[inout].pack_push++;
        tp_data_time[inout].pack_push++;
    }
    if (push) tp_data_time[inout].pack_push++;
    if (uh)
    {
        tp_data_gen[inout].pack_udp_size += payload;
        tp_data_gen[inout].pack_udp_count++;
        tp_data_time[inout].pack_udp_size += payload;
        tp_data_time[inout].pack_udp_count++;
    }
}



void
setup_ext_throughput(char *filename)
{
    assert(sizeof(time_t) == 4);
    tpfile = fopen(DBFile, "wb");
    if (!tpfile)
    {
        fprintf(stderr, "unable to open data file %s\n\n", DBFile);
        exit(-1);
    }
    atexit(safe_exit);
    time_dot  = time(NULL);
    time_dot -= (time_dot % TimeSpan);
    memset(&tp_data_time, 0, sizeof(tp_data_time));
    memset(&tp_data_gen,  0, sizeof(tp_data_gen));
    tp_data_gen[0].time = time(NULL);
}
