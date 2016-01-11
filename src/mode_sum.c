/* summary mode
 *
 * prints bytes_in, pckts_in, bytes_out, pcks_out, other_bytes, other_pcks
 *
 */

/* globals and private definitions for ext_throughput_handler */

#include "inc_pcap.h"
#include <assert.h>

#include "extsniff.h"
#include "params.h"
#include "tp_ext.h"
#include "pack_decode.h"
#include "linwrap.h"


static etp_gen_data    tp_data_gen[4];
static struct timeval  start_time;
static struct timeval  current_time;

void
sum_mode_handler(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
    ip_header      *ih;
    tcp_header       *th;
    udp_header     *uh;
    packet_info     pi;
    int             inout;
    
    decode_packet(pkt_data, &ih, &th, &uh);
    fill_packet_info(ih, th, uh, &pi);

	current_time.tv_sec = header->ts.tv_sec;
	current_time.tv_usec = header->ts.tv_usec;

    tp_data_gen[1].time = header->ts.tv_sec;

	// traffic FROM ref IP is OUTgoing, unless SwitchRefIpMode is set.
	// the reverse sorting of FROM and TO traffic when -x switch is set
    // is done via the XOR operator. SwitchRefIpMode MUST HAVE a setting
    // of 0 or 1 ONLY for that to work. 
    if      (ih->saddr.s_addr == IPnum) inout = 0 ^ SwitchRefIpMode;          
    else if (ih->daddr.s_addr == IPnum) inout = 1 ^ SwitchRefIpMode;
    else                                inout = 2;
    
    if (pi.len > 1500) tp_data_gen[inout].size_dist[1500] += 1;
	else               tp_data_gen[inout].size_dist[pi.len] += 1;

	tp_data_gen[inout].pack_count++;
	//tp_data_gen[inout].pack_size += pi.len;
    // count THE WHOLE packet, including eth header. 
    tp_data_gen[inout].pack_size += header->len;

	if (pi.protocol != PROT_TCP && pi.protocol != PROT_UDP)
		return; 

	if (pi.paylen > 1500) tp_data_gen[inout].payload_dist[1500] += 1;
	else                  tp_data_gen[inout].payload_dist[pi.paylen] += 1;
    tp_data_gen[inout].pay_size  += pi.paylen;

	if (pi.protocol == PROT_TCP)
    {
        if (pi.psh) tp_data_gen[inout].pack_push++;
        if (pi.syn) tp_data_gen[inout].pack_syn++;
        if (pi.fin) tp_data_gen[inout].pack_fin++;
        if (pi.rst) tp_data_gen[inout].pack_rst++;
    }
}


void
sum_mode_handler_first(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
    // only for the first time - to set the duration. 
    sum_mode_handler(param, header, pkt_data);
	start_time.tv_sec = header->ts.tv_sec;
	start_time.tv_usec = header->ts.tv_usec;
}


void
sum_mode_print_summary(void)
{
    int i, j, printme;
    float avg_payload[4];
	float avg_pcksize[4];
	int it; 
	double millis;
	struct timeval since_start;
	

	since_start.tv_usec = current_time.tv_usec - start_time.tv_usec;
	if (since_start.tv_usec < 0)
	{
		since_start.tv_usec *= -1;	// make positive;
		since_start.tv_sec = -1;    // subtract one
		since_start.tv_sec += current_time.tv_sec - start_time.tv_sec;
	}
	else 
		since_start.tv_sec = current_time.tv_sec - start_time.tv_sec;
	millis = (double) since_start.tv_sec * 1000000;
	millis += since_start.tv_usec;
	millis /= 1000;
	//millis = (float) (((long long)(since_start.tv_sec * 1000000) + since_start.tv_usec) / 1000);


    // generate the sum thing
    for (i=0; i<3; i++)
    {
        tp_data_gen[3].pack_count += tp_data_gen[i].pack_count;
        tp_data_gen[3].pack_fin   += tp_data_gen[i].pack_fin;
        tp_data_gen[3].pack_push  += tp_data_gen[i].pack_push;
        tp_data_gen[3].pack_rst   += tp_data_gen[i].pack_rst;
        tp_data_gen[3].pack_size  += tp_data_gen[i].pack_size;
        tp_data_gen[3].pay_size   += tp_data_gen[i].pay_size;
        tp_data_gen[3].pack_syn   += tp_data_gen[i].pack_syn;
        tp_data_gen[3].pack_urg   += tp_data_gen[i].pack_urg;
        for (j=0; j<1501; j++)
		{
            tp_data_gen[3].payload_dist[j] += tp_data_gen[i].payload_dist[j];
            tp_data_gen[3].size_dist[j]    += tp_data_gen[i].size_dist[j];
		}
    }
    
    /* 
	 * average payload size: of all packets actually carrying any payload :-)
	 * THUS it is PERFECTLY POSSIBLE that the AVERAGE PAYLOAD size is GREATER than 
	 * the AVERAGE PACKET size. in the former all packets with ZERO PAYLOAD SIZE ARE 
	 * NOT INCLUDED, whereas in the latter they are. 
     */
    for (j=0; j<4; j++)
	{
		it = tp_data_gen[j].pack_count - tp_data_gen[j].payload_dist[0];
		if (it == 0)
			avg_payload[j] = 0;
		else
			avg_payload[j] = tp_data_gen[j].pay_size / (float) it;

		it = tp_data_gen[j].pack_count;
		if (it == 0)
			avg_pcksize[j] = 0;
		else
			avg_pcksize[j] = tp_data_gen[j].pack_size / (float) it;
	}

    fprintf(STDOUT, "\n%20s%s%10s%s%10s%s%10s%s%10s", 
		"#FIELD", Separat, "OUT", Separat, "IN", Separat, "OTHER", Separat, "SUM");

	fprintf(STDOUT, "\n%20s", "duration(ms)", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10.1lf", 
		Separat,  millis);

    fprintf(STDOUT, "\n%20s", "num_pcks", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_count);

    fprintf(STDOUT, "\n%20s", "sum_size", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_size);

    fprintf(STDOUT, "\n%20s", "sum_payl", Separat);
	for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pay_size);

    fprintf(STDOUT, "\n%20s", "avg_pay_size", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10.2f", Separat, avg_payload[i]);

    fprintf(STDOUT, "\n%20s", "avg_pck_size", Separat);
	for (i=0; i<4; i++) fprintf(STDOUT, "%s%10.2f", Separat, avg_pcksize[i]);

    fprintf(STDOUT, "\n%20s", "flag_psh", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_push);

    fprintf(STDOUT, "\n%20s", "flag_syn", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_syn);

    fprintf(STDOUT, "\n%20s", "flag_rst", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_rst);

    fprintf(STDOUT, "\n%20s", "flag_fin", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_fin);

    fprintf(STDOUT, "\n%20s", "flag_urg", Separat);
    for (i=0; i<4; i++) fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[i].pack_urg);

    if (FlagScreenAdd)
	{
        fprintf(STDOUT, "\n");
        for(i=0; i<1501; i++)
        {
            printme = 0;
            for (j=0; j<4; j++)
                printme += tp_data_gen[j].size_dist[i];
            if (FlagScreenAdd > 1) printme = 1;
            if (printme)
            {
                fprintf(STDOUT, "\n%15s%4d]", "PACKETsize[", i);
                for (j=0; j<4; j++)
                    fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[j].size_dist[i]);
            }
        }

	
        fprintf(STDOUT, "\n");
        for(i=0; i<1501; i++)
        {
            printme = 0;
            for (j=0; j<4; j++)
                printme += tp_data_gen[j].payload_dist[i];
            if (FlagScreenAdd > 1) printme = 1;
            if (printme)
            {
                fprintf(STDOUT, "\n%15s%4d]", "PAYLOADsize[", i);
                for (j=0; j<4; j++)
                    fprintf(STDOUT, "%s%10d", Separat, tp_data_gen[j].payload_dist[i]);
            }
        }
}

    fprintf(STDOUT, "\n\n");
    return;
}




void
setup_summary_mode(char *filename)
{
    memset(tp_data_gen, 0, sizeof(tp_data_gen));
    atexit(sum_mode_print_summary);
	if (DBFile) openOutputFile();
	else        STDOUT = stdout;
}
