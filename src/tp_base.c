#include <stdio.h>
#include "inc_pcap.h"
#include <stdlib.h>

#include "extsniff.h"
#include "params.h"

#include "tp_base.h"

#include "linwrap.h"
#include "winwrap.h"


/* *************************************************************************
   WIN32 definition of function, that is taken from the example at 
   winpcap.polito.it, and USES WinPCap INTERNAL WIN32 ENHANCEMENTS.
   ************************************************************************* */


void                                           // WIN32 DEFINITION OF FUNCTION
win_tp_handler(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
    static struct timeval   old_ts = {0,0};
    u_int                   delay;
    unsigned long long int  Bps,Pps;

    delay=(header->ts.tv_sec - old_ts.tv_sec) * 1000000 - old_ts.tv_usec + header->ts.tv_usec;
    Bps=(((*(long long*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    Pps=(((*(long long*)(pkt_data)) * 1000000) / (delay));

    fprintf(STDOUT, "%10ld.%06ld %10" I64 "d %10" I64 "d\n", 
        header->ts.tv_sec, header->ts.tv_usec, 
        Bps, Pps);
}


/* *************************************************************************
   Standard definition of function, works for *NIX and WIN32.
   To Be Called: 
		First:    setup_tp_handler();
		Then:     std_tp_handler() for each packet
		At last:  std_tp_handler() on break or capture file end. 
   ************************************************************************* */


/* neccessary global variable - should be initialized beforehands */
u_int               TimeSpanMu;
u_int				LastCall;
unsigned long long  pps, bps; 
unsigned long long  TimePointFirst, TimePointLast, TimePointNext;

/* -------------------------------------------------------------------------
   STANDARD DEFINITION OF FUNCTION
  
   works as follows: 
   | - reference point
   * - network packet
   
      ** ***  * * *** * **  *  ** *   * *  *
   |----------|---------|---------|---------|--....
   
   all traffic packets ("*") between the reference time points ("|") are 
   counted. if a new reference time point is reached (capture header time 
   information) the transmitted packets are summed up and divided by the 
   timespan (the time between two "|" including the first one)
  
   will print "relative_time bytes_per_sec packets_per_sec" lines. 
   ------------------------------------------------------------------------- */
void
std_tp_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    unsigned long long  ts;
	int					TimePointsBetween;
	float				time_to_print;
	float				bps_to_print;
	float				pps_to_print;
	int					i;

	if (LastCall) 
	{
		time_to_print = (TimePointNext - TimePointFirst) / (float)1000000;
		bps_to_print = (bps / (float) TimeSpanMu) * 1000000;
        pps_to_print = (pps / (float) TimeSpanMu) * 1000000; 
		fprintf(STDOUT, "%20.2f %20.4f %20.4f\n", 
			time_to_print, bps_to_print, pps_to_print);
		return;
	}


	ts = (long long) 1000000 * header->ts.tv_sec + header->ts.tv_usec;
    if (ts >= TimePointNext) // new time interval
    {
		// calculate time points between current and last [seen]
		TimePointsBetween = (int) ((ts-TimePointLast)/TimeSpanMu);
		// print data for time points between last and currnet (if any)

        // this is the situation in (possible) effect:
        //  | prnt x->|prnt"0"->|prnt"0"->|         |print nothing yet
        //  |--P------|---------|---------|-- ... --|-P-- ...
        //  | (1)       (2.1)     (2.2)    (... 2.x)    (3)

        // take care of field (1) :

        if (pps)
        {
            TimePointLast += TimeSpanMu;
		    time_to_print = (TimePointLast - TimePointFirst) / (float)1000000; // seconds based!!
		    bps_to_print = (bps / (float) TimeSpanMu) * 1000000;
            pps_to_print = (pps / (float) TimeSpanMu) * 1000000; 
        }
        else
        {
            pps_to_print = 0;
            bps_to_print = 0;
        }
		fprintf(STDOUT, "%20.2f %20.4f %20.4f\n", 
			time_to_print, bps_to_print, pps_to_print);

        // take care of fields (2.1) and (2.2) (and all other 2.x fields :)

        for (i=1; i<TimePointsBetween; i++)
		{
			TimePointLast += TimeSpanMu;
			time_to_print = (TimePointLast - TimePointFirst) / (float)1000000;
			fprintf(STDOUT, "%20.2f %20.4f %20.4f\n", time_to_print, 0, 0);
		}

		// field (3): print nothing yet, but save data, and set new write point.

		TimePointNext = TimePointLast + TimeSpanMu;

        bps = 0;
		pps = 0;
    }

	bps += (u_int) (header->len);
	pps += 1;
}


void
std_tp_handler_first(u_char *param,
    const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
	fprintf(STDOUT, "#%19s %20s %20s\n", "relative time [s]", "bytes/sec", "packets/sec");
	TimePointFirst = header->ts.tv_sec * (long long) 1000000 + header->ts.tv_usec; // (1)
	TimePointLast = TimePointFirst;
	TimePointNext = TimePointFirst + TimeSpanMu;
	std_tp_handler(param, header, pkt_data);
}


void
std_tp_handler_last(void)
{
	if (LastCall == 0)
	{
		LastCall = 1;
		std_tp_handler(NULL, NULL, NULL); 
	}
}


/**
	this function is valid for both the WIN32 specific AND the 
	standard throughput modes. It mainly takes care of opening
	the output file if necessary.
*/
void
setup_throughput()
{
	LastCall = 0;
    TimeSpanMu = (u_int) TimeSpan;
	atexit(std_tp_handler_last);
	if (DBFile) openOutputFile();
	else        STDOUT = stdout;

}



/*
(1) 
that " ... * (long long) 1000000" is necessary, because otherwise it would be a
multiplication between two ints, and as long as that multiplication is saved into
a long long variable it MIGHT be that the "2nd half" had not been properly initialized. 
that will result in random data being added to the result, rendering it useless. 
by multiplicating with a long long it is ensured (just like by dividing with a float) 
that the result is treated as long long from the beginning, which makes that behavior 
impossible. 

*/
