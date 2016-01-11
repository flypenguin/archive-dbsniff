/*
 * THIS COPYRIGHT NOTICE IS NECESSARY BECAUSE THIS APPLICATION IS A MODIFICATION
 * OF AN EXAMPLE PROGRAM OF WINPCAP.
 * MOST PARTS HAVE BEEN REWRITTEN, THOUGH :-)
 *
 * ALL REWRITTEN / ADDED PARTS ARE (c) AXEL BOCK, AND - AS FAR AS LEGALLY 
 * POSSIBLE - GPL2 RESTRICTIONS APPLY.
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

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <time.h>
    #include <string.h>
    #include <stdlib.h>
#endif

#include "inc_pcap.h"
#include <signal.h>
#include <stdio.h>
#include <assert.h>

#include "extsniff.h"
#include "littlehelpers.h"
#include "disponly.h"

#include "confnet.h"

#include "params.h"
#include "tp_ext.h"
#include "tp_base.h"
#include "mode_sum.h"





void
safe_terminate(int signum)
{
    static int already_called = 0;
    
    if (already_called) return;
    already_called++;
	fprintf(stderr, "\n\n%25s: program termination with signal: %d\n",
		get_timestr(0), signum);
#ifdef USE_DB
	if (db)
    {
        db_close(db);
        db = NULL;
    }
#endif
    exit(-1);
}


void
exit_handler(void)
{
    //safe_terminate(0);
#ifdef _DEBUG
    fgetc(stdin);
#endif
}


int
main(int argc, char** argv)
{
    struct pcap_pkthdr *header;
    u_char             *pkt_data;
    int                 res;
    unsigned int        ProcessedPackets = 0;

	atexit(exit_handler);                      // <- ditto.
    signal(SIGINT,  safe_terminate);           // as early as possible.
    signal(SIGTERM, safe_terminate);           // calling them more than once
    //signal(SIGSEGV, safe_terminate);           // does no harm :-)
    setup_parameters(argc, argv);
    setup_sniff();                             // if this fails dont bother ...
    res = 0;
	
	// now enter the new main loop

	// first, call all setup_*() functions
	if (ActiveMode == WORK_MODE_NONE) ActiveMode = WORK_MODE_PRINT_HEADERS;
	if (ActiveMode & WORK_MODE_PRINT_HEADERS)       setup_disp_only();
	if (ActiveMode & WORK_MODE_THROUGHPUT_EXTENDED) setup_ext_throughput(DBFile);
	if (ActiveMode & WORK_MODE_SUMMARY)             setup_summary_mode(NULL);

	// then start grabbing & dispatching
	res = 0;
	while (res==0) res=pcap_next_ex(adhandle, &header, (const u_char**)&pkt_data);
    if (res>0)
	{
		if (ActiveMode & WORK_MODE_PRINT_HEADERS)
			disp_only_handler_first(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_PRINT_CONTENT)
			disp_content_handler(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_SUMMARY)
			sum_mode_handler_first(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_THROUGHPUT)
			std_tp_handler_first(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_THROUGHPUT_EXTENDED)
			ext_throughput_handler(NULL, header, pkt_data);

		ProcessedPackets += 1;

		res = 0;
		while (res==0)
			res = pcap_next_ex( adhandle, &header, (const u_char**)&pkt_data);
	}

	while (res>0)
	{
        if (FlagStopAfter && ProcessedPackets == FlagStopAfter) break;
		
		if (ActiveMode & WORK_MODE_PRINT_HEADERS)
			disp_only_handler(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_PRINT_CONTENT)
			disp_content_handler(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_SUMMARY)
			sum_mode_handler(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_THROUGHPUT)
	        std_tp_handler(NULL, header, pkt_data);
		if (ActiveMode & WORK_MODE_THROUGHPUT_EXTENDED)
		    ext_throughput_handler(NULL, header, pkt_data);

		ProcessedPackets += 1;

		res = 0;
		while (res==0)
			res = pcap_next_ex( adhandle, &header, (void*)&pkt_data);
	}

	disp_content_cleanup();
	std_tp_handler_last();
    
	// finally evaluate result state of loops ...
	if (res == -1)
    {
        fprintf(stderr, "Error reading the packets.\n%s\n",
            pcap_geterr(adhandle));
        exit(-1);
    }
    return 0;
}

