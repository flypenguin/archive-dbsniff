#ifndef WIN32
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "inc_pcap.h"
#include <string.h>
#include "params.h"
#include "littlehelpers.h"

#define ErrFile    stderr
#define Promisc    0

pcap_t        *adhandle;                       // what we need for sniffing

unsigned int   NetMask = 0x00;                 // both will be extracted from
unsigned int   OurHost = 0x00;                 // interface information ...

static char    errbuf[PCAP_ERRBUF_SIZE];


void
list_net_devices()
{
    pcap_if_t         *alldevs;
    pcap_if_t         *d;
    char               errbuf[PCAP_ERRBUF_SIZE];
    int                i=0;


    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        fprintf(stderr, "%d. %s", ++i, d->name);
        if (d->description)
            fprintf(stderr, " : %s\n", d->description);
        else
            fprintf(stderr, " (No description available)\n");
    }
    if(i==0)
        fprintf(stderr, "No interfaces found! Make sure (Win)Pcap is installed.\n");
}



void
close_pcap(void)
{
    if (FlagVerbose)
        fprintf(stderr, "\nexit_handler(): capture file closed.\n"); 
    pcap_close(adhandle);
}



char *
set_device(pcap_if_t **ALLDEVS)
{
    int                inum = 0;
    int                i    = 0;
    static char        desc[300];
    pcap_if_t         *alldevs;
    pcap_if_t         *d;
    pcap_addr_t       *a;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* Print the list */
    for (d=alldevs; d; d=d->next)
        i++;
    if (i==0)                                  // if only one device don't ask
    {
        fprintf(stderr, "\nNo interfaces found! Make sure (Win)Pcap is installed.\n");
        exit(-1);
    }
    else if (i==1)
        inum = 1;
	else if (NetDeviceNo > 0)
	{
		if (NetDeviceNo > i)
		{
			fprintf(stderr, "\nERROR: no such interface number: %d\n\n", NetDeviceNo);
			exit(-1);
		}
		else
			inum = NetDeviceNo;
	}
	if (!inum)
    {
		if (NetDevice)
		{
			i = 0;
			for (d=alldevs; d; d=d->next)
			{
				i++;
				if (strstr(d->description, NetDevice))
				{
					fprintf(stderr, "->> %s\n",d->description);
					inum = i;
				}
			}
		}
		else
		{
			i=0;
			if (NetDevice) fprintf(stderr,
				"No interfaces matching device string found.\n");
			for(d=alldevs; d; d=d->next)
			{
				fprintf(stderr, "%d. %s", ++i, d->name);
				if (d->description)
					fprintf(stderr, " (%s)\n", d->description);
				else
					fprintf(stderr, " (No description available)\n");
			}
			fprintf(stderr, "Enter the interface number (1-%d):",i);
			scanf("%d", &inum);
			// simple range check of inum.
			if(inum < 1 || inum > i)
			{
				fprintf(stderr, "\nInterface number out of range.\n");
				/* Free the device list */
				pcap_freealldevs(alldevs);
				_exit(-1);
			}
		}
    }
    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    if (d->description)
        strncpy(desc, d->description, 299);
    /* Open the adapter */
    if ( (adhandle = pcap_open_live(d->name, // name of the device
                            SnapLen,         // portion of the packet to capture.
                                             // 65536 grants that the whole packet will be captured on all the MACs.
                            Promisc,         // don't want Promiscuous mode
                            1000,            // read timeout
                            errbuf           // error buffer
                            ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        _exit(-1);
    }
    // HERE we get the NetMask parameter from the interface
    if((a = d->addresses) != NULL && a->netmask)
    {
        if (!NetMask)                   // if we do NOT yet have a set netmask, get it.
	{
            NetMask=((struct sockaddr_in *)(a->netmask))->sin_addr.s_addr;
	}
        // get IP address. only the first, only one for now.
        if(a->addr)OurHost=*(u_int*)&(((struct sockaddr_in*)a->addr)->sin_addr);
    }
    else
    {
        // we REALLY WANT to have addresses set!!
        fprintf(stderr, "\nWARNING:\n\t couldn't extract interface addresses!\n\n");
    }
    // here everything is well :-)
    pcap_freealldevs(alldevs);
    return desc;
}



char *
open_dump_file()
{
    static char *desc = "dumpfile :-)";
    if (!DumpFile || (adhandle = pcap_open_offline(DumpFile, errbuf)) == NULL)
    {
        fprintf(stderr,"\nUnable to open the the dumpfile '%s'.\n", DumpFile);
        exit(-1);
    }
    else
        atexit(close_pcap);                 // clean up later :-)
    return desc;
}



void
setup_sniff()
{
    pcap_if_t           *alldevs;
    char                *description;
    struct bpf_program   fcode;

    /* Retrieve the device list */
    if (!ReadFromFile)
        description = set_device(&alldevs);
    else
        description = open_dump_file();
    
    // from here ONLY use adhandle, NOT alldevs. it's freed ...

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        _exit(-1);
    }
    //compile the filter
    if(pcap_compile(adhandle, &fcode, FilterStr, 1, NetMask) <0 ){
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        _exit(-1);
    }
    //set the filter
    if(pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        exit(-1);
    }
#ifdef WIN32
    if (ActiveMode == WORK_MODE_THROUGHPUT && UseWinOnly)
        pcap_setmode(adhandle, MODE_STAT);
#endif
    if (FlagVerbose) 
        fprintf(stderr, "listening on %s ...\n", description);
}
