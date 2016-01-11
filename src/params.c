#ifdef WIN32
    #include "getopt.h"
#endif

#include "version.h"

#include "inc_pcap.h"
#include <string.h>
#include <stdlib.h>
#include "confnet.h"
#include "extsniff.h"
#include "params.h"
#include "tp_ext.h"
#include "params.h"

#include "linwrap.h"

// behaviour variables
FILE		   *STDOUT		    = NULL;
char           *FilterStr       = NULL;
char           *DBFile          = NULL;
char           *NetDevice       = NULL;
char           *DumpFile        = NULL;
char           *Separat         = " \0";
int             NetDeviceNo     = 0;
int             ReadFromFile    = 0;
int             UseWinOnly      = 0;
int             ScreenOnly      = 0;
int             SwitchRefIpMode = 0;
int             SnapLen         = 0;
time_t          TimeSpan        = 0;

// the mode variable
int			    ActiveMode      = WORK_MODE_NONE;
//int            DispCont        = 0;
//int            DispOnly        = 0;
//int            SummaryMode     = 0;
//int            ThroughPut      = 0;
//int            EThroughPut     = 0;
//int            StatMode        = 0;

// the flags
int			    FlagTPContent   = 0;
int             FlagVerbose     = 0;
int             FlagScreenAdd   = 0;
int             FlagStopAfter   = 0;

// the others
char          *IP;
unsigned int   IPnum         = 0;



void
print_help(char *program_name)
{
    fprintf(stdout, "\nextsniff %s, ", VERSION_STRING); 
#ifdef WIN32
    fprintf(stdout, "WIN32 ");
#else
    fprintf(stdout, "*nix ");
#endif
#ifdef _DEBUG
    fprintf(stdout, "DEBUG, ");
#else
    fprintf(stdout, "RELEASE, ");
#endif
	fprintf(stdout, "built %s %s\n", __DATE__, __TIME__);
    fprintf(stdout, "available work modes:\n");
    fprintf(stdout, "\t-s           : summary mode\n");
    fprintf(stdout, "\t-p           : print full header information of each packet\n");
    fprintf(stdout, "\t-P           : print CONTENTS of each packet. useful for text flows.\n");
    fprintf(stdout, "\t-t           : throughput mode\n");
    fprintf(stdout, "\t-U           : (broken?) extended throughput mode\n");
#ifdef USE_DB
	fprintf(stdout, "\t-S           : (broken?) statistical analysis mode\n");
#endif
    fprintf(stdout, "\navailable common parameters:\n");
    fprintf(stdout, "\t-r filename  : read fromdump file instead of live capture\n");
	fprintf(stdout, "\t-o filename  : set output filename.\n");
    fprintf(stdout, "\t-v           : additional screen output, use twice for even more\n");
    fprintf(stdout, "\t-V           : be explicitly verbose about parameter settings\n");
	fprintf(stdout, "\t-c           : switch to PAYLOAD throughput mode (tp mode only)\n");
	fprintf(stdout, "\t-R IP        : set reference IP (try -s with and without one!)\n");
	fprintf(stdout, "\t-x           : treat traffic FROM ref ip as INCOMING\n");
	fprintf(stdout, "\t-m num       : stop working after 'num' packets\n");
    fprintf(stdout, "\t-f filter    : set the pcap filter string\n");
    fprintf(stdout, "\t-i NUM       : use net device number NUM\n");
    fprintf(stdout, "\t-I STRING    : use first net device containing STRING\n");
    fprintf(stdout, "\t-l           : list available network devices\n");
    fprintf(stdout, "\t-L len       : set capture length (default: 100)\n");
    fprintf(stdout, "\t-t timespan  : set time interval\n");
    fprintf(stdout, "\t-C \"char\"    : set data set separator (default: space)\n");
    fprintf(stdout, "\t-h           : print this help\n");
}

void
print_tp_help()
{
	fprintf(stdout, "\nTHROUGHPUT MODE HELP\n");
	fprintf(stdout, "--------------------\n");
	fprintf(stdout, "Throughput mode exists in three variants:\n");
	fprintf(stdout, "  1. standard\n  2. extended\n  3. WIN32 standard\n");
	fprintf(stdout, "Usable right now should be modes 1. and 3.\n");
	fprintf(stdout, "Mode 1: select with '-t'.\n");
	fprintf(stdout, "  This mode calculates the throughput seen in a given timespan\n");
	fprintf(stdout, "  on the line or a capture file. All bytes and packets in that\n");
	fprintf(stdout, "  are counted, and finally the bytes and packets per second ratio\n");
	fprintf(stdout, "  calculated based on that timespan is printed.\n");
	fprintf(stdout, "\nMode 2: select with '-T'.\n");
	fprintf(stdout, "  This mode is currently broken.");
	fprintf(stdout, "\nMode 3: select with '-t -W'.\n");
	fprintf(stdout, "  This mode utilizes the WIN32 pcap internal summary mode, which is");
	fprintf(stdout, "  works just fine but use is discouraged. Why? Simple: It is not known\n");
	fprintf(stdout, "  what precisely WinPCap does in that mode. That's all, it should work\n");
	fprintf(stdout, "  just fine.\n\n");
	fprintf(stdout, "Relevant parameters:\n");
	fprintf(stdout, "  -t   set the timespan IN MICROSECONDS, i.e. one second is '-t 1000000'\n");
	fprintf(stdout, "  -c   PAYLOAD throughput instead of complete line throughput\n");
#ifdef WIN32
    //fprintf(stdout, "  -W   use Windows(tm) only extensions (not always useful :-))\n");
#endif
	fprintf(stdout, "\n");
}


void
openOutputFile()
{
	STDOUT = fopen(DBFile, "w");
	if (STDOUT == NULL)
	{
		fprintf(stderr, "ERROR opening output file.\n\n");
		exit(-1);
	}
}




void
setup_parameters(int argc, char **argv)
{
    int c;
	int FlagModeCount = 0;
	//int long_parameter_index;
    if (argc==1)
    {
        print_help(argv[0]);
        exit(0);
    }


#ifdef WIN32
    while ((c=getopt(argc, argv, "cd:o:f:hi:lm:pr:stvxC:DI:L:PU:R:SVW")) != -1)
		//long_options, &long_parameter_index)) != -1)
#else
    while ((c=getopt(argc, argv, "cd:o:f:hi:lm:pr:stvxC:DI:L:PU:R:SV")) != -1)
		//long_options, &long_parameter_index)) != -1)
#endif
    {
        switch (c)
        {
			// the modes
            case 's':                          // summary mode :-)
                FlagModeCount += 1;
				ActiveMode |= WORK_MODE_SUMMARY;
				break; 
            case 't':                          // throughput mode
                FlagModeCount += 1;
				ActiveMode |= WORK_MODE_THROUGHPUT;
                break;
            case 'p':                          // only display :-)
                FlagModeCount += 1;
                ActiveMode |= WORK_MODE_PRINT_HEADERS;
                break;
            case 'P':                          // display packet content :-)
                FlagModeCount += 1;
                ActiveMode |= WORK_MODE_PRINT_CONTENT;
                break;
			case 'S':                          // stat mode: db net analysis :-)
                FlagModeCount += 1;
				ActiveMode |= WORK_MODE_STAT;
				break;
            case 'U':                          // extended throughput mode
                FlagModeCount += 1;
                ActiveMode |= WORK_MODE_THROUGHPUT_EXTENDED;
                IP = strdup(optarg);
                IPnum = inet_addr(IP);
                if (IPnum == INADDR_NONE)
                {
                    fprintf(stderr, "ERROR:\ninvalid IP address: %s\n", IP);
                    exit(-1);
                }
                break;

			// the flags
			case 200:
				print_tp_help();
				_exit(-1);
				break;
            case 'c':                          // time interval
                FlagTPContent = 1;
                break;
            case 'd':                          // time interval
                c = strtol(optarg, NULL, 10);
                TimeSpan = c;
                break;
            case 'f':                          // filter string
                FilterStr = strdup(optarg);
                break;
            case 'h':
                print_help(argv[0]);
                _exit(-1);
                break;
            case 'i':                          // network device
                NetDeviceNo = atoi(optarg);
                break;
            case 'l':
                list_net_devices();
                _exit(-1);
                break;
            case 'm':                          // stop after
                c = strtol(optarg, NULL, 10);
                FlagStopAfter = c;
                break;
            case 'o':                          // filter string
                DBFile = strdup(optarg);
                break;
            case 'r':                          // read from dump file instead of live capture.
                ReadFromFile = 1;
                DumpFile = strdup(optarg);
                break;
            case 'v':                          // tp mode: additional screen output
                FlagScreenAdd += 1;
                break;
            case 'x':                          // switch ref ip modes: now traffic FROM this is INCOMING
                SwitchRefIpMode = 1;
                break;
            case 'C':                          // set data separator character
                Separat = strdup(optarg);
                break;
            case 'I':                          // network device
                NetDevice = strdup(optarg);
                break;
            case 'L':                          // set capture length
                SnapLen = atoi(optarg);
                if (!SnapLen || SnapLen < 50)
                {
                    fprintf(stderr, 
                        "\nERROR:\n\tvalue not valid / too small - %s\n\n", optarg);
                    exit(-1);
                }
                break;
			case 'R':
				IP = strdup(optarg);
                IPnum = inet_addr(IP);
                if (IPnum == INADDR_NONE)
                {
                    fprintf(stderr, "ERROR:\ninvalid IP address: %s\n", IP);
                    exit(-1);
                }
                break;
            case 'V':                          // Verbose mode
                FlagVerbose = 1;
                break;
#ifdef WIN32
            //case 'W':                          // use windows only extensions
            //    UseWinOnly = 1;
            //    break;
#endif
            case '?':
                fprintf(stderr, "error processing command line arguments\n");
                exit(-1);
                break;
			default:
				fprintf(stderr, "\n\nERROR UNKNOWN PARAMETER\n\n");
				_exit(-1);
				break;
        }
    }

	if (ActiveMode == WORK_MODE_NONE)
	{
		fprintf(stderr, "no work mode specified, printing packet headers now.\n");
		ActiveMode |= WORK_MODE_PRINT_HEADERS;
	}

	if (NetDevice && NetDeviceNo)
	{
		fprintf(stderr, "Sorry, you really can't give BOTH the device number and a part of the name\n");
		exit(-1);
	}
	if (DBFile) openOutputFile();
	else        STDOUT = stdout;


	// set variables according to the modes.

	if (ActiveMode & WORK_MODE_SUMMARY)
		if (!FilterStr) FilterStr="ip";

	if (ActiveMode & WORK_MODE_PRINT_HEADERS)
			if (!FilterStr) FilterStr="ip";

	if (ActiveMode & WORK_MODE_PRINT_CONTENT)
	{
			if (!SnapLen)   SnapLen = 65535;
			if (!FilterStr) FilterStr="tcp or udp";
	}

	// now set variables for all modes. 
	if (!SnapLen)                    SnapLen = 70;
	if (!FilterStr && FlagTPContent) FilterStr="tcp or udp";
	if (!TimeSpan)                   TimeSpan = 1000000;

	if (FlagVerbose)
	{
		fprintf(stderr, "capture length : %d\n", SnapLen);
		fprintf(stderr, "filter string  : %s\n", FilterStr);
		
		if (ActiveMode & WORK_MODE_THROUGHPUT)
			fprintf(stderr, "time resolution: %d\n", TimeSpan);

		// FOR WORK MODE SUMMARY
		if (ActiveMode & WORK_MODE_SUMMARY)
		{
			if (IP)
			{
				fprintf(stderr, "reference IP   : %s\n", FilterStr);
				fprintf(stderr, "traffic FROM reference IP is %s\n", 
					SwitchRefIpMode ? "INcoming (-x set)" : "OUTgoing");
			}
			else
				fprintf(stderr, 
					"no reference IP given, all traffic is sorted as 'other'\n");
		}

		if (FlagStopAfter) 
			fprintf(stderr, "Stop working after max. %d packets (if implemented).\n", FlagStopAfter);
		//if (UseWinOnly) 
		//	fprintf(stderr, "Using Windows(tm) specific functions if present.\n");
        if (FlagScreenAdd)
            fprintf(stderr, "printing additional screen output\n");
		if (NetDevice) 
			fprintf(stderr, "working on first net device which name contains \"%s\"\n", NetDevice);
		if (NetDeviceNo) 
			fprintf(stderr, "working on net device number %d\n", NetDeviceNo);
        if (DumpFile)  
			fprintf(stderr, "reading from capture file \"%s\"\n", DumpFile);
    }
}



