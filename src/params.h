/* PARAMS.H
 *
 * responsible for managing global parameters and holding global
 * values, such as filenames, program states, etc.
 */

#ifndef __params_h
#define __params_h 1

extern FILE*			STDOUT;

extern int				ActiveMode;

extern char            *FilterStr;
extern char            *DBFile;
extern char            *NetDevice;
extern char            *DumpFile;
extern char            *Separat;
extern int				NetDeviceNo;
extern int              ReadFromFile;
extern int              UseWinOnly;
extern int              ScreenOnly;
extern int              SwitchRefIpMode;
extern int              SnapLen;
extern time_t           TimeSpan;

extern char            *IP;
extern unsigned int     IPnum;

extern int              FlagVerbose;
extern int              FlagScreenAdd;
extern int              FlagStopAfter;


#define WORK_MODE_NONE					0
#define WORK_MODE_THROUGHPUT			1
#define WORK_MODE_THROUGHPUT_EXTENDED	2
#define WORK_MODE_SUMMARY				4
#define WORK_MODE_PRINT_HEADERS			8
#define WORK_MODE_PRINT_CONTENT			16
#define WORK_MODE_STAT					32



void
setup_parameters(int argc, char **argv);

void 
openOutputFile();

#endif
