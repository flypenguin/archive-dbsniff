#ifdef WIN32
#ifndef __winwrap_h
#define __winwrap_h 1

#include <windows.h>
#include "getopt.h"

// with GNU COMPILERS use "ll" for long long, instead of "I64"
#ifdef __GNUC__
       #define I64 "ll"
#else
     #define I64 "I64"
#endif

// on WINDOWS use Sleep() instead of usleep()
#ifdef WIN32
     #define usleep(n) Sleep(n)
#endif

extern WSADATA wsaData;  

void
startup_win_network();


#endif
#endif
