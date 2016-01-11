#ifdef WIN32
#include "winwrap.h"
#include <stdio.h>

WSADATA wsaData;  

void
startup_win_network()
{
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        exit(1);
    } 
}

#endif

