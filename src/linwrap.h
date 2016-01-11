#ifndef WIN32
#ifndef __linwrap_h
#define __linwrap_h

#define SOCKET int
#define startup_win_network() ;

#define I64 "ll"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>

#include <time.h>

#include <string.h>

#endif
#endif
