#ifndef _INC_PCAP_H
#define _INC_PCAP_H

// okay. on windows, IF
//  1. we're using ms visual studio - everything should work fine.
//  2. we're using mingw/dev-c++, we get problems with data types
//     being redefined from pcap, because pcap does not recognize
//     the gnu c compiler environment on windows (it seems)
// so this header file is ONLY responsible for including pcap.h safely, 
// which means safely on linux, windows (ms vs), windows (dev-c++), and - 
// if I ever try that - windows (cygwin)

#ifdef WIN32 
#ifdef __GNUC__
       #define _BITTYPES_H
#endif
#endif

#include <pcap.h>


#endif

