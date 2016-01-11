#ifndef __loss_h
#define __loss_h 1

#define CAPT_START  0x01
#define CAPT_STOP   0x02
#define CAPT_ABORT  0x03

#pragma pack(1)
struct server_info
{
    char    identifier[25];
    char    version[5]; 
    int     sent_packets;
    int     command;
    int     salt;
};
#pragma pack()

#pragma pack(1)



struct test_content
{
    char identifier[10];
    int  salt;
};
#pragma pack()


#endif

