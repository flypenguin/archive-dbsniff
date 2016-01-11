#include <stdio.h>
#include "linwrap.h"
#include "winwrap.h"
#include "getopt.h"

int num_packets = 0;
int port_num = 0;
char *host_to_push = NULL;
char *id_string = NULL;
size_t id_string_len = 0;
char buf[100];


void 
print_help()
{
    fprintf(stdout, "\nnpush\n\n");
    fprintf(stdout, "valid options are:\n");
    fprintf(stdout, "\t-c [num]    : number of packets to send\n");
    fprintf(stdout, "\t-m [IP]     : machine to send packets to\n");
    fprintf(stdout, "\t-p [port]   : port to address packets to\n");
    fprintf(stdout, "\t-s [string] : string to send with packet\n");
    fprintf(stdout, "\t-h          : this help text\n\n");
    exit(-1);
}


void
parse_parameters(int argc, char **argv)
{  
    char c;
    while ((c=getopt(argc, argv, "m:hc:p:s:")) != -1)
    {
        switch (c)
        {
        case 'c':                          // filter string
            num_packets = atoi(optarg);
            break;
        case 'h':
            print_help();
            break;
        case 'm':                          // filter string
            host_to_push = strdup(optarg);
            break;
        case 'p':                          // filter string
            port_num = atoi(optarg);
            break;
        case 's':                          // filter string
            buf[99] = '\0';
            id_string = strncpy(buf, optarg, 99);
            id_string_len = strlen(id_string);
            break;
        }
    }
    if (!host_to_push)
    {
        fprintf(stderr, "please specify a machine with -m!");
        exit(-1);
    }
    if (!id_string_len)
    {
        strcpy(buf, "buh!");
        id_string_len = 4;
    }
    if (!port_num) port_num = 12345;
    if (!num_packets) num_packets = 1;
}

int main(int argc, char **argv)
{    
    SOCKET sock;
    int rv;
    struct sockaddr_in their_addr;

    startup_win_network();

    parse_parameters(argc, argv);


    their_addr.sin_family = AF_INET;     // host byte order
    their_addr.sin_port = htons(port_num); // short, network byte order
    their_addr.sin_addr.s_addr = inet_addr(host_to_push);
    //inet_aton(host_to_push, &their_addr.sin_addr);
    memset(&(their_addr.sin_zero), '\0', 8); // zero the rest of the struct

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        exit(-1);
    }

    for (rv=0; rv<num_packets; rv++)
        sendto(sock, buf, id_string_len, 0,
            (struct sockaddr *)&their_addr, sizeof(struct sockaddr));

    return 1;
}
