#include "winwrap.h"
#include "linwrap.h"
#include <stdio.h>
#include "getopt.h"

int num_packets;
int port_num = 0;
char *host_to_push = NULL;
char *id_string = NULL;
size_t id_string_len = 0;
int quiet = 0;



void
print_help()
{
    fprintf(stdout, "\nnwait\n\n");
    fprintf(stdout, "valid options are:\n");
    fprintf(stdout, "\t-p [port]   : port on which to listen\n");
    fprintf(stdout, "\t-q          : be quiet - no messages will be printed\n");
    fprintf(stdout, "\t-s [string] : only end if sender sends this string\n");
    fprintf(stdout, "\t-h          : this help\n\n");
    exit(-1);
}

void
parse_parameters(int argc, char **argv)
{  
    char c;
    while ((c=getopt(argc, argv, "s:p:qh")) != -1)
    {
        switch (c)
        {
        case 'p':                          // filter string
            port_num = atoi(optarg);
            break;
        case 'h':
            print_help();
            break;
        case 's':
            id_string = strdup(optarg);
            id_string_len = strlen(id_string);
            break;
        case 'q':
            quiet = 1;
        }
    }
    if (!port_num) port_num = 12345;
}

int main(int argc, char **argv)
{    
    char buf[100];
    SOCKET sock;
    int rv;
    int temp;
    struct sockaddr_in my_addr;

    startup_win_network();

    parse_parameters(argc, argv);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        exit(-1);
    }

    my_addr.sin_family = AF_INET;     // host byte order
    my_addr.sin_port = htons(port_num); // short, network byte order
    my_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct

    if ((bind(sock, (struct sockaddr *)&my_addr,sizeof(struct sockaddr))) == -1)
    {
        perror("bind");
        exit(-1);
    }

    if (!quiet)
        fprintf(stderr, "listening on port %d for incoming packet .... ", port_num);

    rv = 0;
    temp = sizeof(struct sockaddr);
    while (rv == 0)
    {
        rv = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&my_addr, &temp);
        if (id_string_len)
            if (rv != id_string_len || strncmp(id_string, buf, id_string_len) != 0)
                rv = 0;
    }
    if (rv < 0)
    {
        perror("recvfrom");
        exit(-1);
    }

    if (!quiet) 
        fprintf(stderr, "continue :-) \n");

    return 1;
}
