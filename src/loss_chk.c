#include <stdio.h>
#include <time.h>


#include "linwrap.h"
#include "winwrap.h"
#include "loss.h"

int sendabort = 0;
int quiet = 0;
int delay = 50;
int size = 500;
int num_packets = 10000;
int port_num = 12346;
int salt = 0;
int red = 100;

char buf[66000];

char *host_to_push = NULL;
char *id_string = NULL;

SOCKET sock;
struct sockaddr_in their_addr;




void 
print_help()
{
    fprintf(stdout, "\nloss_chk\n\n");
    fprintf(stdout, "valid options are:\n");
    fprintf(stdout, "\t-c [num]    : number of packets to send\n");
    fprintf(stdout, "\t-m [IP]     : machine to send packets to\n");
    fprintf(stdout, "\t-M [IP]     : send abort signal to server running on ""IP""\n");
    fprintf(stdout, "\t-p [port]   : port to address packets to\n");
    fprintf(stdout, "\t-d [ms]     : how many ms delay between packet (set 0 to flood).\n");
    fprintf(stdout, "\t-s [size]   : size of payload to send (UDP!)\n");
    fprintf(stdout, "\t-r [num]    : redundancy: how many repetitions for command packets?\n");
    fprintf(stdout, "\t-q          : be quiet\n\n");
    fprintf(stdout, "\t-h          : this help text\n\n");
    exit(0);
}


void
parse_parameters(int argc, char **argv)
{  
    char c;
    while ((c=getopt(argc, argv, "c:d:hm:p:q:r:s:M:")) != -1)
    {
        switch (c)
        {
        case 'c':                          // number of packets
            num_packets = atoi(optarg);
            break;
        case 'd':
            delay = atoi(optarg);
            break;
        case 'h':
            print_help();
            break;
        case 'M':                          // abort signal ?
            sendabort = 1;
        case 'm':                          // machine to push
            host_to_push = strdup(optarg);
            break;
        case 'p':                          // port to push
            port_num = atoi(optarg);
            break;
        case 'q':
            quiet = 1;
            break;
        case 'r':
            red = atoi(optarg);
            break;
        case 's':                          // payload size 
            size = atoi(optarg);
            if (size < sizeof(struct test_content))
                size = sizeof(struct test_content);
            fprintf(stderr, "size too small - adjusting to minimal %d\n",
                sizeof(struct test_content));
            break;
        }
    }
    if (!host_to_push)
    {
        fprintf(stderr, "please specify a machine with -m!");
        exit(-1);
    }
    if (sendabort) 
        num_packets = 0;
}


void
init_network()
{
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
}


void
send_command(int count, int command, int np)
{
    struct server_info si;
    int i;

    if (command != 0)
    {
        if (command != CAPT_STOP) np = 0;
        switch (command)
        {
            case CAPT_ABORT:
                if (!quiet)
                    fprintf(stderr, "sending abort signal to %s\n", host_to_push);
                break;
            case CAPT_START:
                break;
            case CAPT_STOP:
                break;
        }
    }

    si.salt = salt;
    si.command = command;
    si.sent_packets = np;

    strncpy(si.identifier, "loss_check", sizeof(si.identifier));
    strncpy(si.version, "v2.0", sizeof(si.version));

    for (i=0; i<count; i++)
    {
        sendto(sock, (char*)&si, sizeof(struct server_info), 0,
            (struct sockaddr *)&their_addr, sizeof(struct sockaddr));
        usleep(10);
    }    
}


void
run_test()
{
    int i;
    struct test_content *tc; 

    if (!quiet)
        fprintf(stderr, "testing %s with %d packets (delay %d ms).\n", 
        host_to_push, num_packets, delay);

    tc = (struct test_content *)buf;
    strncpy(tc->identifier, "loss_chk", 9);
    tc->salt = salt;
#ifdef _DEBUG
    printf("salt=%d\n", salt);
#endif

    if (delay)
        for (i=0; i<num_packets; i++)
        {
            sendto(sock, buf, size, 0,
                (struct sockaddr *)&their_addr, sizeof(struct sockaddr));
            usleep(delay);
        }
    else
        for (i=0; i<num_packets; i++)
            sendto(sock, buf, size, 0,
                (struct sockaddr *)&their_addr, sizeof(struct sockaddr));
}



int 
main(int argc, char **argv)
{    
    startup_win_network();

    parse_parameters(argc, argv);

    init_network();

    srand( (unsigned)time( NULL ) );
    salt = rand();
#ifdef _DEBUG
    printf("setting salt to %d\n", salt);
#endif

    if (!sendabort) 
    {
        send_command(red, CAPT_START, 100);
        run_test();
        send_command(red, CAPT_STOP, num_packets);
    }
    else
        send_command(red, CAPT_ABORT, 0);

    return 1;
}
