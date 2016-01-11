#include <stdio.h>
#include <signal.h>

#include "winwrap.h"
#include "linwrap.h"
#include "loss.h"

char *host_to_push = NULL;
int received_packets = 0;
int port_num = 12346;
int quiet = 0;
int continuous = 0;
int this_salt = 0;
int last_salt = -1;
int payload_size = -1;

float loss;

struct sockaddr_in my_addr;
char buf[66000];
SOCKET sock;



void
print_help()
{
    fprintf(stdout, "\nloss_srv\n\n");
    fprintf(stdout, "valid options are:\n");
    fprintf(stdout, "\t-p [port]   : port on which to listen\n");
    fprintf(stdout, "\t-c          : run continously (loop until ctrl-c)\n");
    fprintf(stdout, "\t-q          : don't print anything but the results\n");
    fprintf(stdout, "\t-h          : this help\n\n");
    exit(-1);
}

void
parse_parameters(int argc, char **argv)
{  
    char c;
    while ((c=getopt(argc, argv, "chp:q")) != -1)
    {
        switch (c)
        {
        case 'c':
            continuous = 1;
            break;
        case 'h':
            print_help();
            break;
        case 'p':                          // filter string
            port_num = atoi(optarg);
            break;
        case 'q':
            quiet = 1;
            break;
        }
    }
}


void
init_network()
{    
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
}


void
run_server()
{
#ifdef _DEBUG
    struct test_content *tc;
#endif
    int rv;
    int temp;
    struct server_info *si;

    rv = 1;
    temp = sizeof(struct sockaddr);
    received_packets = 0;
    payload_size = -1;
    while (rv > 0)
    {
        rv = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&my_addr, &temp);
        if (rv == sizeof(struct server_info) && 
            strcmp(((struct server_info*) buf)->identifier, "loss_check") == 0)
        {
            si = (struct server_info*) buf;
#ifdef _DEBUG
            //printf("got command packet. salt=%-5d command=%d\n", si->salt, si->command);
#endif
            switch (si->command)
            {
                case CAPT_ABORT:
                    if (last_salt == si->salt) break;
#ifdef _DEBUG
                    printf("CAPT_ABORT\n");
#endif
                    last_salt = si->salt;
                    // "aborted" will be printed later ...
                    this_salt = 0;
                    rv = 0;     // abort condition for while loop
                    break;
                case CAPT_STOP:
                    if (this_salt != si->salt) break;
#ifdef _DEBUG
                    printf("CAPT_STOP. salt=%d\n", si->salt);
#endif
                    this_salt = -1;
                    rv = 0;     // abort condition for while loop
                    break;
                case CAPT_START:
                    if (this_salt == si->salt) break;
#ifdef _DEBUG
                    printf("CAPT_START. salt=%d\n", si->salt);
#endif
                    this_salt = si->salt;
                    received_packets = 0;
                    break;
            }
        }
        // now we're dealing with struct test_content* !!!!
        else if (strncmp(((struct test_content*) buf)->identifier, "loss_chk", 8) == 0)
        {
            // we have a valid packet :-)
#ifdef _DEBUG
            tc = (struct test_content*) buf;
            if ( tc->salt == this_salt )
#else
            if ( ((struct test_content*) buf)->salt == this_salt )
#endif
            {
#ifdef _DEBUG
                printf("got valid packet. salt=%d\n", ((struct test_content*) buf)->salt);
                if (received_packets == 0)
                    printf("first packet :-)\n");
#endif
                if (payload_size == -1)
                    payload_size = rv;
                else if (payload_size != rv)
                {
                    fprintf(stderr, "ERROR: payload sizes do not match!\n");
                    fprintf(stderr, "       got %d, expected %d.\n", rv, payload_size);
                }
                received_packets++;
            }
        }
    }
    if (rv < 0)
    {
        perror("recvfrom");
        exit(-1);
    }
    else
    {
        si = (struct server_info*) buf;
        if (si->sent_packets == 0)
        {
            // this is if we just want to abort this session!
            fprintf(stderr, "aborted.\n");
            return;
        }
        loss = (1 - (received_packets / (float) si->sent_packets)) * 100;
        fprintf(stdout, "%2.2f   %6d   %6d   %4d\n",
            loss, si->sent_packets, received_packets, payload_size);
    }

}


void
sig_handler(int signal)
{
    fprintf(stdout, "CTRL-C\n");
    exit(0);
}


int 
main(int argc, char **argv)
{    
    int loop_number = 0; 

    startup_win_network();

    parse_parameters(argc, argv);

    init_network();

    signal(SIGINT, sig_handler);

    if (!quiet)
    {
        fprintf(stderr, "listening on port %d for packets .... \n", port_num);
        if (continuous)
            fprintf(stderr, "looping tests.\n");
        fprintf(stderr, "\n");
    }

    fprintf(stdout, "# run no., loss rate in %%, packets_sent, packets_received, payload_size\n");
    do
    {
        loop_number++;
        fprintf(stdout, "%2d.   ", loop_number);
        run_server();
    }
    while (continuous);

    return 1;
}
