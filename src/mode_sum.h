#ifndef __MODE_SUM_H
#define __MODE_SUM_H 


void 
setup_summary_mode(char *filename);

void
sum_mode_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void
sum_mode_handler_first(u_char *, const struct pcap_pkthdr *, const u_char *);


#endif


