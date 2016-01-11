#ifndef __disponly_h
#define __disponly_h

void
setup_disp_only();

void
disp_only_handler(u_char*, const struct pcap_pkthdr*, const u_char *);

void
disp_only_handler_first(u_char*, const struct pcap_pkthdr*, const u_char *);

void
disp_content_handler(u_char*, const struct pcap_pkthdr*, const u_char *);

void
disp_content_cleanup();


#endif
