#define _GNU_SOURCE

#include <pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <ctype.h>


#define LIVE_CAPTURE 1
#define READ_FROM_FILE 2
#define MAX_FILTER_LENGTH 1024
#define MAX_FILENAME_LENGTH 1024
#define TRUE  1
#define FALSE 0
#define MAX_PACKET_LENGTH 65535

int keep_going = 1;
pcap_t *handle;										/* the sniffing session handle (base variable) */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet); 
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);


void sig_handler(int signum){

	keep_going = 0;
	pcap_breakloop(handle);
	printf("pressed Ctrl-C\n\r");
  //Return type of the handler function should be void
}

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {

	int i=0, *counter = (int *)arg; 

	printf("Packet Count: %d\n", ++(*counter)); 
	printf("Received Packet Size: %d\n", pkthdr->len); 
	printf("Payload:\n"); 
	for (i=0; i<pkthdr->len; i++){ 

	if ( isprint(packet[i]) ) /* If it is a printable character, print it */
    	printf("%c ", packet[i]);
	else
    	printf(". "); 
    
    	if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
    		printf("\n"); 
	} 
	return; 
} 

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {


	// from ethernet 2 (DIX 2.0) frame header specification (or just look at <net/ethernet.h>'s ether_header struct)
	// we can see that the last 2 bytes (12 and 13) specify the type of the network level protocol (aka ethertype)
	// so we get them
	int etype = (short) (packet[12]<<8)|(packet[13]);

	if (etype == ETHERTYPE_IP) {
		printf("IPv4!\n");
	} else if (etype == ETHERTYPE_IPV6) {
		printf("IPv6!\n");
	} else {
		printf("Unsupported ether type %04x\n", etype);
	}



	u_int8_t version_byte1 = *(packet+14);

	printf("from IP header, version is 0x%x\n", ((version_byte1>>4)));


/* 	printf("ETHERTYPE_IP is %04x\n", ETHERTYPE_IP);
	printf("ETHERTYPE_IPV6 is %04x\n", ETHERTYPE_IPV6); */

	for (int i=0; i<14; i++) {
		printf("packet[%d]: 0x%02x\n", i, *(packet+i));
	}

    u_int16_t type = handle_ethernet(args,pkthdr,packet);


    if(type == ETHERTYPE_IP) {
        /* handle IP packet */
    } else if(type == ETHERTYPE_ARP) {
        /* handle arp packet */
    } else if(type == ETHERTYPE_REVARP) {
        /* handle reverse arp packet */
    }
    /* ignore */
}

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    
    // ethernet (link layer) header (data link type)
    struct ether_header *eth_header;

    // cast the packet into the header
    eth_header = (struct ether_header *) packet;

	//printf("size of ether_header: %ld\n", sizeof(struct ether_header));

    // get source and DST
    fprintf(stdout,"ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
    fprintf(stdout,"destination: %s ", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

    // get protocol info
    if (ntohs (eth_header->ether_type) == ETHERTYPE_IP) {
        fprintf(stdout,"(IP)");
    } else  if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP) {
        fprintf(stdout,"(ARP)");
    } else  if (ntohs (eth_header->ether_type) == ETHERTYPE_REVARP) {
        fprintf(stdout,"(RARP)");
    } else {
        fprintf(stdout,"(?)");
        exit(1);
    }

    fprintf(stdout,"\n");

    return eth_header->ether_type;
}


int main(int argc, char *argv[]) {

	signal(SIGINT, sig_handler); // Register signal handler

	int count = 0;

	// declare various variables that will be needed
	char *dev="eth0";									/* the name of the interface we scan on */
	char errbuf[PCAP_ERRBUF_SIZE];						/* the error string (where libpcap will store error info) */
	bpf_u_int32 mask;									/* the netmask of our sniffing device */
	bpf_u_int32 net;									/* the IP of our sniffing device */
	struct bpf_program fp;								/* the compiled filter expression */
	char filter_exp[] = "(ip or ip6) and (tcp or udp)";	/* the filter expression */
	
	// get (one of) the network number(s) and the corresponding network mast of the devide we willbe sniffing on
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	// start the capture on the handle with the specified parameters
	handle = pcap_open_live(dev, MAX_PACKET_LENGTH, 1, 1000, errbuf);

	// check if there was an error starting the capture (usually an error with opening the device)
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// compile the filter (see how net (and not mask) is used, TODO try with 0 as the mask)
	if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	// set the (compiled) filter for the session
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}


	// gia thn pcap loop kai thn pcap dispatch (ti diafora exoun) yparxei h pcap_breakloop()
	// pou mporei na xrhsimopoihthei se sighandlers gia thn fash tou stamathmatos
	// xreiazetai allo ena call sthn dispatch omws meta gia na katharisei to buffer apo oti exei
	// meinei mesa kai den exei prolavei na ginei delivered sto programa

	int dl = pcap_datalink(handle);
	if (dl == DLT_EN10MB) {
		printf("ethernet!\n");
	} else if (dl == DLT_IEEE802_11) {
		printf("wifi!\n");
	} else {
		printf("Unknown data link type!\n");
	}

	// prepare to grab a packet
	printf("out of the loop, before\n");

	while(keep_going) {
		printf("in the loop, before\n");
		pcap_loop(handle, 1, my_callback, (u_char *) &count);
		printf("in the loop, after\n");
	}	
	printf("out of the loop, after\n");

	// close the sniffing session
	pcap_close(handle);

	return(0);
}
