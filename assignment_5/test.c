#define _GNU_SOURCE

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"



void process_packet(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet); 


int loop = 1;

// this variable has to be global so that the packet handling routines
// as well as the signal handler can use it.
pcap_t *handle;		/* the sniffing session handle (base variable) */
int datalink_type;	/* the type of the data link, global for caching */

void print_stats(struct counters *cnts) {
	printf("stats");
}

void process_packet(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	

	// cast the argument into its real type
	struct args *a = (struct args *) arg;

	// break the argument down into usable parts
	struct counters *cnts = a->counters;
	//struct nf_list *flows = a->list;

	// increment the total packet counter
	(cnts->total_packets)++;

	// declare variables that will be used in decrypting the packet
	int offset = 0;
	struct ip_header *ip_hdr;
	struct tcp_header *tcp_hdr;
	struct udp_header *udp_hdr;
	unsigned char *payload;
	u_int ip_header_size;
	u_int tl_header_size;	/* transport layer header size */
	int src_port;
	int dst_port;
	int payload_size;
	char *protocol;
	char *src_ip_addr;
	char *dst_ip_addr;


	/**
	 * ACTUAL PACKET PROCESSING FROM HERE ON DOWN
	 * 
	 * Each packet is handled in layer order:
	 * 	1) Link Layer: the data link type is determined, which
	 * 	   we only need so we know how long the link layer header
	 * 	   is, aka how many bytes we need to skip in order to
	 * 	   get to the next layer
	 * 	2) Network Layer: we assume that only IP packets come
	 *     through the network (both IPv4 and IPV6 though). From
	 * 	   this layer we extract the source and destination IP
	 * 	   addresses, as well as the header size, which tells us
	 * 	   how long we have to skip to get to the next layer
	 * 	3) Transport Layer: the only transport layer protocols we
	 * 	   support are TCP and UDP, so any other packet is dropped.
	 * 	   From this layer we extract the source and destination
	 * 	   port numbers, as well as (guess what) the header size,
	 * 	   that allows us to determine the payload size (and thus
	 * 	   its position in memory).
	*/


	// determine the offset
	// (only eth and wlan interfaces are supported, set the offset accordingly)
	// TODO check lo
	if (datalink_type == DLT_EN10MB) {
		offset = ETHERNET_HEADER_LENGTH;
	} else if (datalink_type == DLT_IEEE802_11) {
		offset = IEEE_802_11_HEADER_LENGTH;
	} else {
		return;
	}

	// ... on to the network layer ...
	ip_hdr = (struct ip_header*)(packet + offset);
	ip_header_size = IP_HL(ip_hdr)*4;	// times four because the header is in 4-byte words

	// get src and dst address
	src_ip_addr = inet_ntoa(ip_hdr->ip_src);
	dst_ip_addr = inet_ntoa(ip_hdr->ip_dst);

	// ... on to the transport layer ...
	switch(ip_hdr -> protocol) {
		case IPPROTO_TCP:
			protocol = TCP_STR;

			// TCP header and its size
			tcp_hdr = (struct tcp_header*)(packet + offset + ip_header_size);
			tl_header_size = TH_OFF(tcp_hdr)*4;

			// the size should not be less than (20 bytes is the min header length - with no options)
			if (tl_header_size < 20) {
				//printf("Invalid TCP header length: %d bytes\n", tl_header_size);
				return;
			}

			// get the port numbers
			src_port = ntohs(tcp_hdr->src_port);
			dst_port = ntohs(tcp_hdr->dst_port);

			// get payload info (address in memory and size)
			payload = (u_char *)(packet + offset + ip_header_size + tl_header_size);
			payload_size = ntohs(ip_hdr->len) - (ip_header_size + tl_header_size);

			// increment the counters
			cnts->tcp_packets++;
			cnts->tcp_bytes += ntohs(ip_hdr->len) - ip_header_size;

			break;
		case IPPROTO_UDP:
			protocol = UDP_STR;

			// UDP header (always 8 bytes)
			udp_hdr = (struct udp_header*)(packet + offset + ip_header_size);
			tl_header_size = UDP_HEADER_LENGTH;

			// get the port numbers
			src_port = ntohs(udp_hdr->src_port);
			dst_port = ntohs(udp_hdr->dst_port);

			// get payload info (address in memory and size)
			payload = (u_char *)(packet + offset + ip_header_size + UDP_HEADER_LENGTH);
			payload_size = ntohs(ip_hdr->len) - (ip_header_size + UDP_HEADER_LENGTH);

			// increment the counters
			cnts->udp_packets++;
			cnts->udp_bytes += ntohs(ip_hdr->len) - ip_header_size;

			break;
		default:
			return;
	}
	
	// delimit from previous packets
	printf("\n=================================================================== packet #%d ===================================================================\n", cnts->total_packets);

	
	// ... done with layer processing, print packet info ...
	printf("Protocol: %s over IPv%d\n", protocol, IP_V(ip_hdr));
	printf("Source IP: %s\n", src_ip_addr);
	printf("Source port: %d\n", src_port);
	printf("Destination IP: %s\n", dst_ip_addr);
	printf("Destination port: %d\n", dst_port);
	printf("payload is %d bytes at %p, %d+%d+%d bytes off the start of the packet (link, network and transport layer header sizes)\n", payload_size, payload, offset, ip_header_size, tl_header_size);

	for (int i=0; i<payload_size; i++) {
		if (isprint(payload[i])){
			printf("%c", payload[i]);
		} else {
			printf(".");
		}
		if (i%32 == 0) {
			printf("\n");
		}
	}
	// ... also take care of the rest of the stats ...

	// create the network flow object for this packet
	struct net_flow *nf = init_netflow();

	strcpy(nf->dst_ip, dst_ip_addr);
	strcpy(nf->src_ip, src_ip_addr);
	strcpy(nf->protocol, protocol);
	nf->src_port = src_port;
	nf->dst_port = dst_port;

	/* // check if another packet of the same flow has already been captured
	if (nfl_search(flows, nf) == FALSE) {

		// if it has not, add the new flow, increment corresponding counter and do not free it (it will be freed when the list is freed in main)
		nfl_insert(flows, nf);

		if (strcmp(protocol, TCP_STR) == 0){
			cnts->tcp_flows++;
		} else {
			cnts->udp_flows++;
		}
		cnts->total_flows++;
	} else {
		// if it has, it means the flow been counted, free the new struct
		free_netflow(nf);
	}
	 */
	printf("==================================================================================================================================================\n");

}

void sig_handler(int signum){

	loop = 0;
	pcap_breakloop(handle);
	printf("pressed Ctrl-C\n\r");
  //Return type of the handler function should be void
}

int main(int argc, char *argv[]) {

	signal(SIGINT, sig_handler); // Register signal handler

	// declare various variables that will be needed
	char *dev="eth0";									/* the name of the interface we scan on */
	char errbuf[PCAP_ERRBUF_SIZE];						/* the error string (where libpcap will store error info) */

	// start the capture on the handle with the specified parameters
	handle = pcap_open_live(dev, MAX_PACKET_LENGTH, 1, 1, errbuf);

	if (handle == NULL) {
		printf("Could not open device %s for live capture. Did you run with sudo?\n", dev);
		exit(-1);
	}

	// determine (data) link layer type
	datalink_type = pcap_datalink(handle);

	// check if there was an error starting the capture (usually an error with opening the device)
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// gia thn pcap loop kai thn pcap dispatch (ti diafora exoun) yparxei h pcap_breakloop()
	// pou mporei na xrhsimopoihthei se sighandlers gia thn fash tou stamathmatos
	// xreiazetai allo ena call sthn dispatch omws meta gia na katharisei to buffer apo oti exei
	// meinei mesa kai den exei prolavei na ginei delivered sto programa

	// initialize the structure that will be passed as argument to the callback
	struct args *arg = init_cnts_list_filter();

	// prepare to grab a packet

	while(loop) {
		pcap_loop(handle, 1, process_packet, (u_char *) arg);
	}	

	// free the argument structure
	free_cnts_list_filter(arg);

	// close the sniffing session
	pcap_close(handle);


	return(0);
}
