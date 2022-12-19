#define _GNU_SOURCE

#include <pcap/pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "util.h"

#define LOGFILE_NAME "log.txt"

// global variables
int loop = 1;		/* used for the capture packet loop, global so the signal handler can modify it */
pcap_t *handle;		/* the sniffing session handle (base variable) */
int datalink_type;	/* the type of the data link, global for caching */

void usage();
void process_packet(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet); 
void print_stats(struct counters *cnts);
void sig_handler(int signum);

/**
 * Print the help message
*/
void usage() {
	printf(
	    "\n"
	    "usage:\n"
	    "\t./pcap_ex \n"
		"Options:\n"
		"-i <interface>, Network interface name (e.g., eth0)\n"
		"-r <filename>, Packet capture file name (e.g., test.pcap)\n"
		"-f <filter>, Filter expression (e.g., port 8080)\n"
		"-h, Help message\n\n"
	);

	exit(1);
}

/**
 * Called when a packet is captured to analyze it. Look for
 * comment inside for more information on the per layer proccess
 * of exporting data from the packet.
*/
void process_packet(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	

	// cast the argument into its real type
	struct args *a = (struct args *) arg;

	// break the argument down into usable parts
	struct counters *cnts = a->counters;
	struct nf_list *flows = a->list;
	int filter_port = a->fport;
	FILE *out = a->out;


// TODO delete this
/* 	fprintf(stderr, "+++++++++++++ arguments +++++++++++++\n");
	print_stats(cnts);
	fprintf(stderr, "net flow list size: %d\n", flows->size);
	fprintf(stderr, "filter_port: %d\n", filter_port);
	fprintf(stderr, "output stream: %s\n", out==stdout?"stdout":"file");
	fprintf(stderr, "+++++++++++++++++++++++++++++++++++++\n"); */

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
	char *src_ip_addr = (char*) malloc(MAX_ADDR_LEN);
	char *dst_ip_addr = (char*) malloc(MAX_ADDR_LEN);
	//int tcp_retransmit;
	struct net_flow *nf = NULL;

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
	memcpy(src_ip_addr, inet_ntoa(ip_hdr->ip_src), strlen(inet_ntoa((ip_hdr->ip_src))));
	memcpy(dst_ip_addr, inet_ntoa(ip_hdr->ip_dst), strlen(inet_ntoa((ip_hdr->ip_dst))));

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

			// apply filter
			if (filter_port != NO_FILTER) {
				if (src_port != filter_port && dst_port != filter_port){
					return;
				}
			}

			// get payload info (address in memory and size)
			payload = (u_char *)(packet + offset + ip_header_size + tl_header_size);
			payload_size = ntohs(ip_hdr->len) - (ip_header_size + tl_header_size);

			// check if the packet is a retransmission
			nf = nfl_search(flows, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol); // first see if this is a new flow (if it is, we cannot know if it is a retransmission)
			if(nf != NULL) {
				nf->expected_SEQ = ntohl(tcp_hdr->seq) + payload_size;
			} else {
				// create the new flow
				nf = create_netflow(src_ip_addr, dst_ip_addr, src_port, dst_port, TCP_STR, ntohl(tcp_hdr->seq) + payload_size);
			}

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

			// apply filter
			if (filter_port != NO_FILTER) {
				if (src_port != filter_port && dst_port != filter_port){
					free(src_ip_addr);
					free(dst_ip_addr);
					return;
				}
			}

			// get payload info (address in memory and size)
			payload = (u_char *)(packet + offset + ip_header_size + UDP_HEADER_LENGTH);
			payload_size = ntohs(ip_hdr->len) - (ip_header_size + UDP_HEADER_LENGTH);

			// create new netflow if needed
			nf = nfl_search(flows, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol);
			if(nf != NULL) {
			} else {
				// create the new flow
				nf = create_netflow(src_ip_addr, dst_ip_addr, src_port, dst_port, UDP_STR, NO_SEQ);
			}

			// increment the counters
			cnts->udp_packets++;
			cnts->udp_bytes += ntohs(ip_hdr->len) - ip_header_size;

			break;
		default:
			free(src_ip_addr);
			free(dst_ip_addr);
			return;
	}

	// delimit from previous packets
	fprintf(out, "\n=================================================================== packet #%d ===================================================================\n", cnts->total_packets);

	// ... done with layer processing, print packet info ...
	fprintf(out, "Protocol: %s over IPv%d\n", protocol, IP_V(ip_hdr));
	fprintf(out, "Source IP: %s\n", src_ip_addr);
	fprintf(out, "Source port: %d\n", src_port);
	fprintf(out, "Destination IP: %s\n", dst_ip_addr);
	fprintf(out, "Destination port: %d\n", dst_port);
	fprintf(out, "payload is %d bytes at %p, %d+%d+%d bytes off the start of the packet (link, network and transport layer header sizes)\n", payload_size, payload, offset, ip_header_size, tl_header_size);

	// ... also take care of the rest of the stats ...
	// check if another packet of the same flow has already been captured
	if (nfl_search(flows, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol) == NULL) {

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
	}

	fprintf(out, "==================================================================================================================================================\n");


	free(src_ip_addr);
	free(dst_ip_addr);
}

/**
 * Print the stats for the current session, given the sessions
 * counters.
*/
void print_stats(struct counters *cnts) {
	printf("Total network flows captured: %d\n",cnts->total_flows);
	printf("TCP network flows captured: %d\n",	cnts->tcp_flows);
	printf("UDP network flows captured: %d\n",	cnts->udp_flows);
	printf("Total packets received: %d\n",		cnts->total_packets);
	printf("TCP packets received: %d\n",		cnts->tcp_packets);
	printf("UDP packets received: %d\n",		cnts->udp_packets);
	printf("Total bytes in TCP packets: %d\n",	cnts->tcp_bytes);
	printf("Total bytes in UDP packets: %d\n",	cnts->udp_bytes);
}

/**
 * Designed to handle the SIGINT signal and break the loop of packet
 * capturing when in live mode.
*/
void sig_handler(int signum){
	loop = 0;
	pcap_breakloop(handle);
	printf("\nKeyboard interrupt received, stopping...\n");
}


int main(int argc, char* argv[]) {
    

	signal(SIGINT, sig_handler);

	char errbuf[PCAP_ERRBUF_SIZE];

	FILE *out = NULL;

	// prepare to parse the arguments
	int mode = -1;								// should not be -1 after parsing, would mean that no option was given and help was not printed
	char *source = NULL;								// packet source (interface or file)
	char *filter = NULL;

    // parse the arguments
    char ch;
    while ((ch = getopt(argc, argv, "hi:r:f:")) != -1) {
		switch (ch) {		
			case 'i':
				mode = LIVE_CAPTURE;
				source = optarg;	// assuming that interface names are small and will not cause overflows :)
				break;
			case 'r':
				mode = READ_FROM_FILE;
				source = optarg;
				break;
			case 'f':
				filter = optarg;
				break;
			default:
				// print help
				usage();
		}
	}

	// we should have a mode specified and know whether we have a filter or not by now
	switch (mode) {
		case READ_FROM_FILE:
			handle = pcap_open_offline(source, errbuf);
			out = stdout;
			break;
		case LIVE_CAPTURE:
			handle = pcap_open_live(source, MAX_PACKET_LENGTH, 1, 100, errbuf);

			// check if device opened properly
			if (handle == NULL) {
				printf("Could not open device %s for live capture. Did you run with sudo?\n", source);

				// try to suggest devices that may work
				pcap_if_t *dev;
				if (pcap_findalldevs(&dev, errbuf) != PCAP_ERROR) {
					printf("A device that could be used is for example %s\n", dev->name);
				}

				exit(-1);
			}

			out = fopen(LOGFILE_NAME, "w");

			break;
		default:
			printf("Unrecognized mode of operation!\n");
			usage();
	}

	// determine (data) link layer type
	datalink_type = pcap_datalink(handle);

	// initialize the structure that will be passed as argument to the callback
	struct args *arg = init_args();

	// pass filter and output stream args
	arg->fport = (filter==NULL) ? NO_FILTER : filter_expr_to_portnum(filter);
	arg->out = out;

	// parse packets from source
	int packets = 1;
	
	while(loop && packets != 0) {
		packets = pcap_dispatch(handle, 1, process_packet, (u_char *) arg);
	}


	// DONE: open offline
	// DONE: open live
	// DONE: retransmit
	// DONE: print stats
	// DONE: write to logfile instead of stdout
	// write README
	// document stuff
	// DONE: filters!
	// IPv6
	// break loop and stats

	// cleanup
	print_stats(arg->counters);

	// free the argument structure
	free_args(arg);	// out is cleaned here too

	// close the sniffing session


}
