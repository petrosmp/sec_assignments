#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <ctype.h>

#define NO_MODE 0						/* no mode specified */
#define LIVE_CAPTURE 1					/* live capture mode */
#define READ_FROM_FILE 2				/* read from savefile mode */
#define MAX_FILTER_LENGTH 1024			/* max number of characters in a filter */
#define MAX_FILENAME_LENGTH 1024		/* max number of characters in a filename */
#define TRUE  1							/* boolean true */
#define FALSE 0							/* boolean false */
#define MAX_PACKET_LENGTH 65535			/* maximum bytes in any packet */
#define ETHERNET_HEADER_LENGTH 14		/* ethernet header size */
#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN	6			/* ethernet address length */
#endif
#define IEEE_802_11_HEADER_LENGTH 22	/* WiFi header size */
#define UDP_HEADER_LENGTH 8				/* UDP header size */
#define UDP_STR "UDP"					/* UDP string */
#define TCP_STR "TCP"					/* TCP string */
#define NO_PROTOCOL_STR "NOP"			/* NO Protocol string */
#define PROTO_STR_LEN 4					/* Protocol string size */
#define MAX_IP_ADDR_SIZE 39				/* Maximum characters in an IP address (dots included) */
#define NO_SEQ 0						/* No sequence number */
#define NO_FILTER -1					/* No filter provided */

/**
 * A struct to keep track of the stats while running the program
*/
struct counters {
	int total_packets;
	int total_flows;
	int tcp_packets;
	int tcp_bytes;
	int tcp_flows;
	int udp_packets;
	int udp_bytes;
	int udp_flows;
	int retransmissions;
};

/**
 * A network flow is uniquely represented of the 5 tuple:
 * 	(src_ip, src_port, dst_ip, dst_port, protocol)
 * 
 * The extra field is there to help identify TCP retransmissions.
*/
struct net_flow {
	char *src_ip;
	char *dst_ip;
	int src_port;
	int dst_port;
	char *protocol;
    int expected_SEQ;
};

/**
 * A node of the network flow linked list
*/
struct nf_node {
	struct net_flow *nf;
	struct nf_node *next;
};

/**
 * The list where all network flows are stored
*/
struct nf_list {
	struct nf_node *head;
	struct nf_node *last;
	int size;
};

/**
 * A structure that lets us pass arguments to the callback that
 * handles individual packets.
*/
struct args {
	struct counters *counters;
	struct nf_list *list;
	int fport;
	FILE *out;
};

/* Ethernet header */
struct ethernet_header {
	u_char dst_host[ETHER_ADDR_LEN];	/* dest ether addr */
	u_char src_host[ETHER_ADDR_LEN];	/* source ether addr */
	u_short ether_type;				/* protocol type (abmiguous - https://www.ibm.com/support/pages/ethernet-version-2-versus-ieee-8023-ethernet, but yeah) */
};

/* IP header */
struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;		/* header length */
	unsigned int version:4;	/* version */
#else
	unsigned int version:4;	/* version */
	unsigned int ihl:4;		/* header length */
#endif
	unsigned int tos:8;		/* type of service */
	u_short len;			/* total length */
	u_short id;				/* identification */
	u_short f_off;			/* fragment offset field */

// possible values for ip_off field
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

	u_char ttl;				/* time to live */
	u_char protocol;		/* protocol */
	u_short checksum;		/* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst;	/* source and dest address */
};
#define IP_HL(ip)		(((ip)->ihl))
#define IP_V(ip)		(((ip)->version))

/* TCP header */
struct tcp_header {
	u_short src_port: 16;	/* source port */
	u_short dst_port: 16;	/* destination port */
	u_int seq;			/* sequence number */
	u_int ack;			/* acknowledgement number */
	u_char offx2;		/* data offset, rsvd */
	u_char flags;

// possible flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	u_short win;		/* window */
	u_short checksum;	/* TCP checksum */
	u_short urp;		/* urgent pointer */
};
#define TH_OFF(th)	(((th)->offx2 & 0xf0) >> 4)

/* UDP header */
struct udp_header {
	u_short src_port;	/* source port */
	u_short dst_port;	/* destination port */
	u_short length;		/* length (header + payload) */
	u_short checksum;	/* UDP checksum */
};

/**
 * Allocate space for the argument structure
*/
struct args *init_args();

/**
 * Free the space used by the argument structure
*/
void free_args(struct args *n);

/**
 * Initialize the counter structure
*/
struct counters *init_counters();

/**
 * Free the space used by the counter structure
*/
void free_counters(struct counters *cnts);

/**
 * Initialize the structure that represents a network flow
 * (allocate space in memory and initialize fields).
*/
struct net_flow *init_netflow();

/**
 * Properly free an instance of the network flow structure.
*/
void free_netflow(struct net_flow *nf);

/**
 * Initialize a new node for the network flow linked list
*/
struct nf_node *init_nf_node();

/**
 * Initialize the network flow linked list
*/
struct nf_list *init_list();

/**
 * Free a node from the network flow linked list
*/
void free_nf_node(struct nf_node *n);

/**
 * Insert the given node into the given network flow
 * linked list
*/
void nfl_insert(struct nf_list *l, struct net_flow *nf);

/**
 * Properly free every node of the given network flow linked
 * list and then the list
*/
void nfl_free(struct nf_list *l);

/**
 * Search for a network flow with the given attributes in the
 * given list. If it exists return it, otherwise return null.
*/
struct net_flow *nfl_search(struct nf_list *l, char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol);

/**
 * Create a new netflow with the given attributes.
 * 
 * Calls init_netflow().
*/
struct net_flow *create_netflow(char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol, int seq);

/**
 * Convert a filter expression in the form "port <portnum>" to
 * the integer representing the portnum and return it.
*/
int filter_expr_to_portnum(char *fexpr);

/**
 * Print the contents of the network flow linked list.
 * 
 * Used for testing and debugging.
*/
void nfl_print(struct nf_list *l);
