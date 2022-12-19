#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <ctype.h>

#define NO_MODE 0
#define LIVE_CAPTURE 1
#define READ_FROM_FILE 2
#define MAX_FILTER_LENGTH 1024
#define MAX_FILENAME_LENGTH 1024
#define TRUE  1
#define FALSE 0
#define MAX_PACKET_LENGTH 65535
#define ETHERNET_HEADER_LENGTH 14
#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN	6
#endif
#define IEEE_802_11_HEADER_LENGTH 22
#define UDP_HEADER_LENGTH 8
#define UDP_STR "UDP"
#define TCP_STR "TCP"
#define NO_PROTOCOL_STR "NOP"
#define PROTO_STR_LEN 4
#define MAX_IP_ADDR_SIZE 39
#define NO_SEQ 0
#define NO_FILTER -1

struct counters {
	int total_packets;
	int total_flows;
	int tcp_packets;
	int tcp_bytes;
	int tcp_flows;
	int udp_packets;
	int udp_bytes;
	int udp_flows;
};

struct net_flow {
	char *src_ip;
	char *dst_ip;
	int src_port;
	int dst_port;
	char *protocol;
    int expected_SEQ;
};

struct nf_node {
	struct net_flow *nf;
	struct nf_node *next;
};

struct nf_list {
	struct nf_node *head;
	struct nf_node *last;
	int size;
};

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
	unsigned int ihl:4;		/* version << 4 | header length >> 2 */
	unsigned int version:4;		/* version << 4 | header length >> 2 */
	unsigned int tos:8;		/* type of service */
	u_short len;	/* total length */
	u_short id;		/* identification */
	u_short f_off;	/* fragment offset field */

// possible values for ip_off field
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

	u_char ttl;			/* time to live */
	u_char protocol;	/* protocol */
	u_short checksum;	/* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst; /* source and dest address */
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

struct args *init_args();

void free_args(struct args *n);

struct counters *init_counters();

void free_counters(struct counters *cnts);

struct net_flow *init_netflow();

void free_netflow(struct net_flow *nf);

struct nf_node *init_nf_node();

struct nf_list *init_list();

void free_nf_node(struct nf_node *n);

void nfl_insert(struct nf_list *l, struct net_flow *nf);

void nfl_free(struct nf_list *l);

struct net_flow *nfl_search(struct nf_list *l, char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol);

struct net_flow *create_netflow(char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol, int seq);

int filter_expr_to_portnum(char *fexpr);

void nfl_print(struct nf_list *l);
