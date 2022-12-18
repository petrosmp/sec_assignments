#define _GNU_SOURCE

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* looking at ethernet headers */

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
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

    // get source and DST
    fprintf(stdout,"ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
    fprintf(stdout," destination: %s ", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

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

u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {

    const struct my_ip* ip;
    u_int length = pkthdr-&len;
    u_int hlen,off,version;
    int i;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off &apm; 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
    }

    return NULL;
}