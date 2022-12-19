
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {

	int i=0, *counter = (int *)arg; 

	printf("Packet Count: %d\n", ++(*counter)); 
	printf("Received Packet Size: %d\n", pkthdr->len); 
	printf("Payload:\n"); 
	for (i=0; i<pkthdr->len; i++){ 

	if ( isprint(packet[i]) ) /* If it is a printable character, print it */
		printf("%c", packet[i]);
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
    }

    fprintf(stdout,"\n");

    return eth_header->ether_type;
}

