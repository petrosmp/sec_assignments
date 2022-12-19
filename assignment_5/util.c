#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

struct args *init_args() {
	struct args *n = (struct args *) malloc(sizeof(struct args *));
	n->counters = init_counters();
	n->list = init_list();
	n->fport = NO_FILTER;
	n->out = stdout;
	return n;
}

void free_args(struct args *n) {
	free(n);
}

struct counters *init_counters() {

	struct counters *cnts = (struct counters *) malloc(sizeof(struct counters));

	cnts->total_packets = 0;
	cnts->total_flows = 0;
	cnts->tcp_packets = 0;
	cnts->tcp_bytes = 0;
	cnts->tcp_flows = 0;
	cnts->udp_packets = 0;
	cnts->udp_bytes = 0;
	cnts->udp_flows = 0;

	return cnts;
}

void free_counters(struct counters *cnts) {
	free(cnts);
}

struct net_flow *init_netflow() {
	
	// allocate struct
	struct net_flow *new_flow = (struct net_flow *) malloc(sizeof(struct net_flow));

	// allocate member pointers
	char *src_ip = (char *) malloc(MAX_IP_ADDR_SIZE);
	memset(src_ip, 0, MAX_IP_ADDR_SIZE);
	char *dst_ip = (char *) malloc(MAX_IP_ADDR_SIZE);
	memset(dst_ip, 0, MAX_IP_ADDR_SIZE);
	char *p = (char *) malloc(PROTO_STR_LEN);
	memset(p, 0, PROTO_STR_LEN);
	
	if (p == NULL) {
		printf("initialized protocol to null...\n");
	}

	// assign values
	new_flow->src_ip = src_ip;
	new_flow->dst_ip = dst_ip;
	new_flow->src_port = 0;
	new_flow->dst_port = 0;
	new_flow->protocol = p;
    new_flow->expected_SEQ = NO_SEQ;

	return new_flow;
}

void free_netflow(struct net_flow *nf) {
	free(nf->protocol);
	free(nf->dst_ip);
	free(nf->src_ip);
	free(nf);
}

struct nf_node *init_nf_node() {
	struct nf_node *new_node = (struct nf_node *) malloc(sizeof(struct nf_node));
	new_node->nf = init_netflow();
	new_node->next = NULL;
	return new_node;
}

struct nf_list *init_list() {
	struct nf_list *l = (struct nf_list *) malloc(sizeof(struct nf_list));
	l->head = NULL;
	l->last = NULL;
	l->size = 0;
	return l;
}

void free_nf_node(struct nf_node *n) {
	free_netflow(n->nf);
	free(n);
}

void nfl_insert(struct nf_list *l, struct net_flow *nf) {
	
	struct nf_node *new_node = init_nf_node();
	new_node->nf = nf;
	
	if (l->head == NULL) {
		l->head = new_node;
	} else {
		l->last->next = new_node;
	}
	l->last = new_node;
	new_node->next = NULL;
	l->size++;
	return;
}

void nfl_free(struct nf_list *l) {
	if (l == NULL) {
		printf("nfl_free() called on null list!\n");
		return;
	}

	struct nf_node *cur = l->head, *tmp;
	for(int i=0; i<l->size; i++) {
		tmp = cur->next;
		free_nf_node(cur);
		cur = tmp;
	}
}

struct net_flow *nfl_search(struct nf_list *l, char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol) {
	

	if (l == NULL) {
		fprintf(stderr, "nfl_search() called on NULL list!\n");
	}

	struct nf_node *cur = l->head;

	// TODO not needed null checks
	for(int i=0; i<l->size; i++) {
		if ((cur->nf->src_ip != NULL && strcmp(cur->nf->src_ip, src_ip) == 0)
				&& (cur->nf->dst_ip != NULL && strcmp(cur->nf->dst_ip, dst_ip) == 0)
				&& cur->nf->src_port == src_port
				&& cur->nf->dst_port == dst_port
				&& (cur->nf->protocol != NULL && strcmp(cur->nf->protocol, protocol) == 0))
			{
				return cur->nf;
			}

		cur = cur->next;
	}


	return NULL;
}

struct net_flow *create_netflow(char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol, int seq) {
    struct net_flow *nf = init_netflow();
	strcpy(nf->dst_ip, dst_ip);
	strcpy(nf->src_ip, src_ip);
	strcpy(nf->protocol, protocol);
	nf->src_port = src_port;
	nf->dst_port = dst_port;
    nf->expected_SEQ = seq;

    return nf;
}

/**
 * Assuming filter is like "port 8080"
*/
int filter_expr_to_portnum(char *fexpr) {
    strtok(fexpr, " ");
    return atoi(strtok(NULL, " "));
}

void nfl_print(struct nf_list *l) {

	struct nf_node *cur = l->head;

	fprintf(stdout, "Printing net flow list:\n");

	for(int i=0; i<l->size; i++) {

		fprintf(stdout, "[%d]: (%s:%d to %s:%d over %s)\n", i+1, cur->nf->src_ip, cur->nf->src_port, cur->nf->dst_ip, cur->nf->dst_port, cur->nf->protocol);
		cur = cur->next;
	}

	printf("=================================================================\n");

}