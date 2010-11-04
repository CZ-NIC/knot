#ifndef _CUTEDNS_NODE_H
#define _CUTEDNS_NODE_H

#include "dname.h"
#include "skip-list.h"

struct dnslib_node {
	dnslib_dname_t *owner;
	struct dnslib_node *parent;
	skip_list *rrsets;	// key - RRTYPE (uint16_t); value - dnslib_rrset_t *

	struct dnslib_node *next;	// temporary
};

typedef struct dnslib_node dnslib_node_t;

#endif /* _CUTEDNS_NODE_H */
