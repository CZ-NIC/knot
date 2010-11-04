#ifndef _CUTEDNS_DNAME_H
#define _CUTEDNS_DNAME_H

#include <stdint.h>
#include "common.h"
#include "node.h"

struct dnslib_dname {
	uint8_t *dname;
	uint length;	// is this needed? every dname should end with \0 or pointer
	dnslib_node_t *node;	// NULL if not in zone
};

typedef struct dname dnslib_dname_t;

#endif /* _CUTEDNS_DNAME_H */
