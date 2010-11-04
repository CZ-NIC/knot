#ifndef _CUTEDNS_RDATA_H
#define _CUTEDNS_RDATA_H

#include <stdint.h>
#include "dname.h"
#include "common.h"

union dnslib_rdata_item {
	uint8_t *raw_data;	// will this be convenient enough? what about parsing?
	dnslib_dname_t *dname;
};

typedef union dnslib_rdata_item dnslib_rdata_item_t;

/*----------------------------------------------------------------------------*/

struct dnslib_rdata {
	dnslib_rdata_item_t *items;
	uint *item_lengths;
	uint item_count;
};

typedef struct dnslib_rdata dnslib_rdata_t;

#endif /* _CUTEDNS_RDATA_H */
