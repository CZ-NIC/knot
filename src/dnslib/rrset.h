#ifndef _CUTEDNS_RRSET_H
#define _CUTEDNS_RRSET_H

#include <stdint.h>
#include "dname.h"
#include "rdata.h"
#include "common.h"

struct dnslib_rrset {
	dnslib_dname_t *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	dnslib_rdata_t *rdata;
	uint rdata_count;

	// signatures
	dnslib_rrset *rrsigs;
	uint rrsig_first;
	uint rrsig_count;
};

typedef struct dnslib_rrset dnslib_rrset_t;

#endif /* _CUTEDNS_RRSET_H */
