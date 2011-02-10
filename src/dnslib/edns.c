#include <stdint.h>
#include <stdlib.h>

#include "edns.h"
#include "common.h"

static const short DNSLIB_EDNS_MIN_SIZE = DNSLIB_EDNS_OFFSET_RDATA;

/*----------------------------------------------------------------------------*/

dnslib_opt_rr_t *dnslib_edns_new()
{
	dnslib_opt_rr_t *opt_rr = (dnslib_opt_rr_t *)malloc(
	                                               sizeof(dnslib_opt_rr_t));
	CHECK_ALLOC_LOG(opt_rr, NULL);

	opt_rr->wire = (uint8_t *)malloc(DNSLIB_EDNS_MIN_SIZE);
	if (opt_rr->wire == NULL) {
		ERR_ALLOC_FAILED;
		free(opt_rr);
		return NULL;
	}

	opt_rr->allocated = DNSLIB_EDNS_MIN_SIZE;
	opt_rr->size = DNSLIB_EDNS_MIN_SIZE;

	return opt_rr;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_edns_get_payload(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->payload;
	//return dnslib_wire_read_u16(opt_rr->wire + DNSLIB_EDNS_OFFSET_PAYLOAD);
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_payload(dnslib_opt_rr_t *opt_rr,
                                           uint16_t payload)
{
	opt_rr->payload = payload;
	dnslib_wire_write_u16(opt_rr->wire + DNSLIB_EDNS_OFFSET_PAYLOAD,
	                      payload);
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_edns_get_ext_rcode(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->ext_rcode;
	//return *(opt_rr->wire + DNSLIB_EDNS_OFFSET_EXT_RCODE);
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_ext_rcode(dnslib_opt_rr_t *opt_rr,
                                             uint8_t ext_rcode)
{
	opt_rr->ext_rcode = ext_rcode;
	*(opt_rr->wire + DNSLIB_EDNS_OFFSET_EXT_RCODE) = ext_rcode;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_edns_get_version(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->version;
	//return *(opt_rr->wire + DNSLIB_EDNS_OFFSET_VERSION);
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_version(dnslib_opt_rr_t *opt_rr,
                                           uint8_t version)
{
	opt_rr->version = version;
	*(opt_rr->wire + DNSLIB_EDNS_OFFSET_VERSION) = version;
}

/*----------------------------------------------------------------------------*/

const uint8_t *dnslib_edns_wire(dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->wire;
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_size(dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->size;
}
