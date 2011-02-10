#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "edns.h"
#include "common.h"
#include "descriptor.h"

/*----------------------------------------------------------------------------*/

dnslib_opt_rr_t *dnslib_edns_new()
{
	dnslib_opt_rr_t *opt_rr = (dnslib_opt_rr_t *)malloc(
	                                               sizeof(dnslib_opt_rr_t));
	CHECK_ALLOC_LOG(opt_rr, NULL);
	opt_rr->size = DNSLIB_EDNS_MIN_SIZE;

	return opt_rr;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_edns_get_payload(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->payload;
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_payload(dnslib_opt_rr_t *opt_rr,
                                           uint16_t payload)
{
	opt_rr->payload = payload;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_edns_get_ext_rcode(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->ext_rcode;
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_ext_rcode(dnslib_opt_rr_t *opt_rr,
                                             uint8_t ext_rcode)
{
	opt_rr->ext_rcode = ext_rcode;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_edns_get_version(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->version;
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_version(dnslib_opt_rr_t *opt_rr,
                                           uint8_t version)
{
	opt_rr->version = version;
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_to_wire(const dnslib_opt_rr_t *opt_rr, uint8_t *wire,
                          short max_size)
{
	assert(DNSLIB_EDNS_MIN_SIZE <= max_size);

	// as of now we do not support any options in EDNS
	assert(opt_rr->size == DNSLIB_EDNS_MIN_SIZE);

	uint8_t *pos = wire;
	*(pos++) = 0;
	dnslib_wire_write_u16(pos, DNSLIB_RRTYPE_OPT);
	pos += 2;
	dnslib_wire_write_u16(pos, opt_rr->payload);
	pos += 2;
	*(pos++) = opt_rr->ext_rcode;
	*(pos++) = opt_rr->version;
	dnslib_wire_write_u16(pos, 0);
	pos += 2;
	dnslib_wire_write_u16(pos, 0);

	return opt_rr->size;
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_size(dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->size;
}
