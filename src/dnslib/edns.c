#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "edns.h"
#include "common.h"
#include "descriptor.h"

enum dnslib_edns_consts {
	DNSLIB_EDNS_DO_MASK = (uint16_t)0x8000
};

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

int dnslib_edns_new_from_wire(dnslib_opt_rr_t *opt_rr, const uint8_t *wire,
                              size_t max_size)
{
	const uint8_t *pos = wire;
	int parsed = 0;

	if (pos == NULL || max_size == 0 || opt_rr == NULL) {
		return -1;
	}

	if (max_size < DNSLIB_EDNS_MIN_SIZE) {
		debug_dnslib_edns("Not enough data to parse ENDS.\n");
		return -2;
	}

	// owner of EDNS OPT RR must be root (0)
	if (*pos != 0) {
		debug_dnslib_edns("EDNS packet malformed (expected root "
		                  "domain as owner).\n");
		return -3;
	}
	pos += 1;

	// check the type of the record (must be OPT)
	if (dnslib_wire_read_u16(pos) != DNSLIB_RRTYPE_OPT) {
		debug_dnslib_edns("EDNS packet malformed (expected OPT type"
		                  ".\n");
		return -2;
	}
	pos += 2;

	opt_rr->payload = dnslib_wire_read_u16(pos);
	debug_dnslib_edns("Parsed payload: %u\n", opt_rr->payload);

	pos += 2;
	opt_rr->ext_rcode = *(pos++);
	opt_rr->version = *(pos++);
	opt_rr->flags = dnslib_wire_read_u16(pos);
	pos += 2;

	parsed = DNSLIB_EDNS_MIN_SIZE;

	// ignore RDATA, but move pos behind them
	uint16_t rdlength = dnslib_wire_read_u16(pos);

	if (max_size - parsed < rdlength) {
		debug_dnslib_response("Not enough data to parse ENDS.\n");
		return -3;
	}

	pos += 2 + rdlength;
	parsed += rdlength;

	return parsed;
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

uint16_t dnslib_edns_get_flags(const dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->flags;
}

/*----------------------------------------------------------------------------*/

int dnslib_edns_do(const dnslib_opt_rr_t *opt_rr)
{
	debug_dnslib_edns("Flags: %u\n", opt_rr->flags);
	return (opt_rr->flags & DNSLIB_EDNS_DO_MASK);
}

/*----------------------------------------------------------------------------*/

void dnslib_edns_set_do(dnslib_opt_rr_t *opt_rr)
{
	opt_rr->flags |= DNSLIB_EDNS_DO_MASK;
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
	dnslib_wire_write_u16(pos, opt_rr->flags);
	pos += 2;
	dnslib_wire_write_u16(pos, 0);

	return opt_rr->size;
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_size(dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->size;
}
