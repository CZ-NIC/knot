#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "edns.h"
#include "common.h"
#include "descriptor.h"

enum dnslib_edns_consts {
	DNSLIB_EDNS_DO_MASK = (uint16_t)0x8000,
	DNSLIB_EDNS_OPTION_STEP = 1
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
		debug_dnslib_edns("Not enough data to parse OPT RR.\n");
		return -3;
	}

	while (parsed < rdlength + DNSLIB_EDNS_MIN_SIZE) {
		if (max_size - parsed < 4) {
			debug_dnslib_edns("Not enough data to parse OPT RR.\n");
			return -3;
		}
		uint16_t code = dnslib_wire_read_u16(pos);
		pos += 2;
		uint16_t length = dnslib_wire_read_u16(pos);
		pos += 2;
		if (max_size - parsed - 4 < length) {
			debug_dnslib_edns("Not enough data to parse OPT RR.\n");
			return -3;
		}
		if (dnslib_edns_add_option(opt_rr, code, length, pos) != 0) {
			debug_dnslib_edns("Error parsing OPT option field.\n");
			return -4;
		}
		pos += length;
		parsed += length + 4;
	}

//	pos += 2 + rdlength;
//	parsed += rdlength;

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

int dnslib_edns_add_option(dnslib_opt_rr_t *opt_rr, uint16_t code,
                           uint16_t length, const uint8_t *data)
{
	if (opt_rr->option_count == opt_rr->options_max) {
		dnslib_opt_option_t *options_new =
			(dnslib_opt_option_t *)calloc(
				(opt_rr->options_max + DNSLIB_EDNS_OPTION_STEP),
				sizeof(dnslib_opt_option_t));
		CHECK_ALLOC_LOG(options_new, -1);
		memcpy(options_new, opt_rr->options, opt_rr->option_count);
		opt_rr->options = options_new;
		opt_rr->options_max += DNSLIB_EDNS_OPTION_STEP;
	}

	opt_rr->options[opt_rr->option_count].data = (uint8_t *)malloc(length);
	CHECK_ALLOC_LOG(opt_rr->options[opt_rr->option_count].data, -1);
	memcpy(opt_rr->options[opt_rr->option_count].data, data, length);

	opt_rr->options[opt_rr->option_count].code = code;
	opt_rr->options[opt_rr->option_count].length = length;

	++opt_rr->option_count;
	opt_rr->size += 4 + length;

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_edns_has_option(dnslib_opt_rr_t *opt_rr, uint16_t code)
{
	int i = 0;
	while (i < opt_rr->option_count && opt_rr->options[i].code != code) {
		++i;
	}

	assert(i >= opt_rr->option_count || opt_rr->options[i].code == code);

	return (i < opt_rr->option_count);
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_to_wire(const dnslib_opt_rr_t *opt_rr, uint8_t *wire,
                          short max_size)
{
	assert(DNSLIB_EDNS_MIN_SIZE <= max_size);

	if (max_size < opt_rr->size) {
		debug_dnslib_edns("Not enough place for OPT RR wire format.\n");
		return -1;
	}

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

	uint8_t *rdlen = pos;
	uint16_t len = 0;
	pos += 2;

	// OPTIONs
	for (int i = 0; i < opt_rr->option_count; ++i) {
		dnslib_wire_write_u16(pos, opt_rr->options[i].code);
		pos += 2;
		dnslib_wire_write_u16(pos, opt_rr->options[i].length);
		pos += 2;
		memcpy(pos, opt_rr->options[i].data, opt_rr->options[i].length);
		pos += opt_rr->options[i].length;
		len += 4 + opt_rr->options[i].length;
	}

	dnslib_wire_write_u16(rdlen, len);

	return opt_rr->size;
}

/*----------------------------------------------------------------------------*/

short dnslib_edns_size(dnslib_opt_rr_t *opt_rr)
{
	return opt_rr->size;
}
