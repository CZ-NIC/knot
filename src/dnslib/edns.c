#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "dnslib/edns.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/descriptor.h"
#include "dnslib/debug.h"
#include "dnslib/error.h"

/*! \brief Various EDNS constatns. */
enum dnslib_edns_consts {
	/*! \brief Mask for the DO bit. */
	DNSLIB_EDNS_DO_MASK = (uint16_t)0x8000,
	/*! \brief Step for allocation of space for option entries. */
	DNSLIB_EDNS_OPTION_STEP = 1
};

/*! \brief Minimum size of EDNS OPT RR in wire format. */
static const short DNSLIB_EDNS_MIN_SIZE = 11;

/*----------------------------------------------------------------------------*/

dnslib_opt_rr_t *dnslib_edns_new()
{
	dnslib_opt_rr_t *opt_rr = (dnslib_opt_rr_t *)malloc(
	                                               sizeof(dnslib_opt_rr_t));
	CHECK_ALLOC_LOG(opt_rr, NULL);
	opt_rr->size = DNSLIB_EDNS_MIN_SIZE;
	opt_rr->option_count = 0;
	opt_rr->options_max = 0;

	opt_rr->ext_rcode = 0;
	opt_rr->flags = 0;
	opt_rr->version = 0;

	return opt_rr;
}

/*----------------------------------------------------------------------------*/

int dnslib_edns_new_from_wire(dnslib_opt_rr_t *opt_rr, const uint8_t *wire,
                              size_t max_size)
{
	const uint8_t *pos = wire;
	int parsed = 0;

	if (pos == NULL || max_size == 0 || opt_rr == NULL) {
		return DNSLIB_EBADARG;
	}

	if (max_size < DNSLIB_EDNS_MIN_SIZE) {
		debug_dnslib_edns("Not enough data to parse OPT RR header.\n");
		return DNSLIB_EFEWDATA;
	}

	// owner of EDNS OPT RR must be root (0)
	if (*pos != 0) {
		debug_dnslib_edns("EDNS packet malformed (expected root "
		                  "domain as owner).\n");
		return DNSLIB_EMALF;
	}
	pos += 1;

	// check the type of the record (must be OPT)
	if (dnslib_wire_read_u16(pos) != DNSLIB_RRTYPE_OPT) {
		debug_dnslib_edns("EDNS packet malformed (expected OPT type"
		                  ".\n");
		return DNSLIB_EMALF;
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
	pos += 2;

	if (max_size - parsed < rdlength) {
		debug_dnslib_edns("Not enough data to parse OPT RR.\n");
		return DNSLIB_EFEWDATA;
	}

	while (parsed < rdlength + DNSLIB_EDNS_MIN_SIZE) {
		if (max_size - parsed < 4) {
			debug_dnslib_edns("Not enough data to parse OPT RR"
			                  " OPTION header.\n");
			return DNSLIB_EFEWDATA;
		}
		uint16_t code = dnslib_wire_read_u16(pos);
		pos += 2;
		uint16_t length = dnslib_wire_read_u16(pos);
		pos += 2;
		debug_dnslib_edns("EDNS OPTION: Code: %u, Length: %u\n",
		                  code, length);
		if (max_size - parsed - 4 < length) {
			debug_dnslib_edns("Not enough data to parse OPT RR"
			                  " OPTION data.\n");
			return DNSLIB_EFEWDATA;
		}
		int ret;
		if ((ret =
		     dnslib_edns_add_option(opt_rr, code, length, pos)) != 0) {
			debug_dnslib_edns("Error parsing OPT option field.\n");
			return ret;
		}
		pos += length;
		parsed += length + 4;
	}

	return parsed;
}

/*----------------------------------------------------------------------------*/

int dnslib_edns_new_from_rr(dnslib_opt_rr_t *opt_rr,
                            const dnslib_rrset_t *rrset)
{
	if (opt_rr == NULL || rrset == NULL
	    || dnslib_rrset_type(rrset) != DNSLIB_RRTYPE_OPT) {
		return DNSLIB_EBADARG;
	}

	opt_rr->payload = dnslib_rrset_class(rrset);

	uint32_t ttl = dnslib_rrset_ttl(rrset);
	// first byte of TTL is extended RCODE
	memcpy(&opt_rr->ext_rcode, &ttl, 1);
	// second is the version
	memcpy(&opt_rr->version, (const uint8_t *)(&ttl) + 1, 1);
	// third and fourth are flags
	memcpy(&opt_rr->flags, (const uint8_t *)(&ttl) + 2,
	       2);
	// size of the header, options are counted elsewhere
	opt_rr->size = 11;

	int rc = 0;
	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		assert(*dnslib_rdata_item(rdata, 0)->raw_data == 2);
		assert(*dnslib_rdata_item(rdata, 1)->raw_data == 2);
		assert(*dnslib_rdata_item(rdata, 2)->raw_data
		       == *(dnslib_rdata_item(rdata, 1)->raw_data + 1));
		rc = dnslib_edns_add_option(opt_rr,
			*(dnslib_rdata_item(rdata, 0)->raw_data + 1),
			*(dnslib_rdata_item(rdata, 1)->raw_data + 1),
			(const uint8_t *)(dnslib_rdata_item(rdata, 2)->raw_data
			                  + 1));

		if (rc != DNSLIB_EOK) {
			return rc;
		}

		rdata = dnslib_rrset_rdata_next(rrset, rdata);
	}

	return DNSLIB_EOK;
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
		CHECK_ALLOC_LOG(options_new, DNSLIB_ENOMEM);
		memcpy(options_new, opt_rr->options, opt_rr->option_count);
		opt_rr->options = options_new;
		opt_rr->options_max += DNSLIB_EDNS_OPTION_STEP;
	}

	opt_rr->options[opt_rr->option_count].data = (uint8_t *)malloc(length);
	CHECK_ALLOC_LOG(opt_rr->options[opt_rr->option_count].data, DNSLIB_ENOMEM);
	memcpy(opt_rr->options[opt_rr->option_count].data, data, length);

	opt_rr->options[opt_rr->option_count].code = code;
	opt_rr->options[opt_rr->option_count].length = length;

	++opt_rr->option_count;
	opt_rr->size += 4 + length;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_edns_has_option(const dnslib_opt_rr_t *opt_rr, uint16_t code)
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
                          size_t max_size)
{
	assert(DNSLIB_EDNS_MIN_SIZE <= max_size);

	if (max_size < opt_rr->size) {
		debug_dnslib_edns("Not enough place for OPT RR wire format.\n");
		return DNSLIB_ESPACE;
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

/*----------------------------------------------------------------------------*/

void dnslib_edns_free(dnslib_opt_rr_t **opt_rr)
{
	if (opt_rr == NULL || *opt_rr == NULL) {
		return;
	}

	if ((*opt_rr)->option_count > 0) {
		free((*opt_rr)->options);
	}
	free(*opt_rr);
	*opt_rr = NULL;
}
