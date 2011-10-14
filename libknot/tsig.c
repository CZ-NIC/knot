#include <stdint.h>
#include <assert.h>

#include "tsig.h"
#include "util/error.h"
#include "common.h"
#include "util/utils.h"
#include "rrset.h"
#include "rdata.h"

int tsig_rdata_init(knot_rrset_t *tsig)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	/* Initializes rdata. */
	tsig->rdata = knot_rdata_new();
	if (!tsig->rdata) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	tsig->rdata->items =
		malloc(sizeof(knot_rdata_item_t *) * KNOT_TSIG_ITEM_COUNT);
	if (!tsig->rdata->items) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(tsig->rdata->items, 0,
	       sizeof(knot_rdata_item_t *) * KNOT_TSIG_ITEM_COUNT);

	return KNOT_EOK;
}

int tsig_rdata_set_alg_name(knot_rrset_t *tsig, knot_dname_t *alg_name)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 1);

	knot_rdata_item_set_dname(rdata, 0, alg_name);

	return KNOT_EOK;
}

int tsig_rdata_set_time_signed(knot_rrset_t *tsig, uint64_t time)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 2);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * 6 + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length - 6. */
	wire[0] = 6;
	knot_wire_write_u48((uint8_t *)(wire + 1), time);

	knot_rdata_item_set_raw_data(rdata, 1, wire);

	return KNOT_EOK;
}

int tsig_rdata_set_fudge(knot_rrset_t *tsig, uint16_t fudge)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 3);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * 2 + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length - 2. */
	wire[0] = 2;
	knot_wire_write_u16((uint8_t *)(wire + 1), fudge);

	knot_rdata_item_set_raw_data(rdata, 2, wire);

	return KNOT_EOK;
}

int tsig_rdata_set_mac(knot_rrset_t *tsig, uint16_t length, const uint8_t *mac)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 4);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * length + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length. */
	wire[0] = length;
	/* Copy the actual MAC. */
	memcpy(wire + 1, mac, sizeof(uint8_t) * length);
	knot_rdata_item_set_raw_data(rdata, 3, wire);

	return KNOT_EOK;
}

int tsig_rdata_set_orig_id(knot_rrset_t *tsig, uint16_t id)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 5);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * 2 + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length - 2. */
	wire[0] = 2;
	knot_wire_write_u16((uint8_t *)(wire + 1), id);

	knot_rdata_item_set_raw_data(rdata, 4, wire);

	return KNOT_EOK;
}

int tsig_rdata_set_tsig_error(knot_rrset_t *tsig, uint16_t tsig_error)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 6);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * 2 + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length - 2. */
	wire[0] = 2;
	knot_wire_write_u16((uint8_t *)(wire + 1), tsig_error);

	knot_rdata_item_set_raw_data(rdata, 5, wire);

	return KNOT_EOK;
}

int tsig_rdata_set_other_data(knot_rrset_t *tsig, uint16_t length,
                              const uint8_t *other_data)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 6);

	/* Create the wire format. */
	uint16_t *wire = malloc(sizeof(uint8_t) * length + sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length. */
	wire[0] = length;
	/* Copy the actual data. */
	memcpy(wire + 1, other_data, sizeof(uint8_t) * length);
	knot_rdata_item_set_raw_data(rdata, 6, wire);

	return KNOT_EOK;
}

const knot_dname_t *tsig_rdata_alg_name(const knot_rrset_t *tsig)
{
	if (!tsig) {
		return NULL;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return NULL;
	}

	if (knot_rdata_item_count(rdata) < 1) {
		return NULL;
	}

	return knot_rdata_item(rdata, 0)->dname;
}

uint64_t tsig_rdata_time_signed(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 2) {
		return 0;
	}

	uint16_t *wire = knot_rdata_item(rdata, 1)->raw_data;
	assert(wire[0] == 6);
	/* Skip the size. */
	wire++;

	return knot_wire_read_u48((uint8_t *)wire);
}

uint16_t tsig_rdata_fudge(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 3) {
		return 0;
	}

	uint16_t *wire = knot_rdata_item(rdata, 2)->raw_data;
	assert(wire[0] == 2);
	/* Skip the size. */
	wire++;

	return knot_wire_read_u16((uint8_t *)wire);
}

const uint16_t *tsig_rdata_mac(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 4) {
		return 0;
	}

	return knot_rdata_item(rdata, 3)->raw_data;
}

uint16_t tsig_rdata_orig_id(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 5) {
		return 0;
	}

	uint16_t *wire = knot_rdata_item(rdata, 4)->raw_data;
	assert(wire[0] == 2);
	/* Skip the size. */
	wire++;

	return knot_wire_read_u16((uint8_t *)wire);
}

uint16_t tsig_rdata_error(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 6) {
		return 0;
	}

	uint16_t *wire = knot_rdata_item(rdata, 5)->raw_data;
	assert(wire[0] == 2);
	/* Skip the size. */
	wire++;

	return knot_wire_read_u16((uint8_t *)wire);
}

const uint16_t *tsig_rdata_other_data(const knot_rrset_t *tsig)
{
	/*!< \note How about assert. Or maybe change API??? */
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata) {
		return 0;
	}

	if (knot_rdata_item_count(rdata) < 7) {
		return 0;
	}

	return knot_rdata_item(rdata, 6)->raw_data;
}

int tsig_algorithm_name_to_code(const knot_dname_t *alg_name)
{
	if (!alg_name) {
		return 0;
	}

	const char *name = knot_dname_to_str(alg_name);
	if (!name) {
		return 0;
	}

	knot_lookup_table_t *found =
		knot_lookup_by_name(tsig_algorithm_table, name);

	if (!found) {
		return 0;
	}

	return found->id;
}

uint16_t tsig_alg_digest_length(tsig_algorithm_t alg)
{
	switch (alg) {
		case KNOT_TSIG_ALG_GSS_TSIG:
			return KNOT_TSIG_ALG_DIG_LENGTH_GSS_TSIG;
		case KNOT_TSIG_ALG_HMAC_MD5:
			return KNOT_TSIG_ALG_DIG_LENGTH_HMAC_MD5;
		case KNOT_TSIG_ALG_HMAC_SHA1:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA1;
		case KNOT_TSIG_ALG_HMAC_SHA224:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA224;
		case KNOT_TSIG_ALG_HMAC_SHA256:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA384;
		case KNOT_TSIG_ALG_HMAC_SHA512:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA512;
		default:
			return 0;
	} /* switch(alg) */
}

