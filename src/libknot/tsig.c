/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include "tsig.h"
#include "util/error.h"
#include "util/debug.h"
#include "common.h"
#include "util/utils.h"
#include "rrset.h"
#include "rdata.h"
#include "dname.h"

/*! \brief TSIG algorithms table. */
#define TSIG_ALG_TABLE_SIZE 8
static knot_lookup_table_t tsig_alg_table[TSIG_ALG_TABLE_SIZE] = {
	{ KNOT_TSIG_ALG_NULL, "gss-tsig." },
	{ KNOT_TSIG_ALG_HMAC_MD5, "hmac-md5.sig-alg.reg.int." },
	{ KNOT_TSIG_ALG_HMAC_SHA1, "hmac-sha1." },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "hmac-sha224." },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "hmac-sha256." },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "hmac-sha384." },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "hmac-sha512." },
	{ KNOT_TSIG_ALG_NULL, NULL }
};

int tsig_rdata_init(knot_rrset_t *tsig)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	/* Initializes rdata. */
	tsig->rdata = knot_rdata_new();
	if (!tsig->rdata) {
		return KNOT_ENOMEM;
	}

	tsig->rdata->items =
		malloc(sizeof(knot_rdata_item_t) * KNOT_TSIG_ITEM_COUNT);
	if (!tsig->rdata->items) {
		return KNOT_ENOMEM;
	}

	memset(tsig->rdata->items, 0,
	       sizeof(knot_rdata_item_t) * KNOT_TSIG_ITEM_COUNT);

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

	knot_dname_t *alg_name_copy = knot_dname_deep_copy(alg_name);
	if (!alg_name_copy) {
		return KNOT_ENOMEM;
	}

	knot_rdata_item_set_dname(rdata, 0, alg_name_copy);
	
	/* Release the dname. We want it to have 1 reference only. */
	knot_dname_release(alg_name_copy);

	return KNOT_EOK;
}

int tsig_rdata_set_alg(knot_rrset_t *tsig, tsig_algorithm_t alg)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}

	knot_rdata_t *rdata = knot_rrset_get_rdata(tsig);
	if (!rdata) {
		return KNOT_EBADARG;
	}
	assert(knot_rdata_item_count(rdata) >= 1);

	const char *alg_str = tsig_alg_to_str(alg);
	knot_dname_t *alg_name_copy = knot_dname_new_from_str(alg_str,
							      strlen(alg_str),
							      NULL);
	if (!alg_name_copy) {
		return KNOT_ENOMEM;
	}
	
	knot_rdata_item_set_dname(rdata, 0, alg_name_copy);
	
	/* Release the dname. We want it to have 1 reference only. */
	knot_dname_release(alg_name_copy);

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
	wire[0] = sizeof(uint16_t);
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
	uint16_t *wire = malloc(sizeof(uint8_t) * length + 2 * sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length. */
	wire[0] = length + sizeof(uint16_t);
	knot_wire_write_u16((uint8_t *)(wire + 1), length);
	/* Copy the actual MAC. */
	memcpy((uint8_t *)(wire + 2), mac, sizeof(uint8_t) * length);
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
	wire[0] = sizeof(uint16_t);
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
	wire[0] = sizeof(uint16_t);
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
	uint16_t *wire = malloc(sizeof(uint8_t) * length + 2 * sizeof(uint16_t));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Write the length. */
	wire[0] = length + 2;
	knot_wire_write_u16((uint8_t *)(wire + 1), length);
	/* Copy the actual data. */
	memcpy(wire + 2, other_data, sizeof(uint8_t) * length);
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
		dbg_tsig("TSIG: rdata: alg name: no rdata.\n");
		return NULL;
	}

	if (knot_rdata_item_count(rdata) < 1) {
		dbg_tsig("TSIG: rdata: alg name: not enough items.\n");
		return NULL;
	}

	return knot_rdata_item(rdata, 0)->dname;
}

tsig_algorithm_t tsig_rdata_alg(const knot_rrset_t *tsig)
{
	if (!tsig) {
		return KNOT_TSIG_ALG_NULL;
	}

	/* Get the algorithm name. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig);
	if (!alg_name) {
		dbg_tsig("TSIG: rdata: cannot get algorithm name.\n");
		return KNOT_TSIG_ALG_NULL;
	}

	/* Convert alg name to string. */
	char *name = knot_dname_to_str(alg_name);
	if (!name) {
		dbg_tsig("TSIG: rdata: cannot convert alg name.\n");
		return KNOT_TSIG_ALG_NULL;
	}

	knot_lookup_table_t *item = knot_lookup_by_name(tsig_alg_table, name);
	free(name);
	if (!item) {
		dbg_tsig("TSIG: rdata: unknown algorithm.\n");
		return KNOT_TSIG_ALG_NULL;
	}

	return item->id;
}

uint64_t tsig_rdata_time_signed(const knot_rrset_t *tsig)
{
	/*! \note How about assert. Or maybe change API??? */
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
	/*! \note How about assert. Or maybe change API??? */
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

const uint8_t *tsig_rdata_mac(const knot_rrset_t *tsig)
{
	/*! \note How about assert. Or maybe change API??? */
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

	return (uint8_t*)(knot_rdata_item(rdata, 3)->raw_data + 2);
}

size_t tsig_rdata_mac_length(const knot_rrset_t *tsig)
{
	if (!tsig) {
		return 0;
	}

	const knot_rdata_t *rdata = knot_rrset_rdata(tsig);
	if (!rdata || knot_rdata_item_count(rdata) < 4) {
		return 0;
	}

	return knot_wire_read_u16(
	        (uint8_t *)(knot_rdata_item(rdata, 3)->raw_data + 1));
}

uint16_t tsig_rdata_orig_id(const knot_rrset_t *tsig)
{
	/*! \note How about assert. Or maybe change API??? */
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
	/*! \note How about assert. Or maybe change API??? */
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

const uint8_t *tsig_rdata_other_data(const knot_rrset_t *tsig)
{
	/*! \note How about assert. Or maybe change API??? */
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

	return (uint8_t *)(knot_rdata_item(rdata, 6)->raw_data + 2);
}

uint16_t tsig_rdata_other_data_length(const knot_rrset_t *tsig)
{
	/*! \note How about assert. Or maybe change API??? */
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

	return knot_wire_read_u16((uint8_t *)
	                          (knot_rdata_item(rdata, 6)->raw_data + 1));
}

int tsig_alg_from_name(const knot_dname_t *alg_name)
{
	if (!alg_name) {
		return 0;
	}

	char *name = knot_dname_to_str(alg_name);
	if (!name) {
		return 0;
	}

	knot_lookup_table_t *found =
		knot_lookup_by_name(tsig_alg_table, name);

	if (!found) {
		dbg_tsig("Unknown algorithm: %s \n", name);
		free(name);
		return 0;
	}

	free(name);

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
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA256;
		case KNOT_TSIG_ALG_HMAC_SHA384:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA384;
		case KNOT_TSIG_ALG_HMAC_SHA512:
			return KNOT_TSIG_ALG_DIG_LENGTH_SHA512;
		default:
			return 0;
	} /* switch(alg) */
}

size_t tsig_rdata_tsig_variables_length(const knot_rrset_t *tsig)
{
	if (tsig == NULL) {
		return 0;
	}
	/* Key name, Algorithm name and Other data have variable lengths. */
	const knot_dname_t *key_name = knot_rrset_owner(tsig);
	if (!key_name) {
		return 0;
	}

	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig);
	if (!alg_name) {
		return 0;
	}

	uint16_t other_data_length = tsig_rdata_other_data_length(tsig);

	return knot_dname_size(key_name) + knot_dname_size(alg_name) +
	       other_data_length + KNOT_TSIG_VARIABLES_LENGTH;
}

size_t tsig_rdata_tsig_timers_length()
{
	return KNOT_TSIG_TIMERS_LENGTH;
}


int tsig_rdata_store_current_time(knot_rrset_t *tsig)
{
	if (!tsig) {
		return KNOT_EBADARG;
	}
	time_t curr_time = time(NULL);
	/*! \todo bleeding eyes. */
	tsig_rdata_set_time_signed(tsig, (uint64_t)curr_time);
	return KNOT_EOK;
}

const char* tsig_alg_to_str(tsig_algorithm_t alg)
{
	for (unsigned i = 0; i < TSIG_ALG_TABLE_SIZE; ++i) {
		if (tsig_alg_table[i].id == alg) {
			return tsig_alg_table[i].name;
		}
	}

	return "";
}

size_t tsig_wire_maxsize(const knot_key_t* key)
{
	if (key == NULL) {
		return 0;
	}
	
	size_t alg_name_size = strlen(tsig_alg_to_str(key->algorithm)) + 1;

	return knot_dname_size(key->name) +
	sizeof(uint16_t) + /* TYPE */
	sizeof(uint16_t) + /* CLASS */
	sizeof(uint32_t) + /* TTL */
	sizeof(uint16_t) + /* RDLENGTH */
	alg_name_size + /* Alg. name */
	6 * sizeof(uint8_t) + /* Time signed */
	sizeof(uint16_t) + /* Fudge */
	sizeof(uint16_t) + /* MAC size */
	tsig_alg_digest_length(key->algorithm) + /* MAC */
	sizeof(uint16_t) + /* Original ID */
	sizeof(uint16_t) + /* Error */
	sizeof(uint16_t) + /* Other len */
	6* sizeof(uint8_t); /* uint48_t in case of BADTIME RCODE */
}

size_t tsig_wire_actsize(const knot_rrset_t *tsig)
{
	if (tsig == NULL) {
		return 0;
	}
	
	return knot_dname_size(knot_rrset_owner(tsig)) +
	sizeof(uint16_t) + /* TYPE */
	sizeof(uint16_t) + /* CLASS */
	sizeof(uint32_t) + /* TTL */
	sizeof(uint16_t) + /* RDLENGTH */
	knot_dname_size(tsig_rdata_alg_name(tsig)) +
	6 * sizeof(uint8_t) + /* Time signed */
	sizeof(uint16_t) + /* Fudge */
	sizeof(uint16_t) + /* MAC size */
	tsig_rdata_mac_length(tsig) +
	sizeof(uint16_t) + /* Original ID */
	sizeof(uint16_t) + /* Error */
	sizeof(uint16_t) + /* Other len */
	tsig_rdata_other_data_length(tsig);
}

int tsig_rdata_is_ok(const knot_rrset_t *tsig)
{
	return (tsig
	        && knot_rrset_rdata(tsig) != NULL 
	        && knot_rdata_item_count(knot_rrset_rdata(tsig)) >= 7
	        && tsig_rdata_alg_name(tsig) != NULL
	        && tsig_rdata_time_signed(tsig) != 0);
}

