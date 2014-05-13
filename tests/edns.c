/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <tap/basic.h>

#include "common/errcode.h"
#include "libknot/edns.h"

static const uint16_t EDNS_FLAGS = KNOT_EDNS_FLAGS_DO;
static const uint16_t E_MAX_PLD = 10000;
static const uint8_t E_VERSION = 1;
static const char *E_NSID_STR = "FooBar";
static const uint16_t E_NSID_LEN = strlen(E_NSID_STR);
static const uint8_t E_RCODE = 0;

enum offsets {
	/*! \brief Offset of Extended RCODE in wire order of TTL. */
	OFFSET_ERCODE = 0,
	/*! \brief Offset of Version in wire order of TTL. */
	OFFSET_VER = 1,
	/*! \brief Offset of Flags in wire order of TTL. */
	OFFSET_FLAGS = 2,
	/*! \brief Offset of OPTION code in one OPTION in RDATA. */
	OFFSET_OPT_CODE = 0,
	/*! \brief Offset of OPTION size in one OPTION in RDATA. */
	OFFSET_OPT_SIZE = 2,
	/*! \brief Offset of OPTION data in one OPTION in RDATA. */
	OFFSET_OPT_DATA = 4
};

static int opt_rr_check(knot_rrset_t *opt_rr, knot_edns_params_t *params)
{
	assert(opt_rr != NULL);
	assert(params != NULL);
	int failed = 0;
	int check = 0;

	/* TODO find out whether some test failed. */

	/* Check values in OPT RR by hand. */
	/* CLASS == Max UDP payload */
	check = opt_rr->rclass == params->payload;
	ok(check, "OPT RR: init: wrong max payload");

	/* The OPT RR should have exactly one RDATA. */
	ok(opt_rr->rrs.rr_count == 1, "OPT RR: RR count is not 1");
	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	ok(rdata != NULL, "OPT RR: missing RDATA");

	/* TTL should be stored in machine byte order.
	   We need network byte order to compare its parts. */
	uint8_t ttl_wire[4] = { 0, 0, 0, 0 };
	knot_wire_write_u32(ttl_wire, knot_rdata_ttl(rdata));

	/* Convert Flags from EDNS parameters to wire format for comparison. */
	uint8_t param_flags_wire[2] = { 0, 0 };
	knot_wire_write_u16(param_flags_wire, params->flags);

	/* TTL = Ext RCODE + Version + Flags */
	ok(ttl_wire[OFFSET_ERCODE] == E_RCODE, "OPT RR: init: RCODE is not 0");
	ok(ttl_wire[OFFSET_VER] == params->version,
	   "OPT RR: init: wrong version");
	ok(memcpy(param_flags_wire, ttl_wire + OFFSET_FLAGS, 2) == 0,
	   "OPT RR: init: wrong flags");

	/* NSID in RDATA = Code + Length + Data. */

	uint8_t *data = knot_rdata_data(rdata);
	uint16_t data_len = knot_rdata_rdlen(rdata);
	/* Check RDLENGTH according to given NSID. */
	ok(data_len == 4 + E_NSID_LEN, "OPT RR: init: wrong RDLENGTH");

	/* Check that the first OPTION is NSID. */
	uint16_t opt_code = knot_wire_read_u16(data + OFFSET_OPT_CODE);
	ok(opt_code == KNOT_EDNS_OPTION_NSID, "OPT RR: init: wrong OPTION code");

	/* Check that the first OPTION's size si the size of the NSID string. */
	uint16_t opt_size = knot_wire_read_u16(data + OFFSET_OPT_SIZE);
	ok(opt_size == E_NSID_LEN, "OPT RR: init: wrong NSID data size");

	/* Check the actual NSID data. */
	ok(memcpy(data + OFFSET_OPT_DATA, E_NSID_STR, E_NSID_LEN) == 0,
	   "OPT RR: init: wrong NSID data");

	/* TOTAL: 10 tests. */
	return 0;
}

#define TEST_COUNT 10

int main(int argc, char *argv[])
{
	plan(TEST_COUNT);
	int done = 0;

	knot_rrset_t *opt_rr = NULL;

	/* 1) Creating EDNS params structure with proper data + NSID. */

	knot_edns_params_t *p1 =
		knot_edns_new_params(E_MAX_PLD, E_VERSION, E_FLAGS, E_NSID_LEN,
	                             E_NSID_STR);
	ok(p1 != NULL, "EDNS params: new");
	done++;
	/* NOTE: if this fails, the test should probably not continue, otherwise
	 *       it would give bad results.
	 */

	/* 2-3) Creating EDNS params with no NSID. */
	knot_edns_params_t *p2 = knot_edns_new_params(E_MAX_PLD, E_VERSION,
	                                              E_FLAGS, 0, E_NSID_STR);
	ok(p2 != NULL, "EDNS params: new with NSID length = 0");
	done++;

	knot_edns_params_t *p3 = knot_edns_new_params(E_MAX_PLD, E_VERSION,
	                                              E_FLAGS, E_NSID_LEN,
	                                              NULL);
	ok(p3 != NULL, "EDNS params: new with NSID = NULL");
	done++;

	if (p1 == NULL || p2 == NULL || p3 == NULL) {
		skip_block(TEST_COUNT - done - 1,
		           "Failed to initialize EDNS params.");
		goto exit;
	}

	/* 4-6) Check that all parameters are properly set. */
	bool p1_ok = p1->payload == E_MAX_PLD
	             && p1->version == E_VERSION
	             && p1->flags == E_FLAGS
	             && p1->nsid_len == E_NSID_LEN
	             && memcmp(p1->nsid, E_NSID_STR, E_NSID_LEN) == 0;
	ok(p1_ok, "EDNS params: parameter values (with NSID)");
	done++;

	bool p2_ok = p2->payload == E_MAX_PLD
	             && p2->version == E_VERSION
	             && p2->flags == E_FLAGS
	             && p2->nsid_len == 0
	             && p2->nsid == 0;

	ok(p2_ok, "EDNS params: parameter values (NSID length = 0)");
	done++;

	bool p3_ok = p3->payload == E_MAX_PLD
	             && p3->version == E_VERSION
	             && p3->flags == E_FLAGS
	             && p3->nsid_len == 0
	             && p3->nsid == 0;
	ok(p3_ok, "EDNS params: parameter values (NSID = NULL)");
	done++;

	if (!(p1_ok && p2_ok && p3_ok)) {
		skip_block(TEST_COUNT - done - 1,
		           "EDNS params have wrong values.");
		goto exit;
	}

	/* 7-9) Creating OPT RR from params. */
	ret = knot_edns_init_from_params(NULL, p1, true, NULL);
	ok(ret == KNOT_EINVAL, "OPT RR: init (no OPT)");
	done++;

	ret = knot_edns_init_from_params(opt_rr, NULL, true, NULL);
	ok(ret == KNOT_EINVAL, "OPT RR: init (no EDNS params)");
	done++;

	ret = knot_edns_init_from_params(opt_rr, p1, true, NULL);
	ok(ret == KNOT_EOK, "OPT RR: init (correct)");
	done++;

	if (ret != KNOT_EOK) {
		skip_block(TEST_COUNT - done - 1,
		           "OPT RR not initialized.");
		goto exit;
	}

	/* 10-19) Check initialized values. */
	ret = opt_rr_check(opt_rr, p1);
	done += 10;
	if (ret != 0) {
		skip_block(TEST_COUNT - done - 1,
		           "OPT RR not initialized properly");
		goto exit;
	}

	/* 20- ) Getters / setters */
	/* Payload */



	/* Adding option. */


exit:
	/* Free the parameters. */
	knot_edns_free_params(&p1);
	knot_edns_free_params(&p2);
	knot_edns_free_params(&p3);
	ok(p1 == NULL && p2 == NULL && p3 == NULL, "EDNS params: free (all)");

	knot_rrset_free(&opt_rr);

	return 0;
}
