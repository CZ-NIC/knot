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

#include <assert.h>
#include "common/errcode.h"
#include "libknot/edns.h"
#include "common/descriptor.h"

static const uint16_t E_FLAGS = (uint16_t)1 << 13;
static const uint16_t E_MAX_PLD = 10000;
static const uint16_t E_MAX_PLD2 = 20000;
static const uint8_t E_VERSION = 1;
static const uint8_t E_VERSION2 = 1;
static const uint8_t E_RCODE = 0;
static const uint8_t E_RCODE2 = 200;
static const char *E_NSID_STR = "FooBar";
static const uint16_t E_NSID_LEN = 6;

static const uint16_t E_OPT2_CODE = 23;
static const char *E_OPT2_DATA = "Deadbeef";
static const uint16_t E_OPT2_LEN = 8;

static const uint16_t E_OPT3_CODE = 15;
static const char *E_OPT3_FAKE_DATA = "Not used";
static const char *E_OPT3_DATA = NULL;
static const uint16_t E_OPT3_LEN = 0;
static const uint16_t E_OPT3_FAKE_LEN = 8;

static const uint16_t E_OPT4_CODE = 30;
static const char *E_OPT4_DATA = NULL;
static const uint16_t E_OPT4_LEN = 0;

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

static bool check_ttl(knot_rdata_t *rdata, uint8_t ext_rcode, uint8_t ver,
                      uint16_t flags, char *msg, int *done)
{
	/* TTL should be stored in machine byte order.
	   We need network byte order to compare its parts. */
	uint8_t ttl_wire[4] = { 0, 0, 0, 0 };
	knot_wire_write_u32(ttl_wire, knot_rdata_ttl(rdata));

	/* Convert Flags from EDNS parameters to wire format for comparison. */
	uint8_t flags_wire[2] = { 0, 0 };
	knot_wire_write_u16(flags_wire, flags);

	bool success = true;

	/* TTL = Ext RCODE + Version + Flags */
	bool check = (ttl_wire[OFFSET_ERCODE] == ext_rcode);
	ok(check, "%s: extended RCODE", msg);
	success &= check;
	(*done)++;

	check = (ttl_wire[OFFSET_VER] == ver);
	ok(check, "%s: version", msg);
	success &= check;
	(*done)++;

	check = (memcmp(flags_wire, ttl_wire + OFFSET_FLAGS, 2) == 0);
	ok(check, "%s: flags", msg);
	success &= check;
	(*done)++;

	return success;
}

static bool check_option(knot_rdata_t *rdata, uint16_t opt_code,
                         uint16_t opt_len, uint8_t *opt_data, char *msg,
                         int *done)
{
	assert(rdata != NULL);
	bool success = true;

	uint8_t *data = knot_rdata_data(rdata);
	uint16_t data_len = knot_rdata_rdlen(rdata);

	/* Check RDLENGTH according to given data length. */
	bool check = (data_len >= 4 + opt_len);
	ok(check, "%s: RDLENGTH", msg);
	success &= check;
	(*done)++;

	/* Find the desired option. */
	bool found = false;
	int pos = 0;
	while (pos <= data_len - 4) {
		uint16_t code = knot_wire_read_u16(data + pos + OFFSET_OPT_CODE);
		if (code == opt_code) {
			found = true;
			break;
		}
		uint16_t len = knot_wire_read_u16(data + pos + OFFSET_OPT_SIZE);
		pos += 4 + len;
	}

	/* Check that the option is present. */
	ok(found, "%s: find OPTION %u in OPT RR", msg, opt_code);
	success &= found;
	(*done)++;

	/* Check that the first OPTION's size si the size of the option data. */
	uint16_t opt_size = knot_wire_read_u16(data + pos + OFFSET_OPT_SIZE);
	check = (opt_size == opt_len);
	ok(check, "%s: OPTION data size", msg);
	success &= check;
	(*done)++;

	/* Check the actual NSID data. */
	check = (memcmp(data + pos + OFFSET_OPT_DATA, opt_data, opt_len)) == 0;
	ok(check, "%s: OPTION data", msg);
	success &= check;
	(*done)++;

	return success;
}

static bool check_header(knot_rrset_t *opt_rr, uint16_t payload, uint8_t ver,
                         uint16_t flags, uint8_t ext_rcode, char *msg,
                         int *done)
{
	assert(opt_rr != NULL);
	assert(done != NULL);
	bool check;
	bool success = true;

	/* Check values in OPT RR by hand. */
	/* CLASS == Max UDP payload */
	check = (opt_rr->rclass == payload);
	ok(check, "%s: max payload", msg);
	success &= check;
	(*done)++;

	/* The OPT RR should have exactly one RDATA. */
	check = (opt_rr->rrs.rr_count == 1);
	ok(check, "%s: RR count == 1", msg);
	success &= check;
	(*done)++;

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	check = (rdata != NULL);
	ok(check, "%s: RDATA exists", msg);
	success &= check;
	(*done)++;

	success &= check_ttl(rdata, ext_rcode, ver, flags, msg, done);

	return success;
}

static bool opt_rr_check(knot_rrset_t *opt_rr, uint16_t payload, uint8_t ver,
                         uint16_t flags, uint8_t ext_rcode, uint16_t opt_code,
                         uint16_t opt_len, uint8_t *opt_data, char *msg,
                         int *done)
{
	bool success = true;

	/* RR header */
	success &= check_header(opt_rr, payload, ver, flags, ext_rcode, msg,
	                        done);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	if (rdata == NULL) {
		skip_block(4, "No RDATA in OPT RR.");
		return false;
	}

	/* OPTION in RDATA = Code + Length + Data. */
	success &= check_option(rdata, opt_code, opt_len, opt_data, msg, done);

	return success;
}

static bool test_getters(knot_rrset_t *opt_rr, knot_edns_params_t *params,
                         int *done)
{
	assert(opt_rr != NULL);
	assert(params != NULL);
	assert(done != NULL);
	bool success = true;

	/* Payload */
	bool check = (knot_edns_get_payload(opt_rr) == params->payload);
	ok(check, "OPT RR getters: payload");
	success &= check;
	(*done)++;

	/* Extended RCODE */
	check = (knot_edns_get_ext_rcode(opt_rr) == E_RCODE);
	ok(check, "OPT RR getters: extended RCODE");
	success &= check;
	(*done)++;

	/* Extended RCODE */
	check = (knot_edns_get_version(opt_rr) == params->version);
	ok(check, "OPT RR getters: version");
	success &= check;
	(*done)++;

	/* DO bit */
	check = !knot_edns_do(opt_rr);
	ok(check, "OPT RR getters: DO bit check");
	success &= check;
	(*done)++;

	/* NSID */
	check = (knot_edns_has_option(opt_rr, KNOT_EDNS_OPTION_NSID) ==
	                (params->nsid != NULL && params->nsid_len > 0));
	ok(check, "OPT RR getters: NSID check");
	success &= check;
	(*done)++;

	return success;
}

static bool test_setters(knot_rrset_t *opt_rr, int *done)
{
	assert(opt_rr != NULL);
	assert(done != NULL);

	/* Header-related setters. */
	knot_edns_set_payload(opt_rr, E_MAX_PLD2);
	knot_edns_set_ext_rcode(opt_rr, E_RCODE2);
	knot_edns_set_version(opt_rr, E_VERSION2);
	knot_edns_set_do(opt_rr);

	bool success = true;
	bool check = check_header(opt_rr, E_MAX_PLD2, E_VERSION2,
	                          E_FLAGS | KNOT_EDNS_FLAG_DO, E_RCODE2,
	                          "OPT RR setters", done);
	success &= check;

	/* OPTION(RDATA)-related setters. */

	/* Proper option. */
	int ret = knot_edns_add_option(opt_rr, E_OPT2_CODE, E_OPT2_LEN,
	                           (uint8_t *)E_OPT2_DATA, NULL);
	ok(ret == KNOT_EOK, "OPT RR setters: add option with data (ret = %s)",
	   knot_strerror(ret));
	(*done)++;

	/* Wrong argument: no OPT RR. */
	ret = knot_edns_add_option(NULL, E_OPT3_CODE, E_OPT3_FAKE_LEN,
	                           (uint8_t *)E_OPT3_FAKE_DATA, NULL);
	ok(ret == KNOT_EINVAL, "OPT RR setters: add option (rr == NULL) "
	   "(ret = %s)", knot_strerror(ret));
	(*done)++;

	/* Wrong argument: option length != 0 && data == NULL. */
	ret = knot_edns_add_option(opt_rr, E_OPT3_CODE, E_OPT3_FAKE_LEN, NULL,
	                           NULL);
	ok(ret == KNOT_EINVAL, "OPT RR setters: add option (data == NULL, "
	   "len != 0) (ret = %s)", knot_strerror(ret));
	(*done)++;

	/* Empty OPTION (length 0, data != NULL). */
	ret = knot_edns_add_option(opt_rr, E_OPT3_CODE, E_OPT3_LEN,
	                           (uint8_t *)E_OPT3_FAKE_DATA, NULL);
	ok(ret == KNOT_EOK, "OPT RR setters: add empty option 1 (ret = %s)",
	   knot_strerror(ret));
	(*done)++;

	/* Empty OPTION (length 0, data == NULL). */
	ret = knot_edns_add_option(opt_rr, E_OPT4_CODE, E_OPT4_LEN,
	                           (uint8_t *)E_OPT4_DATA,
	                           NULL);
	ok(ret == KNOT_EOK, "OPT RR setters: add empty option 2 (ret = %s)",
	   knot_strerror(ret));
	(*done)++;

	/* Check empty option 1 */
	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	if (rdata == NULL) {
		skip_block(2, "No RDATA in OPT RR.");
		return false;
	}

	check = check_option(rdata, E_OPT3_CODE, E_OPT3_LEN,
	                     (uint8_t *)E_OPT3_DATA,
	                     "OPT RR setters (empty option 1)", done);
	success &= check;
	(*done)++;

	/* Check empty option 2 */
	check = check_option(rdata, E_OPT4_CODE, E_OPT4_LEN,
	                     (uint8_t *)E_OPT4_DATA,
	                     "OPT RR setters (empty option 2)", done);
	success &= check;
	(*done)++;

	return success;
}

#define TEST_COUNT 44

static inline int remaining(int done) {
	return TEST_COUNT - done - 1;
}

int main(int argc, char *argv[])
{
	plan(TEST_COUNT);
	int done = 0;

	knot_dname_t *root = knot_dname_from_str(".");
	knot_rrset_t *opt_rr = knot_rrset_new(root, KNOT_RRTYPE_OPT,
	                                      KNOT_CLASS_IN, NULL);
	if (opt_rr == NULL) {
		skip_block(TEST_COUNT, "EDNS: Could not allocate OPT RR.\n");
		return 0;
	}

	/* Creating EDNS params structure with proper data + NSID. */

	knot_edns_params_t *p1 = knot_edns_new_params(E_MAX_PLD, E_VERSION,
	                                              E_FLAGS, E_NSID_LEN,
	                                              (uint8_t *)E_NSID_STR);
	ok(p1 != NULL, "EDNS params: new");
	done++;
	/* NOTE: if this fails, the test should probably not continue, otherwise
	 *       it would give bad results.
	 */

	/* Creating EDNS params with no NSID. */
	knot_edns_params_t *p2 = knot_edns_new_params(E_MAX_PLD, E_VERSION,
	                                              E_FLAGS, 0,
	                                              (uint8_t *)E_NSID_STR);
	ok(p2 != NULL, "EDNS params: new with NSID length = 0");
	done++;

	knot_edns_params_t *p3 = knot_edns_new_params(E_MAX_PLD, E_VERSION,
	                                              E_FLAGS, E_NSID_LEN,
	                                              NULL);
	ok(p3 != NULL, "EDNS params: new with NSID = NULL");
	done++;

	if (p1 == NULL || p2 == NULL || p3 == NULL) {
		skip_block(remaining(done), "Failed to initialize EDNS params.");
		goto exit;
	}

	bool success = true;
	bool check;
	/* Check that all parameters are properly set. */
	check = (p1->payload == E_MAX_PLD
	         && p1->version == E_VERSION
	         && p1->flags == E_FLAGS
	         && p1->nsid_len == E_NSID_LEN
	         && memcmp(p1->nsid, E_NSID_STR, E_NSID_LEN) == 0);
	ok(check, "EDNS params: parameter values (with NSID)");
	success &= check;
	done++;

	check = (p2->payload == E_MAX_PLD
	         && p2->version == E_VERSION
	         && p2->flags == E_FLAGS
	         && p2->nsid_len == 0
	         && p2->nsid == 0);

	ok(check, "EDNS params: parameter values (NSID length = 0)");
	success &= check;
	done++;

	check = (p3->payload == E_MAX_PLD
	         && p3->version == E_VERSION
	         && p3->flags == E_FLAGS
	         && p3->nsid_len == 0
	         && p3->nsid == 0);
	ok(check, "EDNS params: parameter values (NSID = NULL)");
	success &= check;
	done++;

	if (!success) {
		skip_block(remaining(done), "EDNS params have wrong values.");
		goto exit;
	}

	/* Creating OPT RR from params. */
	int ret = knot_edns_init_from_params(NULL, p1, true, NULL);
	ok(ret == KNOT_EINVAL, "OPT RR: init (no OPT) (ret = %s)",
	   knot_strerror(ret));
	done++;

	ret = knot_edns_init_from_params(opt_rr, NULL, true, NULL);
	ok(ret == KNOT_EINVAL, "OPT RR: init (no EDNS params) (ret = %s)",
	   knot_strerror(ret));
	done++;

	ret = knot_edns_init_from_params(opt_rr, p1, true, NULL);
	ok(ret == KNOT_EOK, "OPT RR: init (correct) (ret = %s)",
	   knot_strerror(ret));
	done++;

	if (ret != KNOT_EOK) {
		skip_block(remaining(done), "OPT RR not initialized.");
		goto exit;
	}

	/* Check initialized values. */
	success = opt_rr_check(opt_rr, p1->payload, p1->version, p1->flags,
	                       E_RCODE, KNOT_EDNS_OPTION_NSID, p1->nsid_len,
	                       p1->nsid, "OPT RR init", &done);
	if (!success) {
		skip_block(remaining(done), "OPT RR not initialized properly");
		goto exit;
	}

	/* Getters
	   Note: NULL parameters are not supported, so no test for that. */
	success = test_getters(opt_rr, p1, &done);

	if (!success) {
		skip_block(remaining(done), "OPT RR: getters error");
		goto exit;
	}

	/* Setters */
	success = test_setters(opt_rr, &done);

	if (!success) {
		skip_block(remaining(done), "OPT RR: setters error");
		goto exit;
	}

exit:
	/* Free the parameters. */
	knot_edns_free_params(&p1);
	knot_edns_free_params(&p2);
	knot_edns_free_params(&p3);
	ok(p1 == NULL && p2 == NULL && p3 == NULL, "EDNS params: free (all)");

	knot_rrset_free(&opt_rr, NULL);

	return 0;
}
