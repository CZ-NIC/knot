/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include <assert.h>
#include "libknot/libknot.h"
#include "libknot/rrtype/opt.h"
#include "libknot/descriptor.h"
#include "contrib/sockaddr.h"
#include "contrib/wire.h"

static const uint16_t E_MAX_PLD = 10000;
static const uint16_t E_MAX_PLD2 = 20000;
static const uint8_t E_VERSION = 1;
static const uint8_t E_VERSION2 = 2;
static const uint8_t E_RCODE = 0;
static const uint8_t E_RCODE2 = 200;

static const char *E_NSID_STR = "FooBar";
static const uint16_t E_NSID_LEN = 6;

#define E_NSID_SIZE (4 + E_NSID_LEN)

static const uint16_t E_OPT3_CODE = 15;
static const char *E_OPT3_FAKE_DATA = "Not used";
static const char *E_OPT3_DATA = NULL;
static const uint16_t E_OPT3_LEN = 0;
static const uint16_t E_OPT3_FAKE_LEN = 8;

#define E_OPT3_SIZE (4 + E_OPT3_LEN)

static const uint16_t E_OPT4_CODE = 30;
static const char *E_OPT4_DATA = NULL;
static const uint16_t E_OPT4_LEN = 0;

#define E_OPT4_SIZE (4 + E_OPT4_LEN)

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

static const uint16_t DO_FLAG = (uint16_t)1 << 15;

static void check_ttl(knot_rdata_t *rdata, uint8_t ext_rcode, uint8_t ver,
                      uint16_t flags, char *msg)
{
	/* TTL should be stored in machine byte order.
	   We need network byte order to compare its parts. */
	uint8_t ttl_wire[4] = { 0, 0, 0, 0 };
	wire_write_u32(ttl_wire, knot_rdata_ttl(rdata));

	/* Convert Flags from EDNS parameters to wire format for comparison. */
	uint8_t flags_wire[2] = { 0, 0 };
	wire_write_u16(flags_wire, flags);

	/* TTL = Ext RCODE + Version + Flags */
	bool check = (ttl_wire[OFFSET_ERCODE] == ext_rcode);
	ok(check, "%s: extended RCODE", msg);

	check = (ttl_wire[OFFSET_VER] == ver);
	ok(check, "%s: version", msg);

	check = (memcmp(flags_wire, ttl_wire + OFFSET_FLAGS, 2) == 0);
	ok(check, "%s: flags", msg);
}

static void check_option(knot_rdata_t *rdata, uint16_t opt_code,
                         uint16_t opt_len, uint8_t *opt_data, char *msg)
{
	assert(rdata != NULL);

	uint8_t *data = knot_rdata_data(rdata);
	uint16_t data_len = knot_rdata_rdlen(rdata);

	/* Check RDLENGTH according to given data length. */
	bool check = (data_len >= 4 + opt_len);
	ok(check, "%s: RDLENGTH (%u)", msg, data_len);

	/* Find the desired option. */
	bool found = false;
	int pos = 0;
	while (pos <= data_len - 4) {
		uint16_t code = wire_read_u16(data + pos + OFFSET_OPT_CODE);
		if (code == opt_code) {
			found = true;
			break;
		}
		uint16_t len = wire_read_u16(data + pos + OFFSET_OPT_SIZE);
		pos += 4 + len;
	}

	/* Check that the option is present. */
	ok(found, "%s: find OPTION %u in OPT RR", msg, opt_code);

	/* Check that the first OPTION's size si the size of the option data. */
	uint16_t opt_size = wire_read_u16(data + pos + OFFSET_OPT_SIZE);
	check = (opt_size == opt_len);
	ok(check, "%s: OPTION data size", msg);

	/* Check the actual NSID data. */
	check = (memcmp(data + pos + OFFSET_OPT_DATA, opt_data, opt_len)) == 0;
	ok(check, "%s: OPTION data", msg);
}

static void check_header(knot_rrset_t *opt_rr, uint16_t payload, uint8_t ver,
                         uint16_t flags, uint8_t ext_rcode, char *msg)
{
	assert(opt_rr != NULL);
	bool check;

	/* Check values in OPT RR by hand. */
	/* CLASS == Max UDP payload */
	check = (opt_rr->rclass == payload);
	ok(check, "%s: max payload", msg);

	/* The OPT RR should have exactly one RDATA. */
	check = (opt_rr->rrs.rr_count == 1);
	ok(check, "%s: RR count == 1", msg);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	check = (rdata != NULL);
	ok(check, "%s: RDATA exists", msg);

	check_ttl(rdata, ext_rcode, ver, flags, msg);
}

static void test_getters(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	/* These values should be set from the setters test:
	 * Max UDP payload: E_MAX_PLD2
	 * Version:         E_VERSION2
	 * RCODE:           E_RCODE2
	 * Flags:           E_FLAGS | KNOT_EDNS_FLAG_DO
	 * OPTIONs:         1) KNOT_EDNS_OPTION_NSID, E_NSID_LEN, E_NSID_STR
	 *                  2) E_OPT3_CODE, 0, 0
	 *                  3) E_OPT4_CODE, 0, 0
	 */

	/* Payload */
	bool check = (knot_edns_get_payload(opt_rr) == E_MAX_PLD2);
	ok(check, "OPT RR getters: payload");

	/* Extended RCODE */
	check = (knot_edns_get_ext_rcode(opt_rr) == E_RCODE2);
	ok(check, "OPT RR getters: extended RCODE");

	/* Extended RCODE */
	check = (knot_edns_get_version(opt_rr) == E_VERSION2);
	ok(check, "OPT RR getters: version");

	/* DO bit */
	check = knot_edns_do(opt_rr);
	ok(check, "OPT RR getters: DO bit check");

	/* Wire size */
	size_t total_size = KNOT_EDNS_MIN_SIZE
	                    + E_NSID_SIZE + E_OPT3_SIZE + E_OPT4_SIZE;
	size_t actual_size = knot_edns_wire_size(opt_rr);
	check = actual_size == total_size;
	ok(check, "OPT RR getters: wire size (expected: %zu, actual: %zu)",
	   total_size, actual_size);

	/* NSID */
	check = knot_edns_has_option(opt_rr, KNOT_EDNS_OPTION_NSID);
	ok(check, "OPT RR getters: NSID check");

	/* Other OPTIONs */
	check = knot_edns_has_option(opt_rr, E_OPT3_CODE);
	ok(check, "OPT RR getters: empty option 1");

	check = knot_edns_has_option(opt_rr, E_OPT4_CODE);
	ok(check, "OPT RR getters: empty option 2");
}

static void test_setters(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	/* Header-related setters. */
	knot_edns_set_payload(opt_rr, E_MAX_PLD2);
	knot_edns_set_ext_rcode(opt_rr, E_RCODE2);
	knot_edns_set_version(opt_rr, E_VERSION2);
	knot_edns_set_do(opt_rr);

	check_header(opt_rr, E_MAX_PLD2, E_VERSION2, DO_FLAG, E_RCODE2,
	             "OPT RR setters");

	/* OPTION(RDATA)-related setters. */

	/* Proper option. */
	int ret = knot_edns_add_option(opt_rr, KNOT_EDNS_OPTION_NSID,
	                           E_NSID_LEN, (uint8_t *)E_NSID_STR, NULL);
	is_int(KNOT_EOK, ret, "OPT RR setters: add option with data (ret = %s)",
	   knot_strerror(ret));

	/* Wrong argument: no OPT RR. */
	ret = knot_edns_add_option(NULL, E_OPT3_CODE, E_OPT3_FAKE_LEN,
	                           (uint8_t *)E_OPT3_FAKE_DATA, NULL);
	is_int(KNOT_EINVAL, ret, "OPT RR setters: add option (rr == NULL) "
	   "(ret = %s)", knot_strerror(ret));

	/* Wrong argument: option length != 0 && data == NULL. */
	ret = knot_edns_add_option(opt_rr, E_OPT3_CODE, E_OPT3_FAKE_LEN, NULL,
	                           NULL);
	is_int(KNOT_EINVAL, ret, "OPT RR setters: add option (data == NULL, "
	   "len != 0) (ret = %s)", knot_strerror(ret));

	/* Empty OPTION (length 0, data != NULL). */
	ret = knot_edns_add_option(opt_rr, E_OPT3_CODE, E_OPT3_LEN,
	                           (uint8_t *)E_OPT3_FAKE_DATA, NULL);
	is_int(KNOT_EOK, ret, "OPT RR setters: add empty option 1 (ret = %s)",
	   knot_strerror(ret));

	/* Empty OPTION (length 0, data == NULL). */
	ret = knot_edns_add_option(opt_rr, E_OPT4_CODE, E_OPT4_LEN,
	                           (uint8_t *)E_OPT4_DATA, NULL);
	is_int(KNOT_EOK, ret, "OPT RR setters: add empty option 2 (ret = %s)",
	   knot_strerror(ret));

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	ok(rdata != NULL, "OPT RR setters: non-empty RDATA");

	/* Check proper option */
	check_option(rdata, KNOT_EDNS_OPTION_NSID, E_NSID_LEN,
	             (uint8_t *)E_NSID_STR, "OPT RR setters (proper option)");

	/* Check empty option 1 */
	check_option(rdata, E_OPT3_CODE, E_OPT3_LEN,
	             (uint8_t *)E_OPT3_DATA, "OPT RR setters (empty option 1)");

	/* Check empty option 2 */
	check_option(rdata, E_OPT4_CODE, E_OPT4_LEN,
	             (uint8_t *)E_OPT4_DATA, "OPT RR setters (empty option 2)");
}

#define OPT_ID_0 0xaaa0
#define OPT_ID_1 0xaaa1
#define OPT_ID_2 0xaaa2
#define OPT_ID_3 0xaaa3

static bool prepare_edns_data(knot_rrset_t *opt_rr, bool fill)
{
	knot_rrset_clear(opt_rr, NULL);
	int ret = knot_edns_init(opt_rr, E_MAX_PLD, E_RCODE, E_VERSION, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}

	/* Header-related setters. */
	knot_edns_set_payload(opt_rr, E_MAX_PLD2);
	knot_edns_set_ext_rcode(opt_rr, E_RCODE2);
	knot_edns_set_version(opt_rr, E_VERSION2);
	knot_edns_set_do(opt_rr);

	static const uint8_t OPT_DATA[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	};

	if (!fill) {
		return true;
	}

	ret = knot_edns_add_option(opt_rr, OPT_ID_1, 3, OPT_DATA, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}

	ret = knot_edns_add_option(opt_rr, OPT_ID_0, 4, OPT_DATA, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}

	ret = knot_edns_add_option(opt_rr, OPT_ID_1, 3, OPT_DATA, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}

	ret = knot_edns_add_option(opt_rr, OPT_ID_2, 8, OPT_DATA, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}

	return true;
}

static bool check_rdata(const knot_rrset_t *opt_rr, uint16_t len, const uint8_t *data)
{
	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);

	const uint8_t *data_ptr = knot_rdata_data(rdata);
	uint16_t data_len = knot_rdata_rdlen(rdata);

	if (data_len != len) {
		return false;
	}

	return memcmp(data_ptr, data, data_len) == 0;
}

static void test_remove(void)
{
	int iret;
	bool bret;
	knot_rrset_t opt_rr;
	uint16_t new_expected_len;

	iret = knot_edns_init(&opt_rr, E_MAX_PLD, E_RCODE, E_VERSION, NULL);
	ok(iret == KNOT_EOK, "OPT RR remove: init");

	/* Test helper function for data preparation. */
	new_expected_len = 0;
	bret = prepare_edns_data(&opt_rr, false);
	ok(bret, "OPT RR remove: internal data preparation");
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"");
	ok(bret, "OPT RR remove: data preparation");

	new_expected_len = 34;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR remove: data preparation");

	/* Invalid parameter. */
	iret = knot_edns_remove_options(NULL, OPT_ID_0);
	ok(iret == KNOT_EINVAL, "OPT RR remove: invalid parameter (ret = %s)",
	   knot_strerror(iret));

	/* Removing from empty OPT RR. */
	new_expected_len = 0;
	bret = prepare_edns_data(&opt_rr, false);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_remove_options(&opt_rr, OPT_ID_3);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"");
	ok(iret == KNOT_EOK && bret,
	   "OPT RR remove: removing from empty OPT RR (ret = %s)",
	   knot_strerror(iret));

	/* Removing non-existent option. */
	new_expected_len = 34;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_remove_options(&opt_rr, OPT_ID_3);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && bret,
	   "OPT RR remove: removing non-existent option (ret = %s)",
	   knot_strerror(iret));

	/* Removing existent option. */
	new_expected_len = 26;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_remove_options(&opt_rr, OPT_ID_0);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && bret,
	   "OPT RR remove: removing existent option (ret = %s)",
	   knot_strerror(iret));

	/* Removing existent options. */
	new_expected_len = 20;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_remove_options(&opt_rr, OPT_ID_1);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && bret,
	   "OPT RR remove: removing existent options (ret = %s)",
	   knot_strerror(iret));

	/* Removing existent option. */
	new_expected_len = 22;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_remove_options(&opt_rr, OPT_ID_2);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2");
	ok(iret == KNOT_EOK && bret,
	   "OPT RR remove: removing existent option (ret = %s)",
	   knot_strerror(iret));

	knot_rrset_clear(&opt_rr, NULL);
}

static void test_unique(void)
{
	int iret;
	bool bret;
	knot_rrset_t opt_rr;
	uint16_t new_opt_size, new_expected_len;
	uint8_t *reserved_data;

	static const uint8_t OPT_DATA[] = {
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	};

	iret = knot_edns_init(&opt_rr, E_MAX_PLD, E_RCODE, E_VERSION, NULL);
	ok(iret == KNOT_EOK, "OPT RR unique: init");

	new_opt_size = 4;
	iret = knot_edns_reserve_unique_option(NULL, OPT_ID_3, new_opt_size,
	                                       &reserved_data, NULL);
	ok(iret == KNOT_EINVAL, "OPT RR unique: invalid parameter (ret = %s)",
	   knot_strerror(iret));

	/* Add non-existent into empty OPT RR. */
	new_opt_size = 4;
	new_expected_len = 8;
	bret = prepare_edns_data(&opt_rr, false);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_3, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa3\x00\x04\x00\x00\x00\x00");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique non-existent option into empty OPT RR (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa3\x00\x04\xe0\xe1\xe2\xe3");
	ok(bret, "OPT RR unique: check written option");

	/* Add non-existent option. */
	new_opt_size = 4;
	new_expected_len = 42;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_3, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
	                                    "\xaa\xa3\x00\x04\x00\x00\x00\x00");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique non-existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
	                                    "\xaa\xa3\x00\x04\xe0\xe1\xe2\xe3");
	ok(bret, "OPT RR unique: check written option");

	/* Firs should be cleared, remaining with same id removed. */
	new_opt_size = 3;
	new_expected_len = 27;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_1, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\x00\x00\x00"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xe0\xe1\xe2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR unique: check written option");

	/* First should be shortened, remaining with same id removed. */
	new_opt_size = 2;
	new_expected_len = 26;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_1, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x02\x00\x00"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x02\xe0\xe1"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR unique: check written option");

	/* First removed, placed into second place, last shoved. */
	new_opt_size = 6;
	new_expected_len = 30;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_1, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x06\x00\x00\x00\x00\x00\x00"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x06\xe0\xe1\xe2\xe3\xe4\xe5"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR unique: check written option");

	/* First removed, placed into second place, last left untouched. */
	new_opt_size = 10;
	new_expected_len = 34;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_1, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x0a\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR unique: check written option");

	/* Second cleared. */
	new_opt_size = 4;
	new_expected_len = 34;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_0, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\x00\x00\x00\x00"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xe0\xe1\xe2\xe3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(bret, "OPT RR unique: check written option");

	/* Second shortened to zero, remaining shoved. */
	new_opt_size = 0;
	new_expected_len = 30;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_0, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x00"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));

	/* Second deleted, remaining shoved, new put last. */
	new_opt_size = 6;
	new_expected_len = 36;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_0, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
	                                    "\xaa\xa0\x00\x06\x00\x00\x00\x00\x00\x00");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x08\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
	                                    "\xaa\xa0\x00\x06\xe0\xe1\xe2\xe3\xe4\xe5");
	ok(bret, "OPT RR unique: check written option");

	/* Last shortened. */
	new_opt_size = 4;
	new_expected_len = 30;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_2, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x04\x00\x00\x00\x00");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x04\xe0\xe1\xe2\xe3");
	ok(bret, "OPT RR unique: check written option");

	/* Last enlarged. */
	new_opt_size = 10;
	new_expected_len = 36;
	bret = prepare_edns_data(&opt_rr, true);
	ok(bret, "OPT RR remove: internal data preparation");
	iret = knot_edns_reserve_unique_option(&opt_rr, OPT_ID_2, new_opt_size,
	                                       &reserved_data, NULL);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
	ok(iret == KNOT_EOK && reserved_data != NULL && bret,
	   "OPT RR unique: reserve unique existent option (ret = %s)",
	   knot_strerror(iret));
	if (reserved_data == NULL) {
		return;
	}
	memcpy(reserved_data, OPT_DATA, new_opt_size);
	bret = check_rdata(&opt_rr, new_expected_len,
	                   (const uint8_t *)"\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa0\x00\x04\xf0\xf1\xf2\xf3"
	                                    "\xaa\xa1\x00\x03\xf0\xf1\xf2"
	                                    "\xaa\xa2\x00\x0a\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9");
	ok(bret, "OPT RR unique: check written option");

	knot_rrset_clear(&opt_rr, NULL);
}

static void test_alignment(void)
{
	int ret;

	ret = knot_edns_alignment_size(1, 1, 1);
	ok(ret == -1, "no alignment");

	ret = knot_edns_alignment_size(1, 1, 2);
	ok(ret == -1, "no alignment");

	ret = knot_edns_alignment_size(1, 1, 3);
	ok(ret == (6 - (1 + 1 + KNOT_EDNS_OPTION_HDRLEN)), "%i-Byte alignment", ret);

	ret = knot_edns_alignment_size(1, 1, 4);
	ok(ret == (8 - (1 + 1 + KNOT_EDNS_OPTION_HDRLEN)), "%i-Byte alignment", ret);

	ret = knot_edns_alignment_size(1, 1, 512);
	ok(ret == (512 - (1 + 1 + KNOT_EDNS_OPTION_HDRLEN)), "%i-Byte alignment", ret);
}

static void test_keepalive(void)
{
	typedef struct {
		char *msg;
		uint16_t opt_len;
		char *opt;
		uint16_t val;
	} test_t;

	// OK tests.

	static const test_t TESTS[] = {
		{ "ok 0",     0, "",         0 },
		{ "ok 1",     2, "\x00\x01", 1 },
		{ "ok 258",   2, "\x01\x02", 258 },
		{ "ok 65535", 2, "\xFF\xFF", 65535 },
		{ NULL }
	};

	for (const test_t *t = TESTS; t->msg != NULL; t++) {
		size_t len = knot_edns_keepalive_size(t->val);
		ok(len == t->opt_len, "%s: %s, size", __func__, t->msg);

		uint8_t wire[8] = { 0 };
		int ret = knot_edns_keepalive_write(wire, sizeof(wire), t->val);
		is_int(KNOT_EOK, ret, "%s: %s, write, return", __func__, t->msg);
		ok(memcmp(wire, t->opt, t->opt_len) == 0, "%s: %s, write, value",
		                                          __func__, t->msg);

		uint16_t timeout = 0;
		ret = knot_edns_keepalive_parse(&timeout, (uint8_t *)t->opt, t->opt_len);
		is_int(KNOT_EOK, ret, "%s: %s, parse, return", __func__, t->msg);
		ok(timeout == t->val, "%s: %s, parse, value", __func__, t->msg);
	}

	// Error tests.

	uint8_t wire[8] = { 0 };
	ok(knot_edns_keepalive_write(NULL, 0, 0) == KNOT_EINVAL,
	   "%s: write, NULL", __func__);
	ok(knot_edns_keepalive_write(wire, 1, 1) == KNOT_ESPACE,
	   "%s: write, no room", __func__);

	uint16_t timeout = 0;
	ok(knot_edns_keepalive_parse(NULL, (const uint8_t *)"", 0) == KNOT_EINVAL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_keepalive_parse(&timeout, NULL, 0) == KNOT_EINVAL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_keepalive_parse(&timeout, (const uint8_t *)"\x01", 1) == KNOT_EMALF,
	   "%s: parse, malformed", __func__);
}

static void test_chain(void)
{
	typedef struct {
		char *msg;
		uint16_t opt_len;
		knot_dname_t *dname;
	} test_t;

	// OK tests.

	static const test_t TESTS[] = {
		{ ".",  1, (knot_dname_t *)"" },
		{ "a.", 3, (knot_dname_t *)"\x01" "a" },
		{ NULL }
	};

	for (const test_t *t = TESTS; t->msg != NULL; t++) {
		size_t len = knot_edns_chain_size(t->dname);
		ok(len == t->opt_len, "%s: dname %s, size", __func__, t->msg);

		uint8_t wire[8] = { 0 };
		int ret = knot_edns_chain_write(wire, sizeof(wire), t->dname);
		is_int(KNOT_EOK, ret, "%s: dname %s, write, return", __func__, t->msg);
		ok(memcmp(wire, t->dname, t->opt_len) == 0, "%s: dname %s, write, value",
		                                            __func__, t->msg);

		knot_dname_t *dname = NULL;
		ret = knot_edns_chain_parse(&dname, (uint8_t *)t->dname, t->opt_len);
		is_int(KNOT_EOK, ret, "%s: dname %s, parse, return", __func__, t->msg);
		ok(knot_dname_cmp(dname, t->dname) == 0, "%s: dname %s, parse, value",
		                                         __func__, t->msg);
		knot_dname_free(&dname, NULL);
	}

	// Error tests.

	ok(knot_edns_chain_size(NULL) == 0, "%s: size, NULL", __func__);

	uint8_t wire[8] = { 0 };
	ok(knot_edns_chain_write(NULL, 0, wire) == KNOT_EINVAL,
	   "%s: write, NULL", __func__);
	ok(knot_edns_chain_write(wire, 0, NULL) == KNOT_EINVAL,
	   "%s: write, NULL", __func__);
	ok(knot_edns_chain_write(wire, 0, (const knot_dname_t *)"") == KNOT_ESPACE,
	   "%s: write, no room", __func__);

	knot_dname_t *dname = NULL;
	ok(knot_edns_chain_parse(NULL, wire, 0) == KNOT_EINVAL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_chain_parse(&dname, NULL, 0) == KNOT_EINVAL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_chain_parse(&dname, (const uint8_t *)"\x01", 1) == KNOT_EMALF,
	   "%s: parse, malformed", __func__);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_rrset_t opt_rr;
	int ret = knot_edns_init(&opt_rr, E_MAX_PLD, E_RCODE, E_VERSION, NULL);
	is_int(KNOT_EOK, ret, "OPT RR: init");

	/* Check initialized values (no NSID yet). */
	check_header(&opt_rr, E_MAX_PLD, E_VERSION, 0, E_RCODE, "OPT RR: check header");

	test_setters(&opt_rr);
	test_getters(&opt_rr);
	test_remove();
	test_unique();
	test_alignment();
	test_keepalive();
	test_chain();

	knot_rrset_clear(&opt_rr, NULL);

	return 0;
}
