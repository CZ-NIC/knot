/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "libknot/wire.h"
#include "contrib/sockaddr.h"

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

static void check_ttl(knot_rrset_t *rrset, uint8_t ext_rcode, uint8_t ver,
                      uint16_t flags, char *msg)
{
	if (rrset == NULL) {
		return;
	}

	/* TTL should be stored in machine byte order.
	   We need network byte order to compare its parts. */
	uint8_t ttl_wire[4] = { 0, 0, 0, 0 };
	knot_wire_write_u32(ttl_wire, rrset->ttl);

	/* Convert Flags from EDNS parameters to wire format for comparison. */
	uint8_t flags_wire[2] = { 0, 0 };
	knot_wire_write_u16(flags_wire, flags);

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

	uint8_t *data = rdata->data;
	uint16_t data_len = rdata->len;

	/* Check RDLENGTH according to given data length. */
	bool check = (data_len >= 4 + opt_len);
	ok(check, "%s: RDLENGTH (%u)", msg, data_len);

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

	/* Check that the first OPTION's size si the size of the option data. */
	uint16_t opt_size = knot_wire_read_u16(data + pos + OFFSET_OPT_SIZE);
	check = (opt_size == opt_len);
	ok(check, "%s: OPTION data size", msg);

	/* Check the actual NSID data. */
	check = (opt_data == 0 || memcmp(data + pos + OFFSET_OPT_DATA, opt_data, opt_len) == 0);
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
	check = (opt_rr->rrs.count == 1);
	ok(check, "%s: RR count == 1", msg);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	check = (rdata != NULL);
	ok(check, "%s: RDATA exists", msg);

	check_ttl(opt_rr, ext_rcode, ver, flags, msg);
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
	check = knot_edns_get_option(opt_rr, KNOT_EDNS_OPTION_NSID) != NULL;
	ok(check, "OPT RR getters: NSID check");

	/* Other OPTIONs */
	check = knot_edns_get_option(opt_rr, E_OPT3_CODE) != NULL;
	ok(check, "OPT RR getters: empty option 1");

	check = knot_edns_get_option(opt_rr, E_OPT4_CODE) != NULL;
	ok(check, "OPT RR getters: empty option 2");

	uint16_t code = knot_edns_opt_get_code((const uint8_t *)"\x00\x0a" "\x00\x00");
	ok(code == KNOT_EDNS_OPTION_COOKIE, "OPT RR getters: EDNS OPT code");
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
		uint16_t len = knot_edns_keepalive_size(t->val);
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
		uint16_t len = knot_edns_chain_size(t->dname);
		ok(len == t->opt_len, "%s: dname %s, size", __func__, t->msg);

		uint8_t wire[8] = { 0 };
		int ret = knot_edns_chain_write(wire, sizeof(wire), t->dname);
		is_int(KNOT_EOK, ret, "%s: dname %s, write, return", __func__, t->msg);
		ok(memcmp(wire, t->dname, t->opt_len) == 0, "%s: dname %s, write, value",
		                                            __func__, t->msg);

		knot_dname_t *dname = NULL;
		ret = knot_edns_chain_parse(&dname, (uint8_t *)t->dname, t->opt_len, NULL);
		is_int(KNOT_EOK, ret, "%s: dname %s, parse, return", __func__, t->msg);
		ok(knot_dname_is_equal(dname, t->dname), "%s: dname %s, parse, value",
		                                         __func__, t->msg);
		knot_dname_free(dname, NULL);
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
	ok(knot_edns_chain_parse(NULL, wire, 0, NULL) == KNOT_EINVAL && dname == NULL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_chain_parse(&dname, NULL, 0, NULL) == KNOT_EINVAL && dname == NULL,
	   "%s: parse, NULL", __func__);
	ok(knot_edns_chain_parse(&dname, (const uint8_t *)"\x01", 1, NULL) == KNOT_EMALF &&
	   dname == NULL, "%s: parse, malformed", __func__);
}

static void check_cookie_parse(const char *opt, knot_edns_cookie_t *cc,
                               knot_edns_cookie_t *sc, int code, const char *msg)
{
	const uint8_t *data = NULL;
	uint16_t data_len = 0;
	if (opt != NULL) {
		data = knot_edns_opt_get_data((uint8_t *)opt);
		data_len = knot_edns_opt_get_length((uint8_t *)opt);
	}

	int ret = knot_edns_cookie_parse(cc, sc, data, data_len);
	is_int(code, ret, "cookie parse ret: %s", msg);
}

static void ok_cookie_check(const char *opt, knot_edns_cookie_t *cc,
                            knot_edns_cookie_t *sc, uint16_t cc_len, uint16_t sc_len,
                            const char *msg)
{
	check_cookie_parse(opt, cc, sc, KNOT_EOK, msg);

	is_int(cc->len, cc_len, "cookie parse cc len: %s", msg);
	is_int(sc->len, sc_len, "cookie parse cc len: %s", msg);

	uint16_t size = knot_edns_cookie_size(cc, sc);
	is_int(size, cc_len + sc_len, "cookie len: %s", msg);

	uint8_t buf[64];
	int ret = knot_edns_cookie_write(buf, sizeof(buf), cc, sc);
	is_int(KNOT_EOK, ret, "cookie write ret: %s", msg);
}

static void test_cookie(void)
{
	const char *good[] = {
		"\x00\x0a" "\x00\x08" "\x00\x01\x02\x03\x04\x05\x06\x07", /* Only client cookie. */
		"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", /* 8 octets long server cookie. */
		"\x00\x0a" "\x00\x28" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27" /* 32 octets long server cookie. */
	};

	const char *bad[] = {
		"\x00\x0a" "\x00\x00", /* Zero length cookie. */
		"\x00\x0a" "\x00\x01" "\x00", /* Short client cookie. */
		"\x00\x0a" "\x00\x07" "\x00\x01\x02\x03\x04\x05\x06", /* Short client cookie. */
		"\x00\x0a" "\x00\x09" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08", /* Short server cookie. */
		"\x00\x0a" "\x00\x0f" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e", /* Short server cookie. */
		"\x00\x0a" "\x00\x29" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28", /* Long server cookie. */
	};

	knot_edns_cookie_t cc, sc;

	ok_cookie_check(good[0], &cc,  &sc, 8, 0,  "good cookie 0");
	ok_cookie_check(good[1], &cc,  &sc, 8, 8,  "good cookie 1");
	ok_cookie_check(good[2], &cc,  &sc, 8, 32, "good cookie 2");

	check_cookie_parse(NULL,    &cc,  &sc,  KNOT_EINVAL, "no data");
	check_cookie_parse(good[0], NULL, &sc,  KNOT_EINVAL, "no client cookie");
	check_cookie_parse(good[1], &cc,  NULL, KNOT_EINVAL, "no server cookie");

	check_cookie_parse(bad[0],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 0");
	check_cookie_parse(bad[1],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 1");
	check_cookie_parse(bad[2],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 2");
	check_cookie_parse(bad[3],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 3");
	check_cookie_parse(bad[4],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 4");
	check_cookie_parse(bad[5],  &cc,  &sc,  KNOT_EMALF,  "bad cookie 5");
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
	test_alignment();
	test_keepalive();
	test_chain();
	test_cookie();

	knot_rrset_clear(&opt_rr, NULL);

	return 0;
}
