/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "libknot/yparser/yptrafo.h"
#include "libknot/libknot.h"

static void int_test(const char *txt, int64_t num, yp_style_t s,
                     int64_t min, int64_t max)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TINT, YP_VINT = { min, max, YP_NIL, s } };

	diag("integer \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(yp_int(b) == num, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, s | YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void int_bad_test(const char *txt, int code, yp_style_t s,
                         int64_t min, int64_t max)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TINT, YP_VINT = { min, max, YP_NIL, s } };

	diag("integer \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void bool_test(const char *txt, bool val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TBOOL, YP_VNONE };

	diag("boolean \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(yp_bool(b) == val, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void bool_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TBOOL, YP_VNONE };

	diag("boolean \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void opt_test(const char *txt, unsigned val, const knot_lookup_t *opts)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TOPT, YP_VOPT = { opts } };

	diag("option \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(b_len == 1, "compare length");
	ok(yp_opt(b) == val, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void opt_bad_test(const char *txt, int code, const knot_lookup_t *opts)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TOPT, YP_VOPT = { opts } };

	diag("option \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void str_test(const char *txt, const char *val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TSTR, YP_VNONE };

	diag("string \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(b_len == strlen(txt) + 1, "compare length");
	ok(memcmp(yp_str(b), val, b_len) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void addr_test(const char *txt, bool port)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TADDR, YP_VNONE };

	diag("address \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	bool no_port;
	yp_addr(b, &no_port);
	ok(no_port == port, "compare port presence");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void addr_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TADDR, YP_VNONE };

	diag("address \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void addr_range_test(const char *txt)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TNET, YP_VNONE };

	diag("address range \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void addr_range_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TNET, YP_VNONE };

	diag("address range \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void dname_test(const char *txt, const char *val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TDNAME, YP_VNONE };

	diag("dname \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(memcmp(yp_dname(b), val, b_len) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void hex_test(const char *txt, const char *val, const char *txt_out)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_THEX, YP_VNONE };

	if (txt_out == NULL) {
		txt_out = txt;
	}

	diag("hex \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(memcmp(yp_bin(b), val, yp_bin_len(b)) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt_out) == t_len, "txt length");
	ok(memcmp(txt_out, t, t_len) == 0, "compare");
}

static void hex_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_THEX, YP_VNONE };

	diag("hex \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void base64_test(const char *txt, const char *val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TB64, YP_VNONE };

	diag("base64 \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(memcmp(yp_bin(b), val, yp_bin_len(b)) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void ref_test(const char *txt, bool val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t id = { NULL, YP_TBOOL, YP_VNONE };
	yp_item_t ref = { NULL, YP_TGRP, YP_VNONE };
	yp_item_t i = { NULL, YP_TREF, YP_VNONE };
	ref.var.g.id = &id;
	i.var.r.ref = &ref;

	diag("reference to boolean \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(yp_bool(b) == val, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Integer tests. */
	int64_t min = -20000000000, max = 20000000000;
	int_test("5", 5, YP_SNONE, min, max);
	int_test("0", 0, YP_SNONE, min, max);
	int_test("-5", -5, YP_SNONE, min, max);
	int_test("20000000000", max, YP_SNONE, min, max);
	int_test("-20000000000", min, YP_SNONE, min, max);
	int_test("11B", 11LL * 1, YP_SSIZE, min, max);
	int_test("11K", 11LL * 1024, YP_SSIZE, min, max);
	int_test("11M", 11LL * 1024 * 1024, YP_SSIZE, min, max);
	int_test("11G", 11LL * 1024 * 1024 * 1024, YP_SSIZE, min, max);
	int_test("11s", 11LL * 1, YP_STIME, min, max);
	int_test("11m", 11LL * 60, YP_STIME, min, max);
	int_test("11h", 11LL * 3600, YP_STIME, min, max);
	int_test("11d", 11LL * 24 * 3600, YP_STIME, min, max);
	int_test("1025B", 1025LL, YP_SSIZE, min, max);
	int_test("61s", 61LL, YP_STIME, min, max);
	int_bad_test("20000000001", KNOT_ERANGE, YP_SNONE, min, max);
	int_bad_test("-20000000001", KNOT_ERANGE, YP_SNONE, min, max);
	int_bad_test("1x", KNOT_EINVAL, YP_SNONE, min, max);
	int_bad_test("1sx", KNOT_EINVAL, YP_STIME, min, max);

	/* Boolean tests. */
	bool_test("on", true);
	bool_test("off", false);
	bool_bad_test("onx", KNOT_EINVAL);
	bool_bad_test("enable", KNOT_EINVAL);

	/* Option tests. */
	static const knot_lookup_t opts[] = {
		{ 1,   "one" },
		{ 10,  "ten" },
		{ 255, "max" },
		{ 0, NULL }
	};
	opt_test("one", 1, opts);
	opt_test("ten", 10, opts);
	opt_test("max", 255, opts);
	opt_bad_test("onex", KNOT_EINVAL, opts);
	opt_bad_test("word", KNOT_EINVAL, opts);

	/* String tests. */
	str_test("Test string!", "Test string!");

	/* Address tests. */
	addr_test("192.168.123.1", true);
	addr_test("192.168.123.1@12345", false);
	addr_test("2001:db8::1", true);
	addr_test("::1@12345", false);
	addr_test("/tmp/test.sock", true);
	addr_bad_test("192.168.123.x", KNOT_EINVAL);
	addr_bad_test("192.168.123.1@", KNOT_EINVAL);
	addr_bad_test("192.168.123.1@1x", KNOT_EINVAL);
	addr_bad_test("192.168.123.1@65536", KNOT_ERANGE);

	/* Address range tests. */
	addr_range_test("1.1.1.1");
	addr_range_test("1.1.1.1/0");
	addr_range_test("1.1.1.1/32");
	addr_range_test("1.1.1.1-1.2.3.4");
	addr_range_test("::1");
	addr_range_test("::1/0");
	addr_range_test("::1/32");
	addr_range_test("1::-5::");
	addr_range_bad_test("unix", KNOT_EINVAL);
	addr_range_bad_test("1.1.1", KNOT_EINVAL);
	addr_range_bad_test("1.1.1.1/", KNOT_EINVAL);
	addr_range_bad_test("1.1.1.1/33", KNOT_ERANGE);
	addr_range_bad_test("1.1.1.1-", KNOT_EINVAL);
	addr_range_bad_test("1.1.1.1-::1", KNOT_EINVAL);

	/* Dname tests. */
	dname_test("example.com.", "\x07""example""\x03""com""\x00");

	/* Hex tests. */
	hex_test("", "", NULL);
	hex_test("0x", "", "");
	hex_test("Hello World!", "Hello World!", NULL);
	hex_test("0x0155FF", "\x01\x55\xFF", NULL);
	hex_bad_test("0xA", KNOT_EINVAL);

	/* Base64 tests. */
	base64_test("Zm9vYmFy", "foobar");

	/* Ref tests. */
	ref_test("on", true);

	return 0;
}
