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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/yparser/yptrafo.h"
#include "knot/conf/tools.h"
#include "libknot/libknot.h"
#include "contrib/wire.h"

static void mod_id_test(const char *txt, const char *val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             mod_id_to_bin,
	                                             mod_id_to_txt } };

	diag("module id \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	ok(memcmp(b, val, b_len) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void mod_id_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             mod_id_to_bin,
	                                             mod_id_to_txt } };

	diag("module id \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

static void edns_opt_test(const char *txt, uint16_t code, const char *val)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	char t[64];
	size_t t_len = sizeof(t);
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             edns_opt_to_bin,
	                                             edns_opt_to_txt } };

	diag("edns option \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	is_int(KNOT_EOK, ret, "txt to bin");
	uint64_t c = wire_read_u64(b);
	ok(c == code, "compare code");
	ok(memcmp(yp_bin(b + sizeof(uint64_t)), val,
	          yp_bin_len(b + sizeof(uint64_t))) == 0, "compare");
	ret = yp_item_to_txt(&i, b, b_len, t, &t_len, YP_SNOQUOTE);
	is_int(KNOT_EOK, ret, "bin to txt");
	ok(strlen(t) == t_len, "txt ret length");
	ok(strlen(txt) == t_len, "txt length");
	ok(memcmp(txt, t, t_len) == 0, "compare");
}

static void edns_opt_bad_test(const char *txt, int code)
{
	int ret;
	uint8_t b[64];
	size_t b_len = sizeof(b);
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             edns_opt_to_bin,
	                                             edns_opt_to_txt } };

	diag("edns option \"%s\":", txt);
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
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             addr_range_to_bin,
	                                             addr_range_to_txt } };

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
	yp_item_t i = { NULL, YP_TDATA, YP_VDATA = { 0, NULL,
	                                             addr_range_to_bin,
	                                             addr_range_to_txt } };

	diag("address range \"%s\":", txt);
	ret = yp_item_to_bin(&i, txt, strlen(txt), b, &b_len);
	ok(ret == code, "invalid txt to bin");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Module id tests. */
	mod_id_test("module/id", "\x06moduleid");
	mod_id_test("module", "\x06module");
	mod_id_bad_test("module/", KNOT_EINVAL);
	mod_id_bad_test("/", KNOT_EINVAL);
	mod_id_bad_test("/id", KNOT_EINVAL);

	/* EDNS option tests. */
	edns_opt_test("0:", 0, "");
	edns_opt_test("65535:", 65535, "");
	edns_opt_test("1:abc", 1, "abc");
	edns_opt_test("1:0x0102", 1, "\x01\x02");
	edns_opt_bad_test("0", KNOT_EINVAL);
	edns_opt_bad_test("-1:a", KNOT_ERANGE);
	edns_opt_bad_test("65536:a", KNOT_ERANGE);
	edns_opt_bad_test("0:0xa", KNOT_EINVAL);

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

	return 0;
}
