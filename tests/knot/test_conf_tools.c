/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/yparser/yptrafo.h"
#include "knot/conf/tools.h"
#include "libknot/libknot.h"

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

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Module id tests. */
	mod_id_test("module/id", "\x06moduleid");
	mod_id_test("module", "\x06module");
	mod_id_bad_test("module/", KNOT_EINVAL);
	mod_id_bad_test("/", KNOT_EINVAL);
	mod_id_bad_test("/id", KNOT_EINVAL);

	return 0;
}
