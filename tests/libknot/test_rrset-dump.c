/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/rrset-dump.h"

/* BACKGROUND:
 *
 * This unit test could be used for testing rrset-dump with newly implemented RR types.
 * But so far, the functional test records/load is used for this purpose.
 * This unit test ought to catch different quirks of knot_rrset_txt_dump,
 * like re-allocating the given output buffer based on errcode (KNOT_ESPACE).
 */

const knot_dump_style_t *dump_style = &KNOT_DUMP_STYLE_DEFAULT;

typedef struct {
	const char *description;
	knot_rrset_t rrset;
	const char *expect_out;
	int expect_ret;
	size_t buf_sizes[8];
} rrset_dump_test_case_t;

const char rrsig_case_text[] = "test.               \t1234567890\tRRSIG\tDNSKEY 13 1 1234567890 20251015085855 20251015063355 33658 test. uj40mBZYSg21VqhF7AcU6CTp3dM2k8G/Br8ZP902OCrsDjRq3qPZySxYwmcnbNYeAdVyT1m2zLmKZbYa8cCqRA==\n";

knot_rdata_t rrsig_case_rdata = {
	88,
	{ 0x00, 0x30,    0x0d,    0x01,    0x49, 0x96, 0x02, 0xd2,    0x68, 0xef, 0x62, 0x4f,   0x68, 0xef, 0x40, 0x53,    0x83, 0x7a,    0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
	  0xba, 0x3e, 0x34, 0x98, 0x16, 0x58, 0x4a, 0x0d, 0xb5, 0x56, 0xa8, 0x45, 0xec, 0x07, 0x14, 0xe8, 0x24, 0xe9, 0xdd, 0xd3, 0x36, 0x93, 0xc1, 0xbf, 0x06, 0xbf, 0x19, 0x3f, 0xdd, 0x36, 0x38, 0x2a,
	  0xec, 0x0e, 0x34, 0x6a, 0xde, 0xa3, 0xd9, 0xc9, 0x2c, 0x58, 0xc2, 0x67, 0x27, 0x6c, 0xd6, 0x1e, 0x01, 0xd5, 0x72, 0x4f, 0x59, 0xb6, 0xcc, 0xb9, 0x8a, 0x65, 0xb6, 0x1a, 0xf1, 0xc0, 0xaa, 0x44
	}
};

const rrset_dump_test_case_t rrset_dump_test_cases[] = {
	{ "some RRSIG", { (knot_dname_t *)"\x04""test", 1234567890U, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, { 1, 90, &rrsig_case_rdata }, NULL }, rrsig_case_text, KNOT_EOK, { 1, 3, 5, 7, 9, 11 } },
};

void test_rrset_dump(const char *description, const knot_rrset_t *rrset, const char *expect_out, int expect_ret, size_t initial_buf)
{
	size_t bufsize = initial_buf;
	char *buf = calloc(1, initial_buf);
	assert(buf != NULL);

	if (expect_ret == KNOT_EOK) {
		expect_ret = strlen(expect_out);
	}

	int ret = knot_rrset_txt_dump(rrset, &buf, &bufsize, dump_style);
	ok(ret == expect_ret, "%s (init buf %zu): return code %d found %d", description, initial_buf, expect_ret, ret);

	if (expect_out != NULL) {
		ok(strcmp(buf, expect_out) == 0, "%s (init buf %zu): output string '%s' found '%s'", description, initial_buf, expect_out, buf);
	}

	free(buf);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	for (size_t i = 0; i < sizeof(rrset_dump_test_cases) / sizeof(*rrset_dump_test_cases); i++) {
		const rrset_dump_test_case_t *c = &rrset_dump_test_cases[i];
		for (size_t j = 0; j < sizeof(c->buf_sizes) / sizeof(*c->buf_sizes); j++) {
			if (c->buf_sizes[j] > 0) {
			        test_rrset_dump(c->description, &c->rrset, c->expect_out, c->expect_ret, c->buf_sizes[j]);
			}
		}
	}

	return 0;
}
