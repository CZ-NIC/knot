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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <tap/basic.h>
#include <assert.h>

#include "knot/modules/onlinesign/nsec_next.h"
#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"

/*!
 * \brief Assert that a domain name in a static buffer is valid.
 */
#define _assert_dname(name) \
	assert(knot_dname_wire_check(name, name + KNOT_DNAME_MAXLEN, NULL) > 0)

static void _test_nsec_next(const char *msg,
                            const knot_dname_t *input,
                            const knot_dname_t *apex,
                            const knot_dname_t *expected)
{
	knot_dname_t *next = online_nsec_next(input, apex);
	ok(next != NULL && knot_dname_is_equal(next, expected),
	   "nsec_next, %s", msg);
	knot_dname_free(next, NULL);
}

/*!
 * \brief Check \a online_nsec_next.
 *
 * Intentionally implemented as a macro. The input domain names are copied
 * into static buffers and validated.
 */
#define test_nsec_next(msg, _input, _apex, _expected) \
{ \
	uint8_t input[KNOT_DNAME_MAXLEN] = _input; \
	uint8_t apex[KNOT_DNAME_MAXLEN] = _apex; \
	uint8_t expected[KNOT_DNAME_MAXLEN] = _expected; \
	\
	_assert_dname(input); \
	_assert_dname(apex); \
	_assert_dname(expected); \
	\
	_test_nsec_next(msg, input, apex, expected); \
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// adding a single zero-byte label

	test_nsec_next(
		"zero-byte label, apex",
		"\x7""example""\x3""com",
		"\x7""example""\x3""com",
		"\x01\x00""\x07""example""\x03""com"
	);

	test_nsec_next(
		"zero-byte label, subdomain",
		"\x02""nx""\x7""example""\x3""com",
		"\x7""example""\x3""com",
		"\x01\x00""\x02""nx""\x07""example""\x03""com"
	);

	test_nsec_next(
		"zero-byte label, binary",
		"\x02\xff\xff""\x7""example""\x3""com",
		"\x07""example""\x3""com",
		"\x01\x00""\x02\xff\xff""\x7""example""\x3""com"
	);

	// zero byte label won't fit, increment
	#define APEX \
		"\x05""bacon""\x05""salad"

	#define LONG_SUFFIX \
		"\x2e""xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
		"\x2e""iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii" \
		"\x2e""mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm" \
		"\x2e""qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" \
		"\x2c""zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"   \
		APEX
	assert(sizeof(LONG_SUFFIX) == 245 + 1);

	test_nsec_next(
		"increment first label (simple)",
		"\x08""icecream" LONG_SUFFIX,
		APEX,
		"\x08""icecrean" LONG_SUFFIX
	);

	test_nsec_next(
		"increment first label (binary)",
		"\x08""walrus\xff\xff" LONG_SUFFIX,
		APEX,
		"\x08""walrut\x00\x00" LONG_SUFFIX
	);

	test_nsec_next(
		"increment first label (in place)",
		"\x07""lobster" LONG_SUFFIX,
		APEX,
		"\x07""lobstes" LONG_SUFFIX
	);

	test_nsec_next(
		"increment first label (extend)",
		"\x07""\xff\xff\xff\xff\xff\xff\xff" LONG_SUFFIX,
		APEX,
		"\x08""\xff\xff\xff\xff\xff\xff\xff\x00" LONG_SUFFIX
	);

	// name too long

	test_nsec_next(
		"name to long, strip label and increase next (simple)",
		"\x03""\xff\xff\xff""\x04""newt" LONG_SUFFIX,
		APEX,
		"\x04""newu" LONG_SUFFIX
	);

	test_nsec_next(
		"name to long, strip label and increase next (binary)",
		"\x03""\xff\xff\xff""\x04""cc\xff\xff" LONG_SUFFIX,
		APEX,
		"\x04""cd\x00\x00" LONG_SUFFIX
	);

	test_nsec_next(
		"name to long, strip label and increase next (extend)",
		"\x04""\xff\xff\xff\xff""\x03""\xff\xff\xff" LONG_SUFFIX,
		APEX,
		"\x04""\xff\xff\xff\x00" LONG_SUFFIX
	);

	// label too long

	#define MAX_LABEL "\x3f" /* 63 */ \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
		"\xff\xff\xff"
	assert(sizeof(MAX_LABEL) == 64 + 1);

	#define PAD_LABEL "\x28" /* 40 */ \
		"iiiiiiiiiioooooooooottttttttttssssssssss"
	assert(sizeof(PAD_LABEL) == 41 + 1);

	test_nsec_next(
		"label too long, strip and increase next (simple)",
		MAX_LABEL "\x08""mandrill" MAX_LABEL MAX_LABEL PAD_LABEL APEX,
		APEX,
		"\x08""mandrilm" MAX_LABEL MAX_LABEL PAD_LABEL APEX
	);

	test_nsec_next(
		"label too long, strip and increase next (extend)",
		MAX_LABEL "\x07""\xff\xff\xff\xff\xff\xff\xff" MAX_LABEL MAX_LABEL PAD_LABEL APEX,
		APEX,
		"\x08""\xff\xff\xff\xff\xff\xff\xff\x00" MAX_LABEL MAX_LABEL PAD_LABEL APEX
	);

	test_nsec_next(
		"label too long, strip multiple",
		MAX_LABEL MAX_LABEL "\x08""flamingo" MAX_LABEL PAD_LABEL APEX,
		APEX,
		"\x08""flamingp" MAX_LABEL PAD_LABEL APEX
	);

	test_nsec_next(
		"label too long, wrap around to apex",
		"\x31" /* 49 */
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff"
		MAX_LABEL MAX_LABEL MAX_LABEL APEX,
		APEX,
		APEX
	);

	return 0;
}
