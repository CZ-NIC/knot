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

#include <config.h>
#include "tests/common/descriptor_tests.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "common/descriptor.h"

#define BUF_LEN 256

static int descriptor_tests_count(int argc, char *argv[]);
static int descriptor_tests_run(int argc, char *argv[]);

unit_api descriptor_tests_api = {
	"RR descriptors",
	&descriptor_tests_count,
	&descriptor_tests_run
};

static int descriptor_tests_count(int argc, char *argv[])
{
	return 68;
}

static int descriptor_tests_run(int argc, char *argv[])
{
	const    rdata_descriptor_t *descr;
	char     name[BUF_LEN];
	int      ret;
	uint16_t num;

	// Get descriptor, type num to string:
	// 1. TYPE0
	descr = get_rdata_descriptor(0);
	ok(descr->type_name == 0, "get TYPE0 descriptor name");
	cmp_ok(descr->block_types[0], "==", KNOT_RDATA_WF_REMAINDER,
	       "get TYPE0 descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get TYPE0 descriptor 2. item type");

	ret = knot_rrtype_to_string(0, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get TYPE0 ret");
	ok(strcmp(name, "TYPE0") == 0, "get TYPE0 name");

	// 2. A
	descr = get_rdata_descriptor(1);
	ok(strcmp(descr->type_name, "A") == 0, "get A descriptor name");
	cmp_ok(descr->block_types[0], "==", 4,
	       "get A descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get A descriptor 2. item type");

	ret = knot_rrtype_to_string(1, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get A ret");
	ok(strcmp(name, "A") == 0, "get A name");

	// 3. CNAME
	descr = get_rdata_descriptor(5);
	ok(strcmp(descr->type_name, "CNAME") == 0, "get CNAME descriptor name");
	cmp_ok(descr->block_types[0], "==", KNOT_RDATA_WF_COMPRESSED_DNAME,
	       "get CNAME descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get CNAME descriptor 2. item type");

	ret = knot_rrtype_to_string(5, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get CNAME ret");
	ok(strcmp(name, "CNAME") == 0, "get CNAME name");

	// 4. TYPE38 (A6)
	descr = get_rdata_descriptor(38);
	ok(descr->type_name == 0, "get TYPE38 descriptor name");
	cmp_ok(descr->block_types[0], "==", KNOT_RDATA_WF_REMAINDER,
	       "get TYPE38 descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get TYPE38 descriptor 2. item type");

	ret = knot_rrtype_to_string(38, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get TYPE38 ret");
	ok(strcmp(name, "TYPE38") == 0, "get TYPE38 name");

	// 5. ANY
	descr = get_rdata_descriptor(255);
	ok(strcmp(descr->type_name, "ANY") == 0, "get ANY descriptor name");
	cmp_ok(descr->block_types[0], "==", KNOT_RDATA_WF_REMAINDER,
	       "get ANY descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get ANY descriptor 2. item type");

	ret = knot_rrtype_to_string(255, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get ANY ret");
	ok(strcmp(name, "ANY") == 0, "get ANY name");

	// 6. TYPE256
	descr = get_rdata_descriptor(256);
	ok(descr->type_name == 0, "get TYPE256 descriptor name");
	cmp_ok(descr->block_types[0], "==", KNOT_RDATA_WF_REMAINDER,
	       "get TYPE256 descriptor 1. item type");
	cmp_ok(descr->block_types[1], "==", KNOT_RDATA_WF_END,
	       "get TYPE256 descriptor 2. item type");

	ret = knot_rrtype_to_string(256, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get TYPE256 ret");
	ok(strcmp(name, "TYPE256") == 0, "get TYPE256 name");


	// Class num to string:
	// 7. CLASS0
	ret = knot_rrclass_to_string(0, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get CLASS0 ret");
	ok(strcmp(name, "CLASS0") == 0, "get CLASS0 name");

	// 8. IN
	ret = knot_rrclass_to_string(1, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get IN ret");
	ok(strcmp(name, "IN") == 0, "get IN name");

	// 9. ANY
	ret = knot_rrclass_to_string(255, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get ANY ret");
	ok(strcmp(name, "ANY") == 0, "get ANY name");

	// 10. CLASS65535
	ret = knot_rrclass_to_string(65535, name, BUF_LEN);
	cmp_ok(ret, "!=", -1, "get CLASS65535 ret");
	ok(strcmp(name, "CLASS65535") == 0, "get CLASS65535 name");

	// String to type num:
	// 11. A
	ret = knot_rrtype_from_string("A", &num);
	cmp_ok(ret, "!=", -1, "get A num ret");
	cmp_ok(num, "==", 1, "get A num");

	// 12. a
	ret = knot_rrtype_from_string("a", &num);
	cmp_ok(ret, "!=", -1, "get a num ret");
	cmp_ok(num, "==", 1, "get a num");

	// 13. AaAa
	ret = knot_rrtype_from_string("AaAa", &num);
	cmp_ok(ret, "!=", -1, "get AaAa num ret");
	cmp_ok(num, "==", 28, "get AaAa num");

	// 14. ""
	ret = knot_rrtype_from_string("", &num);
	cmp_ok(ret, "==", -1, "get "" num ret");

	// 15. DUMMY
	ret = knot_rrtype_from_string("DUMMY", &num);
	cmp_ok(ret, "==", -1, "get DUMMY num ret");

	// 16. TypE33
	ret = knot_rrtype_from_string("TypE33", &num);
	cmp_ok(ret, "!=", -1, "get TypE33 num ret");
	cmp_ok(num, "==", 33, "get TypE33 num");

	// 17. TYPE
	ret = knot_rrtype_from_string("TYPE", &num);
	cmp_ok(ret, "==", -1, "get TYPE num ret");

	// 18. TYPE0
	ret = knot_rrtype_from_string("TYPE0", &num);
	cmp_ok(ret, "!=", -1, "get TYPE0 num ret");
	cmp_ok(num, "==", 0, "get TYPE0 num");

	// 19. TYPE65535
	ret = knot_rrtype_from_string("TYPE65535", &num);
	cmp_ok(ret, "!=", -1, "get TYPE65535 num ret");
	cmp_ok(num, "==", 65535, "get TYPE65535 num");

	// 20. TYPE65536
	ret = knot_rrtype_from_string("TYPE65536", &num);
	cmp_ok(ret, "==", -1, "get TYPE65536 num ret");

	// String to class num:
	// 21. In
	ret = knot_rrclass_from_string("In", &num);
	cmp_ok(ret, "!=", -1, "get In num ret");
	cmp_ok(num, "==", 1, "get In num");

	// 22. ANY
	ret = knot_rrclass_from_string("ANY", &num);
	cmp_ok(ret, "!=", -1, "get ANY num ret");
	cmp_ok(num, "==", 255, "get ANY num");

	// 23. ""
	ret = knot_rrclass_from_string("", &num);
	cmp_ok(ret, "==", -1, "get "" num ret");

	// 24. DUMMY
	ret = knot_rrclass_from_string("DUMMY", &num);
	cmp_ok(ret, "==", -1, "get DUMMY num ret");

	// 25. CLass33
	ret = knot_rrclass_from_string("CLass33", &num);
	cmp_ok(ret, "!=", -1, "get CLass33 num ret");
	cmp_ok(num, "==", 33, "get CLass33 num");

	// 26. CLASS
	ret = knot_rrclass_from_string("CLASS", &num);
	cmp_ok(ret, "==", -1, "get CLASS num ret");

	// 27. CLASS0
	ret = knot_rrclass_from_string("CLASS0", &num);
	cmp_ok(ret, "!=", -1, "get CLASS0 num ret");
	cmp_ok(num, "==", 0, "get CLASS0 num");

	// 28. CLASS65535
	ret = knot_rrclass_from_string("CLASS65535", &num);
	cmp_ok(ret, "!=", -1, "get CLASS65535 num ret");
	cmp_ok(num, "==", 65535, "get CLASS65535 num");

	// 29. CLASS65536
	ret = knot_rrclass_from_string("CLASS65536", &num);
	cmp_ok(ret, "==", -1, "get CLASS65536 num ret");

	return 0;
}
