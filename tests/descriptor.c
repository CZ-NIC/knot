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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "common/descriptor.h"

#define BUF_LEN 256

int main(int argc, char *argv[])
{
	plan(108);

	const    rdata_descriptor_t *descr;
	char     name[BUF_LEN];
	int      ret;
	uint16_t num;

	// Get descriptor, type num to string:
	// 1. TYPE0
	descr = get_rdata_descriptor(0);
	ok(descr->type_name == 0, "get TYPE0 descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get TYPE0 descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get TYPE0 descriptor 2. item type");

	ret = knot_rrtype_to_string(0, name, BUF_LEN);
	ok(ret != -1, "get TYPE0 ret");
	ok(strcmp(name, "TYPE0") == 0, "get TYPE0 name");

	// 2. A
	descr = get_rdata_descriptor(1);
	ok(strcmp(descr->type_name, "A") == 0, "get A descriptor name");
	ok(descr->block_types[0] == 4,
	   "get A descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get A descriptor 2. item type");

	ret = knot_rrtype_to_string(1, name, BUF_LEN);
	ok(ret != -1, "get A ret");
	ok(strcmp(name, "A") == 0, "get A name");

	// 3. CNAME
	descr = get_rdata_descriptor(5);
	ok(strcmp(descr->type_name, "CNAME") == 0, "get CNAME descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_COMPRESSED_DNAME,
	   "get CNAME descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get CNAME descriptor 2. item type");

	ret = knot_rrtype_to_string(5, name, BUF_LEN);
	ok(ret != -1, "get CNAME ret");
	ok(strcmp(name, "CNAME") == 0, "get CNAME name");

	// 4. TYPE38 (A6)
	descr = get_rdata_descriptor(38);
	ok(descr->type_name == 0, "get TYPE38 descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get TYPE38 descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get TYPE38 descriptor 2. item type");

	ret = knot_rrtype_to_string(38, name, BUF_LEN);
	ok(ret != -1, "get TYPE38 ret");
	ok(strcmp(name, "TYPE38") == 0, "get TYPE38 name");

	// 5. ANY
	descr = get_rdata_descriptor(255);
	ok(strcmp(descr->type_name, "ANY") == 0, "get ANY descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get ANY descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get ANY descriptor 2. item type");

	ret = knot_rrtype_to_string(255, name, BUF_LEN);
	ok(ret != -1, "get ANY ret");
	ok(strcmp(name, "ANY") == 0, "get ANY name");

	// 6. TYPE256
	descr = get_rdata_descriptor(256);
	ok(descr->type_name == 0, "get TYPE256 descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get TYPE256 descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get TYPE256 descriptor 2. item type");

	ret = knot_rrtype_to_string(256, name, BUF_LEN);
	ok(ret != -1, "get TYPE256 ret");
	ok(strcmp(name, "TYPE256") == 0, "get TYPE256 name");


	// Class num to string:
	// 7. CLASS0
	ret = knot_rrclass_to_string(0, name, BUF_LEN);
	ok(ret != -1, "get CLASS0 ret");
	ok(strcmp(name, "CLASS0") == 0, "get CLASS0 name");

	// 8. IN
	ret = knot_rrclass_to_string(1, name, BUF_LEN);
	ok(ret != -1, "get IN ret");
	ok(strcmp(name, "IN") == 0, "get IN name");

	// 9. ANY
	ret = knot_rrclass_to_string(255, name, BUF_LEN);
	ok(ret != -1, "get ANY ret");
	ok(strcmp(name, "ANY") == 0, "get ANY name");

	// 10. CLASS65535
	ret = knot_rrclass_to_string(65535, name, BUF_LEN);
	ok(ret != -1, "get CLASS65535 ret");
	ok(strcmp(name, "CLASS65535") == 0, "get CLASS65535 name");

	// String to type num:
	// 11. A
	ret = knot_rrtype_from_string("A", &num);
	ok(ret != -1, "get A num ret");
	ok(num == 1, "get A num");

	// 12. a
	ret = knot_rrtype_from_string("a", &num);
	ok(ret != -1, "get a num ret");
	ok(num == 1, "get a num");

	// 13. AaAa
	ret = knot_rrtype_from_string("AaAa", &num);
	ok(ret != -1, "get AaAa num ret");
	ok(num == 28, "get AaAa num");

	// 14. ""
	ret = knot_rrtype_from_string("", &num);
	ok(ret == -1, "get "" num ret");

	// 15. DUMMY
	ret = knot_rrtype_from_string("DUMMY", &num);
	ok(ret == -1, "get DUMMY num ret");

	// 16. TypE33
	ret = knot_rrtype_from_string("TypE33", &num);
	ok(ret != -1, "get TypE33 num ret");
	ok(num == 33, "get TypE33 num");

	// 17. TYPE
	ret = knot_rrtype_from_string("TYPE", &num);
	ok(ret == -1, "get TYPE num ret");

	// 18. TYPE0
	ret = knot_rrtype_from_string("TYPE0", &num);
	ok(ret != -1, "get TYPE0 num ret");
	ok(num == 0, "get TYPE0 num");

	// 19. TYPE65535
	ret = knot_rrtype_from_string("TYPE65535", &num);
	ok(ret != -1, "get TYPE65535 num ret");
	ok(num == 65535, "get TYPE65535 num");

	// 20. TYPE65536
	ret = knot_rrtype_from_string("TYPE65536", &num);
	ok(ret == -1, "get TYPE65536 num ret");

	// String to class num:
	// 21. In
	ret = knot_rrclass_from_string("In", &num);
	ok(ret != -1, "get In num ret");
	ok(num == 1, "get In num");

	// 22. ANY
	ret = knot_rrclass_from_string("ANY", &num);
	ok(ret != -1, "get ANY num ret");
	ok(num == 255, "get ANY num");

	// 23. ""
	ret = knot_rrclass_from_string("", &num);
	ok(ret == -1, "get "" num ret");

	// 24. DUMMY
	ret = knot_rrclass_from_string("DUMMY", &num);
	ok(ret == -1, "get DUMMY num ret");

	// 25. CLass33
	ret = knot_rrclass_from_string("CLass33", &num);
	ok(ret != -1, "get CLass33 num ret");
	ok(num == 33, "get CLass33 num");

	// 26. CLASS
	ret = knot_rrclass_from_string("CLASS", &num);
	ok(ret == -1, "get CLASS num ret");

	// 27. CLASS0
	ret = knot_rrclass_from_string("CLASS0", &num);
	ok(ret != -1, "get CLASS0 num ret");
	ok(num == 0, "get CLASS0 num");

	// 28. CLASS65535
	ret = knot_rrclass_from_string("CLASS65535", &num);
	ok(ret != -1, "get CLASS65535 num ret");
	ok(num == 65535, "get CLASS65535 num");

	// 29. CLASS65536
	ret = knot_rrclass_from_string("CLASS65536", &num);
	ok(ret == -1, "get CLASS65536 num ret");

	// Get obsolete descriptor:
	// 30. TYPE0
	descr = get_obsolete_rdata_descriptor(0);
	ok(descr->type_name == 0, "get TYPE0 descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get TYPE0 descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get TYPE0 descriptor 2. item type");

	// 31. MD
	descr = get_obsolete_rdata_descriptor(3);
	ok(strcmp(descr->type_name, "MD") == 0, "get MD descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_COMPRESSED_DNAME,
	   "get A descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get A descriptor 2. item type");

	// 32. NXT
	descr = get_obsolete_rdata_descriptor(30);
	ok(strcmp(descr->type_name, "NXT") == 0, "get NXT descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_COMPRESSED_DNAME,
	   "get CNAME descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_REMAINDER,
	   "get CNAME descriptor 2. item type");
	ok(descr->block_types[2] == KNOT_RDATA_WF_END,
	   "get CNAME descriptor 3. item type");

	// 33. TYPE38 (A6)
	descr = get_obsolete_rdata_descriptor(38);
	ok(descr->type_name == 0, "get TYPE38 descriptor name");
	ok(descr->block_types[0] == KNOT_RDATA_WF_REMAINDER,
	   "get TYPE38 descriptor 1. item type");
	ok(descr->block_types[1] == KNOT_RDATA_WF_END,
	   "get TYPE38 descriptor 2. item type");

	// knot_rrtype_to_string invalid output buffer size
	ret = knot_rrtype_to_string(1, NULL, 0);
	ok(ret == -1, "knot_rrtype_to_string: invalid output buffer size");

	// knot_rrclass_to_string invalid output buffer size
	ret = knot_rrclass_to_string(1, NULL, 0);
	ok(ret == -1, "knot_rrclass_to_string: invalid output buffer size");

	// descriptor_item_is_dname
	ok(descriptor_item_is_dname(KNOT_RDATA_WF_END) == 0,
	   "descriptor is not dname");
	ok(descriptor_item_is_dname(KNOT_RDATA_WF_COMPRESSED_DNAME) != 0,
	   "descriptor is compressed dname");
	ok(descriptor_item_is_dname(KNOT_RDATA_WF_UNCOMPRESSED_DNAME) != 0,
	   "descriptor is uncompressed dname");

	// descriptor_item_is_compr_dname
	ok(descriptor_item_is_compr_dname(KNOT_RDATA_WF_END) == 0,
	   "descriptor is not compressed dname");
	ok(descriptor_item_is_compr_dname(KNOT_RDATA_WF_COMPRESSED_DNAME) != 0,
	   "descriptor is compressed dname");

	// descriptor_item_is_fixed
	ok(descriptor_item_is_fixed(0) == 0,
	   "descriptor is not fixed");
	ok(descriptor_item_is_fixed(1) != 0,
	   "descriptor is fixed");

	// descriptor_item_is_remainder
	ok(descriptor_item_is_remainder(0) == 0,
	   "descriptor is not remainder");
	ok(descriptor_item_is_remainder(KNOT_RDATA_WF_REMAINDER) != 0,
	   "descriptor is remainder");

	// knot_rrtype_is_metatype
	ok(knot_rrtype_is_metatype(0) == 0,
	   "rrtype is not metatype");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_SIG) != 0,
	   "rrtype is SIG");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_OPT) != 0,
	   "rrtype is OPT");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_TKEY) != 0,
	   "rrtype is TKEY");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_TSIG) != 0,
	   "rrtype is TSIG");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_IXFR) != 0,
	   "rrtype is IXFR");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_AXFR) != 0,
	   "rrtype is AXFR");
	ok(knot_rrtype_is_metatype(KNOT_RRTYPE_ANY) != 0,
	   "rrtype is ANY");

	// knot_rrtype_is_ddns_forbidden
	ok(knot_rrtype_is_ddns_forbidden(0) == 0,
	   "rrtype is not ddns forbidden");
	ok(knot_rrtype_is_ddns_forbidden(KNOT_RRTYPE_RRSIG) != 0,
	   "rrtype is RRSIG");
	ok(knot_rrtype_is_ddns_forbidden(KNOT_RRTYPE_NSEC) != 0,
	   "rrtype is NSEC");
	ok(knot_rrtype_is_ddns_forbidden(KNOT_RRTYPE_NSEC3) != 0,
	   "rrtype is NSEC3");

	// knot_rrtype_additional_needed
	ok(knot_rrtype_additional_needed(0) == 0,
	   "rrtype is not additional needed");
	ok(knot_rrtype_additional_needed(KNOT_RRTYPE_NS) != 0,
	   "rrtype is NS");
	ok(knot_rrtype_additional_needed(KNOT_RRTYPE_MX) != 0,
	   "rrtype is MX");
	ok(knot_rrtype_additional_needed(KNOT_RRTYPE_SRV) != 0,
	   "rrtype is SRV");

	return 0;
}
