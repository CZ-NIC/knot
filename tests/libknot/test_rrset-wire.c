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

#include <assert.h>
#include <tap/basic.h>

#include "libknot/packet/rrset-wire.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"

// Wire initializers

#define MESSAGE_HEADER(AN, AUTH, ADD)  0xd4, 0xec, 0x81, 0xa0, 0x00, 0x01, \
                                       0x00, AN, 0x00, AUTH, 0x00, ADD

#define QUERY(qname, type) qname, 0x00, type, 0x00, 0x01

#define RR_HEADER(owner, type, rdlength0, rdlength1) owner, 0x00, type, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, rdlength0, rdlength1

#define QNAME_POINTER 0xc0, 0x0c

// Initializers' sizes

#define QUERY_SIZE 12 + 4
#define RR_HEADER_SIZE 10

// Sample domain names

#define QNAME 0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00
#define QNAME_SIZE 8
#define QNAME_LONG \
0x3f,'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', \
'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', \
'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', \
'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'w', 'y', \
'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 0x3f,\
'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', \
'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', \
'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', \
'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'x', 'x', 'y', 'z', \
'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 0x3f,'a', \
'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', \
'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', \
'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', \
'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'x', 'x', 'y', 'z', 'a', \
'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'i', 'k', 0x3d,'a', 'b', \
'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', \
'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', \
'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', \
'p', 'q', 'r', 's', 't', 'u', 'v', 'x', 'x', 'y', 'z', 'a', 'b', \
'c', 'd', 'e', 'f', 'g', 'h', 'i', 0x00
#define QNAME_LONG_SIZE 255
#define POINTER_SIZE 2

struct wire_data {
	uint8_t wire[65535];
	size_t size;
	size_t pos;
	int code;
	const char *msg;
};

#define FROM_CASE_COUNT 17

static const struct wire_data FROM_CASES[FROM_CASE_COUNT] = {
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A)},
  .size = QUERY_SIZE + QNAME_SIZE,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "No header" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A), 0x00, 0x00, 0x01},
  .size = QUERY_SIZE + QNAME_SIZE + 3,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "Partial header" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A),
            RR_HEADER(QNAME, KNOT_RRTYPE_A, 0x00, 0x04) },
  .size = QUERY_SIZE + RR_HEADER_SIZE + QNAME_SIZE * 2,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "No RDATA" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A),
            RR_HEADER(QNAME, KNOT_RRTYPE_A, 0x00, 0x04), 0x01 },
  .size = QUERY_SIZE + RR_HEADER_SIZE + QNAME_SIZE * 2 + 1,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "Partial RDATA" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A),
            RR_HEADER(QNAME, KNOT_RRTYPE_A, 0x00, 0x04), 0x01, 0x02, 0x03, 0x04 },
  .size = QUERY_SIZE + RR_HEADER_SIZE + QNAME_SIZE * 2 + 4,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "OK RDATA" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_A),
            RR_HEADER(QNAME, KNOT_RRTYPE_A, 0x00, 0x05), 0x01, 0x02, 0x03, 0x04, 0x05 },
  .size = QUERY_SIZE + RR_HEADER_SIZE + QNAME_SIZE * 2 + 5,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "Trailing RDATA" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME_LONG, KNOT_RRTYPE_SOA),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_SOA, 0x00, 0x18), QNAME_POINTER, QNAME_POINTER,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
  .size = QUERY_SIZE + RR_HEADER_SIZE + QNAME_LONG_SIZE + 6 + 20,
  .pos = QUERY_SIZE + QNAME_LONG_SIZE,
  .code = KNOT_EOK,
  .msg = "Max DNAME" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_SIG),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_SIG, 0xff, 0xdb),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, QNAME },
  .size = 65535,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "Max RDLENGTH" },
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME_LONG, KNOT_RRTYPE_SIG),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_SIG, 0xff, 0xff),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, QNAME_POINTER },
  .size = 65535 + QNAME_LONG_SIZE + QUERY_SIZE + RR_HEADER_SIZE + 2,
  .pos = QUERY_SIZE + QNAME_LONG_SIZE,
  .code = KNOT_EMALF,
  .msg = "Max RDLENGTH + compression"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_NSEC),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_NSEC, 0x00, 0x03),
            QNAME_POINTER, 0x00},
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 2 + 1,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "DNAME wrong compression"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_NAPTR),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_NAPTR, 0x00, 0x01),
            0x00},
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 1,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "NAPTR missing header"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_NAPTR),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_NAPTR, 0x00, 0x09),
            0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, QNAME_POINTER},
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 9,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "NAPTR bad offset"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_NAPTR),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_NAPTR, 0x00, 0x09),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 7,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "NAPTR no DNAME"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_NAPTR),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_NAPTR, 0x00, 0x0c),
            0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x01, 0xff, 0x01, 0xff, QNAME_POINTER},
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 10 + 2,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "NAPTR valid"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_APL),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_APL, 0x00, 0x00) },
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "Valid 0 RDATA"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_TXT),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_TXT, 0x00, 0x00) },
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EMALF,
  .msg = "Invalid 0 RDATA"},
{ .wire = { MESSAGE_HEADER(1, 0, 0), QUERY(QNAME, KNOT_RRTYPE_PX),
            RR_HEADER(QNAME_POINTER, KNOT_RRTYPE_PX, 0x00, 0x06),
            0x00, 0x00, QNAME_POINTER, QNAME_POINTER },
  .size = QUERY_SIZE + QNAME_SIZE + RR_HEADER_SIZE + 2 + 6,
  .pos = QUERY_SIZE + QNAME_SIZE,
  .code = KNOT_EOK,
  .msg = "Obsolete RR type"},
};

#define TEST_CASE_FROM(rrset, i) size_t _pos##i = FROM_CASES[i].pos; \
	ok(knot_rrset_rr_from_wire(FROM_CASES[i].wire, &_pos##i, FROM_CASES[i].size, \
	rrset, NULL, true) == FROM_CASES[i].code, "rrset wire: %s", FROM_CASES[i].msg)

static void test_inputs(void)
{
	for (size_t i = 0; i < FROM_CASE_COUNT; ++i) {
		knot_rrset_t rrset;
		knot_rrset_init_empty(&rrset);
		TEST_CASE_FROM(&rrset, i);
		knot_rrset_clear(&rrset, NULL);
	}
}

static void check_canon(uint8_t *wire, size_t size, size_t pos, bool canon,
                        knot_dname_t *qname, knot_dname_t *dname)
{
	knot_rrset_t rrset;
	knot_rrset_init_empty(&rrset);

	int ret = knot_rrset_rr_from_wire(wire, &pos, size, &rrset, NULL, canon);
	is_int(KNOT_EOK, ret, "OK %s canonization", canon ? "with" : "without");
	ok(memcmp(rrset.owner, qname, knot_dname_size(qname)) == 0, "compare owner");

	uint8_t *rdata = knot_rdataset_at(&rrset.rrs, 0)->data;
	ok(memcmp(rdata, dname, knot_dname_size(dname)) == 0, "compare rdata dname");

	knot_rrset_clear(&rrset, NULL);
}

static void test_canonization(void)
{
	#define UPP_QNAME_SIZE	5
	#define UPP_QNAME 0x01, 0x41, 0x01, 0x5a, 0x00	// A.Z.
	#define LOW_QNAME 0x01, 0x61, 0x01, 0x7a, 0x00	// a.z.

	#define UPP_DNAME_SIZE	3
	#define UPP_DNAME 0x01, 0x58, 0x00	// X.
	#define LOW_DNAME 0x01, 0x78, 0x00	// x.

	uint8_t wire[] = {
		MESSAGE_HEADER(1, 0, 0), QUERY(UPP_QNAME, KNOT_RRTYPE_NS),
		RR_HEADER(UPP_QNAME, KNOT_RRTYPE_NS, 0x00, UPP_DNAME_SIZE), UPP_DNAME
	};
	size_t size = QUERY_SIZE + RR_HEADER_SIZE + UPP_QNAME_SIZE * 2 + UPP_DNAME_SIZE;
	size_t pos = QUERY_SIZE + UPP_QNAME_SIZE;

	knot_dname_t upp_qname[] = { UPP_QNAME };
	knot_dname_t upp_dname[] = { UPP_DNAME };
	check_canon(wire, size, pos, false, upp_qname, upp_dname);

	knot_dname_t low_qname[] = { LOW_QNAME };
	knot_dname_t low_dname[] = { LOW_DNAME };
	check_canon(wire, size, pos, true, low_qname, low_dname);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("Test NULL parameters");
	int ret = knot_rrset_rr_from_wire(NULL, NULL, 0, NULL, NULL, true);
	is_int(KNOT_EINVAL, ret, "rr wire: Invalid params");

	diag("Test various inputs");
	test_inputs();

	diag("Test canonization");
	test_canonization();

	return 0;
}
