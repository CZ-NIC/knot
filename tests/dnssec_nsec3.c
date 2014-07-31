/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <string.h>
#include <tap/basic.h>

#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/nsec3.h"

int main(int argc, char *argv[])
{
	plan(10);

	int result = KNOT_EOK;

	// lengths of different hashes

	is_int(20, knot_nsec3_hash_length(1),
	   "raw hash length for SHA1");
	is_int(0, knot_nsec3_hash_length(42),
	   "raw hash length for unknown algorithm");
	is_int(32, knot_nsec3_hash_b32_length(1),
	   "B32 hash length for SHA1");
	is_int(0, knot_nsec3_hash_b32_length(42),
	   "B32 hash length for unknown algorithm");

	//  parsing NSEC3PARAMs from wire

	knot_nsec3_params_t params = { 0 };
	knot_rrset_t *rrset = NULL;
	uint8_t rdata[] = {
		0x01,                  // hash algorithm
		0x00,                  // flags
		0x00, 0x0a,            // iterations
		0x04,                  // salt length
		'a', 'b', 'c', 'd'     // salt
	};

	knot_dname_t *owner = knot_dname_from_str("test.");
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC3PARAM, KNOT_CLASS_IN, NULL);
	knot_dname_free(&owner, NULL);

	result = knot_rrset_add_rdata(rrset, rdata, sizeof(rdata), 0, NULL);
	if (result == KNOT_EOK) {
		knot_nsec3param_from_wire(&params, &rrset->rrs);
	}

	is_int(1, params.algorithm, "parse algorithm from wire");
	is_int(0, params.flags, "parse flags from wire");
	is_int(10, params.iterations, "parse iterations from wire");
	is_int(4, params.salt_length, "parse salt length from wire");
	is_int(0, memcmp(params.salt, "abcd", 4), "parse salt from wire");

	knot_rrset_free(&rrset, NULL);
	knot_nsec3param_free(&params);

	// hash computation

	params.algorithm = 1;
	params.flags = 0;
	params.iterations = 7;
	params.salt_length = 14;
	params.salt = (uint8_t *)strdup("happywithnsec3");

	const char *dname_str = "knot-dns.cz.";
	knot_dname_t *dname = knot_dname_from_str(dname_str);

	uint8_t expected[] = {
		0x72, 0x40, 0x55, 0x83, 0x92, 0x93, 0x95, 0x28, 0xee, 0xa2,
		0xcc, 0xe1, 0x13, 0xbe, 0xcd, 0x41, 0xee, 0x8a, 0x71, 0xfd
	};

	size_t digest_size = 0;
	uint8_t *digest = NULL;
	result = knot_nsec3_hash(&params, dname, knot_dname_size(dname),
	                         &digest, &digest_size);
	ok(result == KNOT_EOK && digest_size == sizeof(expected) &&
	   memcmp(digest, expected, sizeof(expected)) == 0, "compute hash");

	free(digest);
	free(params.salt);
	knot_dname_free(&dname, NULL);

	return 0;
}
