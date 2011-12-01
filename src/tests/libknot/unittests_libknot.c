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
#include "knot/common.h"
#include "common/libtap/tap_unit.h"

// Units to test
#include "tests/libknot/libknot/cuckoo_tests.h"
#include "tests/libknot/libknot/dname_tests.h"
#include "tests/libknot/libknot/edns_tests.h"
#include "tests/libknot/libknot/node_tests.h"
#include "tests/libknot/libknot/rdata_tests.h"
#include "tests/libknot/libknot/response_tests.h"
#include "tests/libknot/libknot/rrset_tests.h"
#include "tests/libknot/libknot/zone_tests.h"
#include "tests/libknot/libknot/dname_table_tests.h"
#include "tests/libknot/libknot/nsec3_tests.h"
#include "tests/libknot/libknot/packet_tests.h"
#include "tests/libknot/libknot/query_tests.h"
#include "tests/libknot/libknot/zonedb_tests.h"
#include "tests/libknot/libknot/zone_tree_tests.h"
#include "tests/libknot/libknot/tsig_tests.h"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
//	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {

		/* DNS units */
		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&dname_tests_api,    //! DNS library (dname) unit
		&edns_tests_api,     //! DNS library (EDNS0) unit
		&zone_tests_api,     //! DNS library (zone) unit
		&node_tests_api,     //! DNS library (node) unit
		&rdata_tests_api,    //! DNS library (rdata) unit
		&response_tests_api, //! DNS library (response) unit
		&rrset_tests_api,    //! DNS library (rrset) unit
		&dname_table_tests_api,
		&nsec3_tests_api,
		&packet_tests_api,
		&query_tests_api,
		&zonedb_tests_api,   //! DNS library (zonedb) unit
		&zone_tree_tests_api,
		&tsig_tests_api,
		NULL
	};

	// Plan number of tests
	int id = 0;
	int test_count = 0;
	note("Units:");
	while (tests[id] != NULL) {
		note("- %s : %d tests", tests[id]->name,
		     tests[id]->count(argc, argv));
		test_count += tests[id]->count(argc, argv);
		++id;
	}

	plan(test_count);

	// Run tests
	id = 0;
	while (tests[id] != NULL) {
		diag("Testing unit: %s", tests[id]->name);
		tests[id]->run(argc, argv);
		++id;
	}

//	log_close();

	// Evaluate
	return exit_status();
}

