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
//#include "knot/common.h"
#include "common/libtap/tap_unit.h"

#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"

// Units to test
#include "tests/libknot/realdata/libknot/dname_tests_realdata.h"
#include "tests/libknot/realdata/libknot/response_tests_realdata.h"
//#include "libknot/edns_tests.h"
#include "tests/libknot/realdata/libknot/node_tests_realdata.h"
#include "tests/libknot/realdata/libknot/rdata_tests_realdata.h"
//#include "libknot/response_tests_realdata.h"
#include "tests/libknot/realdata/libknot/rrset_tests_realdata.h"
//#include "libknot/zone_tests_realdata.h"
#include "tests/libknot/realdata/libknot/zonedb_tests_realdata.h"
#include "tests/libknot/realdata/libknot/packet_tests_realdata.h"

#include "common/lists.h"
// Run all loaded units
int main(int argc, char *argv[])
{
	data_for_knot_tests = create_test_data_from_dump();

	if (data_for_knot_tests == NULL) {
		diag("Data could not be loaded!");
		return 0;
	}

	// Open log
//	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {

		/* DNS units */
//		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&dname_tests_api,    //! DNS library (dname) unit
//		&edns_tests_api,     //! DNS library (EDNS0) unit
		&node_tests_api,     //! DNS library (node) unit
		&rdata_tests_api,    //! DNS library (rdata) unit
		&packet_tests_api,
//		&response_tests_api, //! DNS library (response) unit
		&response_tests_api, //! DNS library (response) unit
		&rrset_tests_api,    //! DNS library (rrset) unit
//		&zone_tests_api,     //! DNS library (zone) unit
//		&zonedb_tests_api,   //! DNS library (zonedb) unit
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

