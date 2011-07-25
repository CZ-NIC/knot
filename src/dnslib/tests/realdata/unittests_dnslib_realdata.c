#include <config.h>
#include "knot/common.h"
#include "common/libtap/tap_unit.h"

#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

// Units to test
#include "dnslib/dname_tests_realdata.h"
//#include "dnslib/edns_tests.h"
#include "dnslib/node_tests_realdata.h"
#include "dnslib/rdata_tests_realdata.h"
#include "dnslib/response_tests_realdata.h"
#include "dnslib/rrset_tests_realdata.h"
//#include "dnslib/zone_tests_realdata.h"
#include "dnslib/zonedb_tests_realdata.h"

#include "common/lists.h"
// Run all loaded units
int main(int argc, char *argv[])
{
	data_for_dnslib_tests = create_test_data_from_dump();

	if (data_for_dnslib_tests == NULL) {
		diag("Data could not be loaded!");
		return 0;
	}

	// Open log
	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {

		/* DNS units */
//		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&dname_tests_api,    //! DNS library (dname) unit
//		&edns_tests_api,     //! DNS library (EDNS0) unit
		&node_tests_api,     //! DNS library (node) unit
		&rdata_tests_api,    //! DNS library (rdata) unit
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

	log_close();

	// Evaluate
	return exit_status();
}

