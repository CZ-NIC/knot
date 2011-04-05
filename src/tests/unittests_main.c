#include <config.h>
#include "knot/common.h"
#include "tests/libtap/tap_unit.h"

// Units to test
#include "tests/common/slab_tests.h"
#include "tests/common/skiplist_tests.h"
#include "tests/common/da_tests.h"
#include "tests/dnslib/cuckoo_tests.h"
#include "tests/dnslib/dname_tests.h"
#include "tests/dnslib/edns_tests.h"
#include "tests/dnslib/node_tests.h"
#include "tests/dnslib/rdata_tests.h"
#include "tests/dnslib/response_tests.h"
#include "tests/dnslib/rrset_tests.h"
#include "tests/dnslib/zone_tests.h"
#include "tests/dnslib/zonedb_tests.h"
#include "tests/knot/dthreads_tests.h"
#include "tests/knot/server_tests.h"
#include "tests/knot/conf_tests.h"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {
		/* Core data structures. */
		&slab_tests_api,     //! SLAB allocator unit
		&skiplist_tests_api, //! Skip list unit
		&dthreads_tests_api, //! DThreads testing unit
		&da_tests_api,       //! Dynamic array unit

		/* DNS units */
		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&dname_tests_api,    //! DNS library (dname) unit
		&edns_tests_api,     //! DNS library (EDNS0) unit
		&node_tests_api,     //! DNS library (node) unit
		&rdata_tests_api,    //! DNS library (rdata) unit
		&response_tests_api, //! DNS library (response) unit
		&rrset_tests_api,    //! DNS library (rrset) unit
		&zone_tests_api,     //! DNS library (zone) unit
		&zonedb_tests_api,   //! DNS library (zonedb) unit

		/* Server parts. */
		&conf_tests_api,     //! Configuration parser tests
		&server_tests_api,   //! Server unit
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

