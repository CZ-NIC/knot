#include <config.h>
#include "knot/common.h"
#include "common/libtap/tap_unit.h"

// Units to test
#include "dnslib/cuckoo_tests.h"
#include "dnslib/dname_tests.h"
#include "dnslib/edns_tests.h"
#include "dnslib/node_tests.h"
#include "dnslib/rdata_tests.h"
#include "dnslib/response2_tests.h"
#include "dnslib/rrset_tests.h"
#include "dnslib/zone_tests.h"
#include "dnslib/dname_table_tests.h"
#include "dnslib/nsec3_tests.h"
#include "dnslib/packet_tests.h"
#include "dnslib/query_tests.h"
#include "dnslib/zonedb_tests.h"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {

		/* DNS units */
		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&dname_tests_api,    //! DNS library (dname) unit
		&edns_tests_api,     //! DNS library (EDNS0) unit
//		&node_tests_api,     //! DNS library (node) unit
		&rdata_tests_api,    //! DNS library (rdata) unit
		&response2_tests_api, //! DNS library (response) unit
		&rrset_tests_api,    //! DNS library (rrset) unit
		&dname_table_tests_api,
		&nsec3_tests_api,
		&packet_tests_api,
		&query_tests_api,
		&zonedb_tests_api,   //! DNS library (zonedb) unit
		&zone_tests_api,     //! DNS library (zone) unit
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

