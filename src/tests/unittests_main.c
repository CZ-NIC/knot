#include <config.h>
#include "knot/common.h"
#include "tests/tap_unit.h"

// Units to test
#include "skiplist_tests.c"
#include "dthreads_tests.c"
#include "da_tests.c"
#include "cuckoo_tests.c"
#include "zonedb_tests.c"
#include "dnslib_tests.c"
#include "server_tests.c"
#include "slab_tests.c"
#include "conf_tests.c"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
	log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {
		&skiplist_tests_api, //! Skip list unit
		&dthreads_tests_api, //! DThreads testing unit
		&da_tests_api,       //! Dynamic array unit
		&cuckoo_tests_api,   //! Cuckoo hashing unit
		&zonedb_tests_api,   //! Zone database unit
		&conf_tests_api,     //! Configuration parser tests
		&dnslib_tests_api,   //! DNS library unit
		&server_tests_api,   //! Server unit
		&slab_tests_api,     //! SLAB allocator unit
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

