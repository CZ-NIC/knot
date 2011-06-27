#include <config.h>
#include "knot/common.h"
#include "common/libtap/tap_unit.h"

// Units to test
#include "tests/common/slab_tests.h"
#include "tests/common/skiplist_tests.h"
#include "tests/common/events_tests.h"
#include "tests/common/da_tests.h"
#include "tests/common/acl_tests.h"
#include "tests/knot/dthreads_tests.h"
#include "tests/knot/journal_tests.h"
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
		&journal_tests_api,  //! Journal unit
		&slab_tests_api,     //! SLAB allocator unit
		&skiplist_tests_api, //! Skip list unit
		&dthreads_tests_api, //! DThreads testing unit
		&events_tests_api,   //! Events testing unit
		&da_tests_api,       //! Dynamic array unit
		&acl_tests_api,      //! ACLs

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

