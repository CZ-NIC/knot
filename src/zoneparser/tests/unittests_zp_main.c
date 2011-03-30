#include <config.h>
#include "tests/tap_unit.h"
// Units to test
#include "zcompile_tests.c"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
	//log_init(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING));

	// Build test set
	unit_api *tests[] = {
		&zoneparser_tests_api, //! Zoneparser unit
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

	//log_close();

	// Evaluate
	return exit_status();
}

