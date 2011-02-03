#include <stdio.h>

#include "tap_unit.h"
#include "conf/conf.h"

/* Resources. */
#include "sample_conf.rc"

static int conf_tests_count(int argc, char *argv[]);
static int conf_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api conf_tests_api = {
	"Configuration parser", //! Unit name
	&conf_tests_count,      //! Count scheduled tests
	&conf_tests_run         //! Run scheduled tests
};

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int conf_tests_count(int argc, char *argv[])
{
	return 2;
}

/*! Run all scheduled tests for given parameters.
 */
static int conf_tests_run(int argc, char *argv[])
{
	int c = 0;
	const char* config_fn = 0;
	while ((c = getopt(argc, argv, "c:")) != -1) {
		switch (c)
		{
		case 'c':
			config_fn = optarg;
			note("Using config: %s", config_fn);
			break;
		}
	}


	// Test 1: Allocate new config
	config_t *conf = config_new(config_fn);
	ok(conf != 0, "config_new()");

	// Test 2: Parse config
	int ret = 0;
	if (config_fn) {
		ret = config_parse(conf);
	} else {
		ret = config_parse_str(conf, sample_conf_rc);
		config_fn = "rc:/sample_conf";
	}

	ok(ret == 0, "parsing configuration file %s", config_fn);

	// Deallocating config
	config_free(conf);

	return 0;
}
