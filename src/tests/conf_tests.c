#include <stdio.h>

#include "tap_unit.h"
#include "conf/conf.h"

static FILE* conf_fp = 0;
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
	return 3;
}

static int cf_read(unsigned char *dest, unsigned int len)
{
	return fread(dest, len, 1, conf_fp);
}

/*! Run all scheduled tests for given parameters.
 */
static int conf_tests_run(int argc, char *argv[])
{
	// Test 1: Open configuration file for reading
	char *name = "";
	conf_fp = fopen(name, "r");
	ok(conf_fp != 0, "open configuration file %s", name);
	if (conf_fp == 0) {
		return 1;
	}

	// Test 2: Allocate new config
	config_t *conf = config_new(name);
	ok(conf != 0, "config_new()");
	cf_read_hook = cf_read;

	// Test 3: Parse config
	int ret = config_parse(conf);
	ok(ret == 0, "parsing configuration file %s", name);

	// Deallocating config
	config_free(conf);
	fclose(conf_fp);
	conf_fp = 0;

	return 0;
}
