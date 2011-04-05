#include "tests/dnslib/zonedb_tests.h"


static int zonedb_tests_count(int argc, char *argv[]);
static int zonedb_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api zonedb_tests_api = {
	"Zone database",      //! Unit name
	&zonedb_tests_count,  //! Count scheduled tests
	&zonedb_tests_run     //! Run scheduled tests
};

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int zonedb_tests_count(int argc, char *argv[])
{
	return 0;
}

/*! Run all scheduled tests for given parameters.
 */
static int zonedb_tests_run(int argc, char *argv[])
{
	return 0;
}
