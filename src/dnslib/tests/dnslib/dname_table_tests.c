#include "dname_table_tests.h"

static int dnslib_dname_table_tests_count(int argc, char *argv[]);
static int dnslib_dname_table_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dname_table_tests_api = {
	"Dname table",     //! Unit name
	&dnslib_dname_table_tests_count,  //! Count scheduled tests
	&dnslib_dname_table_tests_run     //! Run scheduled tests
};

static const int DNSLIB_DNAME_TABLE_TEST_COUNT = 7;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_dname_table_tests_count(int argc, char *argv[])
{
	return DNSLIB_DNAME_TABLE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_dname_table_tests_run(int argc, char *argv[])
{
}
