#include "dname_table_tests.h"
#include "dnslib/dname-table.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

static int dnslib_dname_table_tests_count(int argc, char *argv[]);
static int dnslib_dname_table_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dname_table_tests_api = {
	"Dname table",     //! Unit name
	&dnslib_dname_table_tests_count,  //! Count scheduled tests
	&dnslib_dname_table_tests_run     //! Run scheduled tests
};

static int test_dname_table_new()
{
	dnslib_dname_table_t *table = dnslib_dname_table_new();
	if (table == NULL) {
		return 0;
	}

	dnslib_dname_table_free(&table);
	return 1;
}

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
	int final_res = 1;
	int res = 0;

	ok((res = test_dname_table_new()), "dname table: new");
	final_res *= res;

	skip(!res, 6);

	endskip;

	return final_res;
}
