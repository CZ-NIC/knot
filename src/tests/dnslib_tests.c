#include "tests/tap_unit.h"

#include "tests/dnslib/dnslib_dname_tests.c"
#include "tests/dnslib/dnslib_rdata_tests.c"
#include "tests/dnslib/dnslib_node_tests.c"
#include "tests/dnslib/dnslib_rrset_tests.c"
#include "tests/dnslib/dnslib_zone_tests.c"
#include "tests/dnslib/dnslib_response_tests.c"
#include "tests/dnslib/dnslib_edns_tests.c"

static int dnslib_tests_count(int argc, char *argv[]);
static int dnslib_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_tests_api = {
	"DNS library",        //! Unit name
	&dnslib_tests_count,  //! Count scheduled tests
	&dnslib_tests_run     //! Run scheduled tests
};

/*! \todo Implement theese tests into API.
  */

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_tests_count(int argc, char *argv[])
{
	return dnslib_dname_tests_count(argc, argv)
	       + dnslib_rdata_tests_count(argc, argv)
	       + dnslib_rrset_tests_count(argc, argv)
	       + dnslib_node_tests_count(argc, argv)
	       + dnslib_zone_tests_count(argc, argv)
	       + dnslib_response_tests_count(argc, argv)
	       + dnslib_edns_tests_count(argc, argv);       
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_tests_run(int argc, char *argv[])
{
	int res = 0;

	int rrset_tests = dnslib_rrset_tests_count(argc, argv);
	int node_tests = dnslib_node_tests_count(argc, argv);
	int zone_tests = dnslib_zone_tests_count(argc, argv);

	note("Testing module: dname");
	res = dnslib_dname_tests_run(argc, argv);

	note("Testing module: rdata");
	res *= dnslib_rdata_tests_run(argc, argv);

	skip(!res, rrset_tests + node_tests + zone_tests);

	note("Testing module: rrset");
	res = dnslib_rrset_tests_run(argc, argv);

	skip(!res, node_tests + zone_tests);

	note("Testing module: node");
	res = dnslib_node_tests_run(argc, argv);

	skip(!res, zone_tests);

	note("Testing module: zone");
	res = dnslib_zone_tests_run(argc, argv);

	note("Testing module: response");
	res = dnslib_response_tests_run(argc, argv);

	note("Testing module: ends");
	res = dnslib_edns_tests_run(argc, argv);

	endskip; // skipped zone

	endskip; // skipped node & zone

	endskip; // skipped rrset & node & zone

	return res;
}
