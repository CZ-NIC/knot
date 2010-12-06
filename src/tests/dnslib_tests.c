#include "tap_unit.h"

#include "dnslib/dnslib_dname_tests.c"
#include "dnslib/dnslib_rdata_tests.c"
#include "dnslib/dnslib_node_tests.c"
#include "dnslib/dnslib_rrset_tests.c"
#include "dnslib/dnslib_zone_tests.c"

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
		   + dnslib_zone_tests_count(argc, argv);
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_total = 0;

	note("Testing module: dname");
	ok((res = dnslib_dname_tests_run(argc, argv)), "dnslib: Module dname");
	res_total += res;

	note("Testing module: rdata");
	ok((res = dnslib_rdata_tests_run(argc, argv)), "dnslib: Module rdata");
	res_total += res;

	skip(!res, 3);

	note("Testing module: rrset");
	ok((res = dnslib_rrset_tests_run(argc, argv)), "dnslib: Module rrset");
	res_total += res;

	skip(!res, 2);

	note("Testing module: node");
	ok((res = dnslib_node_tests_run(argc, argv)), "dnslib: Module node");
	res_total += res;

	skip(!res, 1);

	note("Testing module: zone");
	ok((res = dnslib_zone_tests_run(argc, argv)), "dnslib: Module zone");
	res_total += res;

	endskip; // NODE failed

	endskip; // RRSET failed

	endskip; // DNAME or RDATA failed

	return res_total;
}
