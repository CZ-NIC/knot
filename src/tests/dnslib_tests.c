#include "tap_unit.h"

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
	return 0;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_tests_run(int argc, char *argv[])
{
	return 0;
}
