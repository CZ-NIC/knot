#include <assert.h>
#include <inttypes.h>

//#define RESP_TEST_DEBUG
#include "dnslib/tests/dnslib/response2_tests.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/response.h"
#include "dnslib/rdata.h"
#include "dnslib/rrset.h"
#include "dnslib/dname.h"
#include "dnslib/wire.h"
#include "dnslib/descriptor.h"
#include "dnslib/edns.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int dnslib_response2_tests_count(int argc, char *argv[]);
static int dnslib_response2_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response2_tests_api = {
	"DNS library - response",      //! Unit name
	&dnslib_response2_tests_count,  //! Count scheduled tests
	&dnslib_response2_tests_run     //! Run scheduled tests
};

static int test_response_init()
{
}

static int test_response_init_query()
{
}

static int test_response_clear()
{
}

static int test_response_add_opt()
{
}

static int test_response_add_rrset()
{
}

static int test_response

static const int DNSLIB_RESPONSE2_TEST_COUNT = 12;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_response2_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE2_TEST_COUNT;
}


/*! Run all scheduled tests for given parameters.
 */
static int dnslib_response2_tests_run(int argc, char *argv[])
{

}
