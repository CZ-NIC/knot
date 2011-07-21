/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "packet_tests_realdata.h"
#include "dnslib/error.h"
#include "dnslib/packet.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#ifdef TEST_WITH_LDNS
#include "ldns/packet.h"
#endif

static int packet_tests_count(int argc, char *argv[]);
static int packet_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api packet_tests_api = {
	"Packet",     //! Unit name
	&packet_tests_count,  //! Count scheduled tests
	&packet_tests_run     //! Run scheduled tests
};
static const uint DNSLIB_PACKET_TEST_COUNT = 14;

static int packet_tests_count(int argc, char *argv[])
{
	return DNSLIB_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_dnslib_tests;
}

