/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/error.h"
#include "dnslib/nsec3.h"
#include "dnslib/utils.h"
#include "nsec3_tests.h"

static int dnslib_nsec3_tests_count(int argc, char *argv[]);
static int dnslib_nsec3_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api nsec3_tests_api = {
	"NSEC3",      //! Unit name
	&dnslib_nsec3_tests_count,  //! Count scheduled tests
	&dnslib_nsec3_tests_run     //! Run scheduled tests
};

extern int compare_wires_simple(uint8_t *w1, uint8_t *w2, uint count);

static int test_nsec3_params_from_wire()
{
	/* Create sample NSEC3PARAM rdata */
	dnslib_rdata_item_t items[4];
	dnslib_rdata_t *rdata = dnslib_rdata_new();
	rdata->items = items;
	rdata->count = 4;
	dnslib_rdata_item_set_raw_data(rdata, 0, (uint16_t *)"\x1\x0\x1");
	dnslib_rdata_item_set_raw_data(rdata, 1, (uint16_t *)"\x1\x0\x5");
	dnslib_rdata_item_set_raw_data(rdata, 2, (uint16_t *)"\x2\x0\x0\xF");
//	raw_data = (((uint8_t *)raw_data) + 3;
//	raw_data = "12345678";
	dnslib_rdata_item_set_raw_data(rdata, 3,
	                    (uint16_t *)"\x9\x0\x8\xF\xF\xF\xF\xF\xF\xF\xF\xF");

	dnslib_rrset_t *rrset =
		dnslib_rrset_new(dnslib_dname_new_from_str("cz.",
		                 strlen("cz."), NULL),
	                         DNSLIB_RRTYPE_NSEC3PARAM,
	                         DNSLIB_CLASS_IN,
	                         3600);
	assert(rrset);
	assert(dnslib_rrset_add_rdata(rrset, rdata) == DNSLIB_EOK);

	dnslib_nsec3_params_t params;

	int errors = 0;
	int lived = 0;
	lives_ok({
		if (dnslib_nsec3_params_from_wire(NULL, NULL) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_nsec3_params_from_wire(&params, NULL) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

		lived = 0;
		if (dnslib_nsec3_params_from_wire(NULL, rrset) !=
		    DNSLIB_EBADARG) {
			errors++;
		}
		lived = 1;

	}, "nsec3 params from wire NULL tests");
	errors += lived != 1;

	if (dnslib_nsec3_params_from_wire(&params, rrset) != DNSLIB_EOK) {
		diag("Could not convert nsec3 params to wire!");
		return 0;
	}

	if (params.algorithm != 1) {
		diag("Algorithm error");
		errors++;
	}

	if (params.flags != 5) {
		diag("Flags error");
		errors++;
	}

	if (params.iterations != 15) {
		diag("Iterations error");
		errors++;
	}

	if (params.salt_length != 8) {
		diag("Salt length error");
		return 0;
	}

	if (compare_wires_simple(params.salt, "\xF\xF\xF\xF\xF\xF\xF\xF",
	                         8) != 0) {
		diag("Salt wire error");
		errors++;
	}

	dnslib_rrset_free(&rrset);
	return (errors == 0);
}

static const int DNSLIB_NSEC3_TESTS_COUNT = 1;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_nsec3_tests_count(int argc, char *argv[])
{
	return DNSLIB_NSEC3_TESTS_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_nsec3_tests_run(int argc, char *argv[])
{
	ok(test_nsec3_params_from_wire(), "nsec3: params from wire");
	return 1;
}
