/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "packet_tests_realdata.h"
#include "libknot/util/error.h"
#include "libknot/packet/packet.h"
#include "libknot/packet/response2.h"
/* *test_t structures */
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#ifdef TEST_WITH_LDNS
#include "ldns/packet.h"
#endif

static int response2_tests_count(int argc, char *argv[]);
static int response2_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response2_tests_api = {
	"DNS library - response2",     //! Unit name
	&response2_tests_count,  //! Count scheduled tests
	&response2_tests_run     //! Run scheduled tests
};

#ifdef TEST_WITH_LDNS
extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);
extern int compare_rr_rdata(knot_rdata_t *rdata, ldns_rr *rr, uint16_t type);
extern int compare_rrset_w_ldns_rr(const knot_rrset_t *rrset,
                                   ldns_rr *rr, char check_rdata);
extern int compare_rrsets_w_ldns_rrlist(const knot_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count);

extern int check_packet_w_ldns_packet(knot_packet_t *packet,
                                      ldns_pkt *ldns_packet,
                                      int check_header,
                                      int check_question,
                                      int check_body,
                                      int check_edns);
#endif

extern knot_packet_t *packet_from_test_response(test_response_t *response);

static int test_response_init_from_query(list query_list)
{
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, query_list) {
		knot_packet_t *response =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(response);
		knot_packet_t *query =
			packet_from_test_response((test_response_t *)n);
		assert(query);
		knot_packet_set_max_size(response, 1024 * 10);
		if (knot_response2_init_from_query(response,
		                                     query) != KNOT_EOK) {
			diag("Could not init response from query!");
			errors++;
		}
		knot_packet_free(&response);
		knot_packet_free(&query);
	}
	return (errors == 0);
}

//static int test_response_add_opt(list opt_list)
//{
//	int errors = 0;
//	node *n = NULL;
//	WALK_LIST(n, query_list) {
//		knot_packet_t *response =
//			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
//		assert(response);
//		knot_opt_rr_t *opt =
//			opt_from_test_opt((test_opt_t *)n);
//		assert(query);
//		if (knot_response2_add_opt(response,
//		                             opt, 1)!= KNOT_EOK) {
//			diag("Could not add OPT RR to response!");
//			errors++;
//		}
//		knot_packet_free(&response);
//		knot_opt_rr_free(&opt);
//	}
//	return (errors == 0);
//}

extern knot_rrset_t *rrset_from_test_rrset(test_rrset_t *test_rrset);

static int test_response_add_generic(int (*func)(knot_packet_t *,
                                                 const knot_rrset_t *,
                                                 int, int, int),
                                     list rrset_list)
{
	/*!< \todo Now adding only one RRSet at the time, try more, use nodes */
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		knot_packet_t *response =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(response);
		knot_packet_set_max_size(response,
		                           KNOT_PACKET_PREALLOC_RESPONSE * 100);
		assert(knot_response2_init(response) == KNOT_EOK);

		knot_rrset_t *rrset =
			rrset_from_test_rrset((test_rrset_t *)n);
		assert(rrset);

		int ret = 0;
		if ((ret = func(response, rrset, 0, 1, 0)) != KNOT_EOK) {
			diag("Could not add RRSet to response! Returned: %d",
			     ret);
			diag("(owner: %s type %s)",
			     ((test_rrset_t *)n)->owner->str,
			     knot_rrtype_to_string((
			     (test_rrset_t *)n)->type));
			errors++;
		}
		knot_packet_free(&response);
		knot_rrset_deep_free(&rrset, 1, 1, 1);
	}

	return (errors == 0);
}

static void test_response_add_rrset(list rrset_list)
{
	ok(test_response_add_generic(knot_response2_add_rrset_answer,
	                             rrset_list),
	   "response: add answer rrset");
	ok(test_response_add_generic(knot_response2_add_rrset_authority,
	                             rrset_list),
	   "response: add authority rrset");
	ok(test_response_add_generic(knot_response2_add_rrset_additional,
	                             rrset_list),
	   "response: add additional rrset");
}

static const uint KNOT_RESPONSE2_TEST_COUNT = 4;

static int response2_tests_count(int argc, char *argv[])
{
	return KNOT_RESPONSE2_TEST_COUNT;
}

static int response2_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_knot_tests;

//	int res = 0;
	ok(test_response_init_from_query(data->query_list),
	   "response: init from query");
	test_response_add_rrset(data->rrset_list);
	return 1;
}
