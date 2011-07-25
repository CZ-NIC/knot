/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "packet_tests_realdata.h"
#include "dnslib/error.h"
#include "dnslib/packet.h"
#include "dnslib/response2.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#ifdef TEST_WITH_LDNS
#include "ldns/packet.h"
#endif

static int response2_tests_count(int argc, char *argv[]);
static int response2_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response2_tests_api = {
	"Packet",     //! Unit name
	&response2_tests_count,  //! Count scheduled tests
	&response2_tests_run     //! Run scheduled tests
};

#ifdef TEST_WITH_LDNS
extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);
extern int compare_rr_rdata(dnslib_rdata_t *rdata, ldns_rr *rr, uint16_t type);
extern int compare_rrset_w_ldns_rr(const dnslib_rrset_t *rrset,
                                   ldns_rr *rr, char check_rdata);
extern int compare_rrsets_w_ldns_rrlist(const dnslib_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count);

extern int check_packet_w_ldns_packet(dnslib_packet_t *packet,
                                      ldns_pkt *ldns_packet,
                                      int check_header,
                                      int check_question,
                                      int check_body,
                                      int check_edns);
#endif

extern dnslib_packet_t *packet_from_test_response(test_response_t *response);

static int test_response_init_from_query(list query_list)
{
	diag("query loading not yet done!");
	return 0;
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, query_list) {
		dnslib_packet_t *response =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		assert(response);
		dnslib_packet_t *query =
			packet_from_test_response((test_response_t *)n);
		assert(query);
		if (dnslib_response2_init_from_query(response,
		                                     query) != DNSLIB_EOK) {
			diag("Could not init response from query!");
			errors++;
		}
		dnslib_packet_free(&response);
		dnslib_packet_free(&query);
	}
	return (errors == 0);
}

//static int test_response_add_opt(list opt_list)
//{
//	int errors = 0;
//	node *n = NULL;
//	WALK_LIST(n, query_list) {
//		dnslib_packet_t *response =
//			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
//		assert(response);
//		dnslib_opt_rr_t *opt =
//			opt_from_test_opt((test_opt_t *)n);
//		assert(query);
//		if (dnslib_response2_add_opt(response,
//		                             opt, 1)!= DNSLIB_EOK) {
//			diag("Could not add OPT RR to response!");
//			errors++;
//		}
//		dnslib_packet_free(&response);
//		dnslib_opt_rr_free(&opt);
//	}
//	return (errors == 0);
//}

extern dnslib_rrset_t *rrset_from_test_rrset(test_rrset_t *test_rrset);

static int test_response_add_generic(int (*func)(dnslib_packet_t *,
                                                 const dnslib_rrset_t *,
                                                 int, int, int),
                                     list rrset_list)
{
	/*!< \todo Now adding only one RRSet at the time, try more, use nodes */
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		dnslib_packet_t *response =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		assert(response);

		dnslib_rrset_t *rrset =
			rrset_from_test_rrset((test_rrset_t *)n);
		assert(rrset);

		if (func(response, rrset, 0, 1, 0) != DNSLIB_EOK) {
			diag("Could not add RRSet to response!");
			diag("(owner: %s type %s)",
			     ((test_rrset_t *)n)->owner->str,
			     dnslib_rrtype_to_string((
			     (test_rrset_t *)n)->type));
			errors++;
		}
		dnslib_packet_free(&response);
		dnslib_rrset_deep_free(&rrset, 1, 1, 1);
	}

	return (errors == 0);
}

static void test_response_add_rrset(list rrset_list)
{
	ok(test_response_add_generic(dnslib_response2_add_rrset_answer,
	                             rrset_list),
	   "response: add answer rrset");
	ok(test_response_add_generic(dnslib_response2_add_rrset_authority,
	                             rrset_list),
	   "response: add authority rrset");
	ok(test_response_add_generic(dnslib_response2_add_rrset_additional,
	                             rrset_list),
	   "response: add additional rrset");
}

static const uint DNSLIB_RESPONSE2_TEST_COUNT = 4;

static int response2_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE2_TEST_COUNT;
}

static int response2_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_dnslib_tests;

//	int res = 0;
	ok(test_response_init_from_query(data->query_list),
	   "response: init from query");
	test_response_add_rrset(data->rrset_list);
	return 1;
}
