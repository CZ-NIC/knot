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

static int packet_tests_count(int argc, char *argv[]);
static int packet_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api packet_tests_api = {
	"DNS library - packet",     //! Unit name
	&packet_tests_count,  //! Count scheduled tests
	&packet_tests_run     //! Run scheduled tests
};

#ifdef TEST_WITH_LDNS
extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);
extern int compare_rr_rdata(dnslib_rdata_t *rdata, ldns_rr *rr, uint16_t type);
extern int compare_rrset_w_ldns_rr(const dnslib_rrset_t *rrset,
                                   ldns_rr *rr, char check_rdata);
extern int compare_rrsets_w_ldns_rrlist(const dnslib_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count);

int check_packet_w_ldns_packet(dnslib_packet_t *packet,
                                      ldns_pkt *ldns_packet,
                                      int check_header,
                                      int check_question,
                                      int check_body,
                                      int check_edns)
{
	int errors = 0;
	if (check_header) {
	dnslib_packet_dump(packet);
	getchar();
		if (packet->header.id != ldns_pkt_id(ldns_packet)) {
			diag("response ID does not match");
			errors++;
		}

		/* qdcount is always 1 in dnslib's case */

		/* TODO check flags1 and flags2 - no API for that,
		 * write my own */

		if (packet->header.ancount !=
		                ldns_pkt_ancount(ldns_packet)) {
			diag("Answer RRSet count wrongly converted");
			errors++;
		}

		if (packet->header.nscount !=
		                ldns_pkt_nscount(ldns_packet)) {
			diag("Authority RRSet count wrongly converted.\n"
			     "got %d should be %d",
			     dnslib_packet_authority_rrset_count(packet),
			     ldns_pkt_nscount(ldns_packet));
			errors++;
		}

		/* - 1 because ldns does not include OPT_RR to additional "
		 "section */
		int minus = (packet->opt_rr.version == 0) ? 1 : 0;

		if ((packet->header.arcount - minus) !=
		                ldns_pkt_arcount(ldns_packet)) {
			diag("Additional RRSet count wrongly converted.\n"
			     "got %d should be %d",
			     dnslib_packet_additional_rrset_count(packet) -
			     minus,
			     ldns_pkt_arcount(ldns_packet));
			errors++;
		}

		if (errors) {
			return errors;
		}
	}
	/* Header checked */

	/* Question section */

	int ret = 0;
	if (check_question) {
		dnslib_rrset_t *question_rrset =
		                dnslib_rrset_new(packet->
		                                 question.qname,
		                                 packet->
		                                 question.qtype,
		                                 packet->
		                                 question.qclass,
		                                 3600);

		if ((ret = compare_rrset_w_ldns_rr(question_rrset,
			ldns_rr_list_rr(ldns_pkt_question(ldns_packet),
			0), 0)) != 0) {
			diag("Question rrsets wrongly converted");
			errors++;
		}
		dnslib_rrset_free(&question_rrset);
	}

	if (check_body) {

		/* other RRSets */

		if ((ret =
		     compare_rrsets_w_ldns_rrlist(packet->answer,
		                         ldns_pkt_answer(ldns_packet),
                        dnslib_packet_answer_rrset_count(packet))) != 0) {
			diag("Answer rrsets wrongly converted");
			errors++;
		}



		if ((ret = compare_rrsets_w_ldns_rrlist(packet->authority,
		                             ldns_pkt_authority(ldns_packet),
			dnslib_packet_authority_rrset_count(packet))) != 0) {
			diag("Authority rrsets wrongly converted - %d", ret);
			errors++;
		}

		/* We don't want to test OPT RR, which is the last rrset
		 * in the additional section */

		if ((ret = compare_rrsets_w_ldns_rrlist(packet->additional,
		                           ldns_pkt_additional(ldns_packet),
			dnslib_packet_additional_rrset_count(packet) - 1)) != 0) {
			diag("Additional rrsets wrongly converted");
			errors++;
		}

	}

	if (check_edns) {

		/* OPT RR */

		if (ldns_pkt_edns(ldns_packet)) {
			/* if (packet->edns_packet == NULL) {
   diag("ldns has edns section, dnslib has not");
   return 1;
  } */

			dnslib_opt_rr_t *opt = &(packet->opt_rr);

			if (ldns_pkt_edns_udp_size(ldns_packet) !=
			                dnslib_edns_get_payload(opt)) {
				diag("Payloads in EDNS are different");
				errors++;
			}

			if (ldns_pkt_edns_version(ldns_packet) !=
			                dnslib_edns_get_version(opt)) {
				diag("Versions in EDNS are different");
				errors++;
			}

			if (ldns_pkt_edns_extended_rcode(ldns_packet) !=
			                dnslib_edns_get_ext_rcode(opt)) {
				diag("Extended rcodes in EDNS are different");
				errors++;
			}

			/* TODO parse flags do bit, z value ... */
		}
	}

	return errors;
}
#endif

extern dnslib_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset);
extern dnslib_dname_t *dname_from_test_dname(const test_dname_t *test_dname);

/* Converts dnslib_rrset_t to dnslib_opt_rr */
static dnslib_opt_rr_t *opt_rrset_to_opt_rr(dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	dnslib_opt_rr_t *opt_rr = dnslib_edns_new();
	assert(opt_rr);

	dnslib_edns_set_payload(opt_rr, rrset->rclass);

	dnslib_edns_set_ext_rcode(opt_rr, rrset->ttl);

	/* TODO rdata? mostly empty, I guess, but should be done */

	return opt_rr;
}

dnslib_packet_t *packet_from_test_response(test_response_t *test_packet)
{
	dnslib_rrset_t *parsed_opt = NULL;

	for (int j = 0; j < test_packet->arcount; j++) {
		if (test_packet->additional[j]->type ==
		    DNSLIB_RRTYPE_OPT) {
			parsed_opt =
				rrset_from_test_rrset(
				test_packet->additional[j]);
			assert(parsed_opt);
			break;
		}
	}

	dnslib_opt_rr_t *opt_rr = NULL;
	if (parsed_opt != NULL) {
		opt_rr =
			opt_rrset_to_opt_rr(parsed_opt);
		assert(opt_rr);
	} else {
		opt_rr = NULL;
	}

	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
	assert(packet);
	dnslib_packet_set_max_size(packet, 1024 * 10);

	if (opt_rr != NULL) {
		packet->opt_rr = *opt_rr;
	}

	packet->header.id = test_packet->id;
	packet->header.qdcount = test_packet->qdcount;

	packet->question.qname = dname_from_test_dname(test_packet->qname);
	packet->size += test_packet->qname->size;
	packet->question.qtype = test_packet->qtype;
	packet->question.qclass = test_packet->qclass;

	packet->size += 4;

	packet->answer =
		malloc(sizeof(dnslib_rrset_t *) * test_packet->ancount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->ancount; j++) {
		if (&(test_packet->answer[j])) {
			packet->answer[packet->an_rrsets++] =
			  rrset_from_test_rrset(test_packet->answer[j]);
		}
	}

	packet->authority =
		malloc(sizeof(dnslib_rrset_t *) * test_packet->nscount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->nscount; j++) {
		if (&(test_packet->authority[j])) {
			packet->authority[packet->ns_rrsets++] =
			  rrset_from_test_rrset(test_packet->authority[j]);
		}
	}

	packet->authority =
		malloc(sizeof(dnslib_rrset_t *) * test_packet->arcount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->arcount; j++) {
		if (&(test_packet->additional[j])) {
			if (test_packet->additional[j]->type ==
			    DNSLIB_RRTYPE_OPT) {
				continue;
			}
			packet->additional[packet->ar_rrsets++] =
			  rrset_from_test_rrset(test_packet->additional[j]);
		}
	}

	return packet;
}

static int test_packet_parse_from_wire(list raw_response_list)
{
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n ,raw_response_list) {
		test_raw_packet_t *raw_packet = (test_raw_packet_t *)n;
		dnslib_packet_t *packet =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		int ret = 0;
		if ((ret =
		     dnslib_packet_parse_from_wire(packet, raw_packet->data,
		                                   raw_packet->size, 0)) !=
		    DNSLIB_EOK) {
			diag("Warning: could not parse wire! "
			     "(might be caused by malformed dump) - "
			     "dnslib error: %s", dnslib_strerror(ret));
//			hex_print(raw_packet->data,
//			          raw_packet->size);
			continue;
		}

		ldns_pkt *ldns_packet = NULL;

		if (ldns_wire2pkt(&ldns_packet, raw_packet->data,
				  raw_packet->size) != LDNS_STATUS_OK) {
			diag("Could not parse wire using ldns");
			diag("%s",
			     ldns_get_errorstr_by_id(ldns_wire2pkt(&ldns_packet,
							raw_packet->data,
							raw_packet->size)));
			return 0;
		}

		if (check_packet_w_ldns_packet(packet, ldns_packet, 1,
		                               1, 1, 1) != 0) {
			diag("Wrongly created packet");
			errors++;
		}

		ldns_pkt_free(ldns_packet);
		dnslib_packet_free(&packet);
	}

	return (errors == 0);
}

static int test_packet_to_wire(list raw_response_list)
{
	int errors = 0;
	/*!< \todo test queries too! */
//	/* We'll need data from both lists. */
//	test_packet_t **test_packets = NULL;
//	uint test_packet_count = 0;
//	node *n = NULL;
//	WALK_LIST(n, response_list) {
//		test_packet_count++;
//	}

//	test_packets =
//		malloc(sizeof(test_packet_t *) * test_packet_count);
//	assert(test_packets);
//	int i = 0;
//	WALK_LIST(n, response_list) {
//		test_packets[i++] = (test_response_t *)n;
//	}

//	test_raw_packet_t **test_packets = NULL;
//	uint test_packet_count = 0;
//	n = NULL;
//	WALK_LIST(n, raw_response_list) {
//		test_packet_count++;
//	}

//	test_packets =
//		malloc(sizeof(test_raw_packet_t *) * test_packet_count);
//	assert(test_packets);
//	i = 0;
//	WALK_LIST(n, raw_response_list) {
//		test_packets[i++] = (test_raw_packet_t *)n;
//	}

//	assert(test_response_count == test_packet_count);
	node *n = NULL;
	WALK_LIST(n, raw_response_list) {
		/* Create packet from raw response. */
		dnslib_packet_t *packet =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_RESPONSE);
		assert(packet);
		test_raw_packet_t *raw_packet = (test_raw_packet_t *)n;
		if (dnslib_packet_parse_from_wire(packet, raw_packet->data,
		                                  raw_packet->size, 0) !=
		    DNSLIB_EOK) {
			diag("Warning: could not parse wire! "
			     "(might be caused be malformed dump)");
			continue;
		}
		/* Use this packet to create wire */
		uint8_t *wire = NULL;
		size_t size = 0;
		if (dnslib_packet_to_wire(packet, &wire ,&size) != DNSLIB_EOK) {
			diag("Could not convert packet to wire");
		}
		/* Create ldns packet from created wire */
		ldns_pkt *ldns_packet = NULL;

		if (ldns_wire2pkt(&ldns_packet, wire,
		                  size) != LDNS_STATUS_OK) {
			diag("Could not parse wire using ldns");
			/*!< \todo get rid of this */
			diag("%s",
			     ldns_get_errorstr_by_id(ldns_wire2pkt(&ldns_packet,
			                             wire,
			                             size)));
			return 0;
		}

		if (check_packet_w_ldns_packet(packet, ldns_packet, 1, 1, 1,
		                               1) != 0) {
			diag("Packet wrongly converted to wire!");
			errors++;
		}
		dnslib_packet_free(&packet);
		ldns_pkt_free(ldns_packet);
	}

	return (errors == 0);
}

static const uint DNSLIB_PACKET_TEST_COUNT = 2;

static int packet_tests_count(int argc, char *argv[])
{
	return DNSLIB_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_dnslib_tests;

	int res = 0;
	ok(res = test_packet_parse_from_wire(data->raw_packet_list),
	   "packet: from wire");
	skip(!res, 1);
	ok(test_packet_to_wire(data->raw_packet_list), "packet: to wire");
	endskip;

	return 1;
}

