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

#ifdef TEST_WITH_LDNS
extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);
extern int compare_rr_rdata(dnslib_rdata_t *rdata, ldns_rr *rr, uint16_t type);
extern int compare_rrset_w_ldns_rr(const dnslib_rrset_t *rrset,
                                   ldns_rr *rr, char check_rdata);
extern int compare_rrsets_w_ldns_rrlist(const dnslib_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count);

static int check_packet_w_ldns_packet(dnslib_packet_t *packet,
                                      ldns_pkt *ldns_packet)
{
	if (packet->header.id != ldns_pkt_id(ldns_packet)) {
		diag("response ID does not match");
		return 1;
	}

	/* qdcount is always 1 in dnslib's case */

	/* TODO check flags1 and flags2 - no API for that, write my own*/

	if (dnslib_packet_answer_rrset_count(packet) !=
	    ldns_pkt_ancount(ldns_packet)) {
		diag("Answer RRSet count wrongly converted");
		return 1;
	}

	if (dnslib_packet_authority_rrset_count(packet) !=
	    ldns_pkt_nscount(ldns_packet)) {
		diag("Authority RRSet count wrongly converted");
		return 1;
	}

	if (dnslib_packet_additional_rrset_count(packet) !=
	    ldns_pkt_arcount(ldns_packet)) {
		diag("Additional RRSet count wrongly converted");
		return 1;
	}

	/* Header checked */

	/* Question section */

	int ret = 0;

	dnslib_rrset_t *question_rrset = dnslib_rrset_new(packet->
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
		return 1;
	}

	dnslib_rrset_free(&question_rrset);

	/* other RRSets */

	if ((ret = compare_rrsets_w_ldns_rrlist(packet->answer,
					 ldns_pkt_answer(ldns_packet),
					 packet->header.ancount)) != 0) {
		diag("Answer rrsets wrongly converted");
		return 1;
	}



	if ((ret = compare_rrsets_w_ldns_rrlist(packet->authority,
					 ldns_pkt_authority(ldns_packet),
					 packet->header.nscount)) != 0) {
		diag("Authority rrsets wrongly converted - %d", ret);
		return 1;
	}

	/* We don't want to test OPT RR, which is the last rrset
	 * in the additional section */

	if ((ret = compare_rrsets_w_ldns_rrlist(packet->additional,
					 ldns_pkt_additional(ldns_packet),
					 packet->header.arcount - 1)) != 0) {
		diag("Additional rrsets wrongly converted");
		return 1;
	}

	/* OPT RR */

	if (ldns_pkt_edns(ldns_packet)) {
		/* if (packet->edns_packet == NULL) {
			diag("ldns has edns section, dnslib has not");
			return 1;
		} */

		dnslib_opt_rr_t *opt = &(packet->edns_packet);

		if (ldns_pkt_edns_udp_size(ldns_packet) !=
		    dnslib_edns_get_payload(opt)) {
			diag("Payloads in EDNS are different");
			return 1;
		}

		if (ldns_pkt_edns_version(ldns_packet) !=
		    dnslib_edns_get_version(opt)) {
			diag("Versions in EDNS are different");
			return 1;
		}

		if (ldns_pkt_edns_extended_rcode(ldns_packet) !=
		    dnslib_edns_get_ext_rcode(opt)) {
			diag("Extended rcodes in EDNS are different");
			return 1;
		}

		/* TODO parse flags do bit, z value ... */
	}

	return 0;
}
#endif

static dnslib_packet_t *packet_from_test_response(test_response_t *test_packet)
{
	parsed_opt = NULL;

	dnslib_rrset_t *parsed_opt = NULL;

	for (int j = 0; j < test_packet->arcount; j++) {
		if (test_packet->additional[j]->type ==
		    DNSLIB_RRTYPE_OPT) {
			parsed_opt =
				rrset_from_test_rrset(
					test_packet->additional[j]);
			assert(parsed_opt);
		}
	}

	dnslib_opt_rr_t *opt_rr = opt_rrset_to_opt_rr(parsed_opt);

	resp = dnslib_packet_empty(opt_rr);

	if (opt_rr != NULL) {
		dnslib_edns_free(&opt_rr);
	}

	resp->header.id = test_packet->id;
	resp->header.qdcount = test_packet->qdcount;

	assert(test_packet->qname);

	resp->question.qname = test_packet->qname;
	resp->size += test_packet->qname->size;
	resp->question.qtype = test_packet->qtype;
	resp->question.qclass = test_packet->qclass;

	resp->size += 4;

	for (int j = 0; j < test_packet->ancount; j++) {
		if (&(test_packet->answer[j])) {
			if (dnslib_response_add_rrset_answer(resp,
			    test_packet->answer[j], 0, 0, 0) != 0) {
				char *tmp_dname =
				dnslib_dname_to_str(test_packet->
						    answer[j]->owner);
				diag("Could not add answer rrset");
				diag("owner: %s type: %d",
				     tmp_dname,
				     test_packet->answer[j]->type);
				free(tmp_dname);
				return 0;
			}
		}
	}


	assert(resp->header.ancount == test_packet->ancount);

	for (int j = 0; j < test_packet->nscount; j++) {
		if (&(test_packet->authority[j])) {
			if (dnslib_response_add_rrset_authority(resp,
				test_packet->authority[j],
				0, 0, 0) != 0) {
				diag("Could not add authority rrset");
				return 0;
			}
		}
	}


	assert(resp->header.nscount == test_packet->nscount);

	for (int j = 0; j < test_packet->arcount; j++) {
		if (&(test_packet->additional[j])) {
			if (test_packet->additional[j]->type ==
			    DNSLIB_RRTYPE_OPT) {
				continue;
			}
			if (dnslib_response_add_rrset_additional(resp,
				test_packet->additional[j],
				0, 0, 0) != 0) {
				diag("Could not add additional rrset");
				return 0;
			}
		}
	}

	/* Response is created */

//		assert(resp->header.arcount == responses[i]->arcount);

	uint8_t *dnslib_wire = NULL;

	size_t dnslib_wire_size;

	assert(resp->question.qname);

	if (dnslib_response_to_wire(resp, &dnslib_wire,
				    &dnslib_wire_size) != 0) {
		diag("Could not convert dnslib response to wire\n");
		dnslib_response_free(&resp);
		return 0;
	}
}

static int test_packet_parse_from_wire(list raw_response_list,
                                       list parsed_response_list)
{
	int errors = 0;
	assert(responses);

	dnslib_response_t *resp;

	dnslib_opt_rr_t *opt_rr = NULL;

	dnslib_rrset_t *parsed_opt = NULL;


		/* Response is created */

//		assert(resp->header.arcount == responses[i]->arcount);

		uint8_t *dnslib_wire = NULL;

		size_t dnslib_wire_size;

		assert(resp->question.qname);

		if (dnslib_response_to_wire(resp, &dnslib_wire,
					    &dnslib_wire_size) != 0) {
			diag("Could not convert dnslib response to wire\n");
			dnslib_response_free(&resp);
			return 0;
		}

#ifndef TEST_WITH_LDNS

		/* TODO investigate - was showing far more errors than expected*/

		diag("Not implemented without usage of ldns");

		return 0;

/*

		note("Comparing wires directly - might not be sufficient"
		     "Test with LDNS, if possible");

		uint tmp_places = compare_wires(dnslib_wire, raw_data[i]->data,
						dnslib_wire_size);


		if (tmp_places) {
			diag("Wires did not match - differ in %d places",
			     tmp_places);
			errors++;
		} */

#endif

#ifdef TEST_WITH_LDNS

		ldns_pkt *packet = NULL;

		if (ldns_wire2pkt(&packet, raw_data[i]->data,
				  raw_data[i]->size) != LDNS_STATUS_OK) {
			diag("Could not parse wire using ldns");
			diag("%s",
			     ldns_get_errorstr_by_id(ldns_wire2pkt(&packet,
							dnslib_wire,
							dnslib_wire_size)));
			return 0;
		}

		if (compare_response_w_ldns_packet(resp, packet) != 0) {
			diag("Wrongly created wire");
			return 0;
		}

		ldns_pkt_free(packet);
#endif

	dnslib_response_free(&resp);
	}

	return (errors == 0);
}

static const uint DNSLIB_PACKET_TEST_COUNT = 14;

static int packet_tests_count(int argc, char *argv[])
{
	return DNSLIB_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_dnslib_tests;
}

