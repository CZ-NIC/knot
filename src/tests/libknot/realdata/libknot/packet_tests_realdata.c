/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include <config.h>
#include "knot/common.h"
#include "packet_tests_realdata.h"
#include "libknot/packet/packet.h"
#include "libknot/packet/response.h"
/* *test_t structures */
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
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
/* Compares one rdata knot with rdata from ldns.
 * Comparison is done through comparing wireformats.
 * Returns 0 if rdata are the same, 1 otherwise
 */
int compare_rr_rdata(knot_rdata_t *rdata, ldns_rr *rr,
			    uint16_t type)
{
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	for (int i = 0; i < rdata->count; i++) {
		/* check for ldns "descriptors" as well */

		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME) {
			if (rdata->items[i].dname->size !=
			    ldns_rdf_size(ldns_rr_rdf(rr, i))) {
				diag("%s", rdata->items[i].dname->name);
				diag("%s", ldns_rdf_data(ldns_rr_rdf(rr, i)));
				diag("%d", ldns_rdf_size(ldns_rr_rdf(rr, i)));
				diag("%d", rdata->items[i].dname->size);
				diag("Dname sizes in rdata differ");
				return 1;
			}
			if (compare_wires_simple(rdata->items[i].dname->name,
				ldns_rdf_data(ldns_rr_rdf(rr, i)),
				rdata->items[i].dname->size) != 0) {
				diag("%s", rdata->items[i].dname->name);
				diag("%s", ldns_rdf_data(ldns_rr_rdf(rr, i)));
				diag("Dname wires in rdata differ");
				return 1;
			}
		} else {
			/* Compare sizes first, then actual data */
			if (rdata->items[i].raw_data[0] !=
			    ldns_rdf_size(ldns_rr_rdf(rr, i))) {
				/* \note ldns stores the size including the
				 * length, knot does not */
				diag("Raw data sizes in rdata differ");
				diag("knot: %d ldns: %d",
				     rdata->items[i].raw_data[0],
				     ldns_rdf_size(ldns_rr_rdf(rr, i)));
//				hex_print((char *)
//					  (rdata->items[i].raw_data + 1),
//					  rdata->items[i].raw_data[0]);
//				hex_print((char *)ldns_rdf_data(ldns_rr_rdf(rr,
//									    i)),
//					  ldns_rdf_size(ldns_rr_rdf(rr, i)));
				if (abs(rdata->items[i].raw_data[0] -
				    ldns_rdf_size(ldns_rr_rdf(rr, i))) != 1) {
					return 1;
				}
			}
			if (compare_wires_simple((uint8_t *)
				(rdata->items[i].raw_data + 1),
				ldns_rdf_data(ldns_rr_rdf(rr, i)),
				rdata->items[i].raw_data[0]) != 0) {
//				hex_print((char *)
//					  (rdata->items[i].raw_data + 1),
//					  rdata->items[i].raw_data[0]);
//				hex_print((char *)
//					  ldns_rdf_data(ldns_rr_rdf(rr, i)),
//					  rdata->items[i].raw_data[0]);
				diag("Raw data wires in rdata differ in item "
				     "%d", i);

				return 1;
			}
		}
	}

	return 0;
}

int compare_rrset_w_ldns_rr(const knot_rrset_t *rrset,
				      ldns_rr_list *rr_set, char check_rdata)
{
	/* We should have only one rrset from ldns, although it is
	 * represented as rr_list ... */

	int errors = 0;

	ldns_rr *rr = ldns_rr_list_rr(rr_set, 0);
	assert(rr);
	assert(rrset);

	/* compare headers */

	if (rrset->owner->size != ldns_rdf_size(ldns_rr_owner(rr))) {
		char *tmp_dname = knot_dname_to_str(rrset->owner);
		diag("RRSet owner names differ in length");
		diag("ldns: %d, knot: %d", ldns_rdf_size(ldns_rr_owner(rr)),
		     rrset->owner->size);
		diag("%s", tmp_dname);
		diag("%s", ldns_rdf_data(ldns_rr_owner(rr)));
		free(tmp_dname);
		errors++;
	}

	if (compare_wires_simple(rrset->owner->name,
				 ldns_rdf_data(ldns_rr_owner(rr)),
				 rrset->owner->size) != 0) {
		diag("RRSet owner wireformats differ");
		diag("%s \\w %s\n", rrset->owner->name,
		     ldns_rdf_data(ldns_rr_owner(rr)));
		errors++;
	}

	if (rrset->type != ldns_rr_get_type(rr)) {
		diag("RRset types differ");
		diag("knot type: %d Ldns type: %d", rrset->type,
		     ldns_rr_get_type(rr));
		errors++;
	}

	if (rrset->rclass != ldns_rr_get_class(rr)) {
		diag("RRset classes differ");
		errors++;
	}

	if (rrset->ttl != ldns_rr_ttl(rr)) {
		diag("RRset TTLs differ");
		diag("knot: %d ldns: %d", rrset->ttl, ldns_rr_ttl(rr));
		errors++;
	}

	/* compare rdatas */

	if (rrset->rdata == NULL) {
		diag("RRSet has no RDATA!");
		return errors;
	}
	knot_rdata_t *tmp_rdata = rrset->rdata;

	int i = 0;

	while ((rr = ldns_rr_list_pop_rr(rr_set))) {
		assert(rr);

		if (compare_rr_rdata(tmp_rdata, rr, rrset->type) != 0) {
			diag("Rdata differ");
			return 1;
		}

		tmp_rdata = tmp_rdata->next;
		i++;
	}

////	if (check_rdata) {
////		if (compare_rr_rdata(rrset->rdata, rr, rrset->type) != 0) {
////			diag("Rdata differ");
////			errors++;
////		}
////	}

	return errors;
}

int compare_rrsets_w_ldns_rrlist(const knot_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count)
{
	int errors = 0;

	/* There are no rrsets currenty. Everything is just rr */

	ldns_rr_list *rr_set = NULL;

	ldns_rr_list_sort(rrlist);

	if (count < 0) {
		return 0;
	}

	for (int i = 0; i < count ; i++) {
		/* normally ldns_pop_rrset or such should be here */

		rr_set = ldns_rr_list_pop_rrset(rrlist);
		/* Get one rr from list. */
		ldns_rr *rr = ldns_rr_list_rr(rr_set, 0);
		assert(rr);

		if (rr_set == NULL) {
			diag("Ldns and knot structures have different "
			     "counts of rrsets.");
			diag("knot: %d ldns: %d",
			     count, (count - 1) - i);
			return -1;
		}

//		diag("RRset from ldns is %d long", ldns_rr_list_rr_count(rr_set));

//		diag("Got type from ldns: %d (%d)\n", ldns_rr_get_type(rr), i);

		int j = 0;
		for (j = 0; j < count; j++) {
//			diag("Got type from knot: %d\n", rrsets[j]->type);
			if (rrsets[j]->type == ldns_rr_get_type(rr) &&
			    rrsets[j]->owner->size ==
			    ldns_rdf_size(ldns_rr_owner(rr)) &&
			    (compare_wires_simple(ldns_rdf_data(ldns_rr_owner(rr)), rrsets[j]->owner->name,
			    rrsets[j]->owner->size) == 0)) {
				errors += compare_rrset_w_ldns_rr(rrsets[j],
				                                  rr_set, 1);
				break;
			}
		}
		if (j == count) {
			diag("There was no RRSet of the same type!");
//			errors++;
		}
	}

	return errors;
}

int check_packet_w_ldns_packet(knot_packet_t *packet,
                                      ldns_pkt *ldns_packet,
                                      int check_header,
                                      int check_question,
                                      int check_body,
                                      int check_edns)
{
	int errors = 0;
	if (check_header) {
//		if (packet->header.id != ldns_pkt_id(ldns_packet)) {
//			diag("response ID does not match - %d %d",
//			     packet->header.id,
//			     ldns_pkt_id(ldns_packet));
//			errors++;
//		}

		/* qdcount is always 1 in knot's case */

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
			     packet->header.nscount,
			     ldns_pkt_nscount(ldns_packet));
			errors++;
		}

		/* - 1 because ldns does not include OPT_RR to additional "
		 "section */
		int minus = (!ldns_pkt_edns_version(ldns_packet)) ? 1 : 0;
//		int minus = 0;

		if ((packet->header.arcount - minus) !=
		                ldns_pkt_arcount(ldns_packet)) {
			diag("Additional RRSet count wrongly converted.\n"
			     "got %d should be %d",
			     packet->header.arcount,
			     ldns_pkt_arcount(ldns_packet));
			errors++;
		}

		/*!< \todo Check OPT RR! */

		if (errors) {
			return errors;
		}
	}
	/* Header checked */

	/* Question section */

	int ret = 0;
	if (check_question) {
		knot_rrset_t *question_rrset =
		                knot_rrset_new(packet->
		                                 question.qname,
		                                 packet->
		                                 question.qtype,
		                                 packet->
		                                 question.qclass,
		                                 3600);

		if ((ret = compare_rrset_w_ldns_rr(question_rrset,
			ldns_pkt_question(ldns_packet), 0)) != 0) {
			diag("Question rrsets wrongly converted");
			errors++;
		}
		knot_rrset_free(&question_rrset);
	}

	if (check_body) {

		/* other RRSets */

		if ((ret =
		     compare_rrsets_w_ldns_rrlist(packet->answer,
		                         ldns_pkt_answer(ldns_packet),
                        knot_packet_answer_rrset_count(packet))) != 0) {
			diag("Answer rrsets wrongly converted");
			errors++;
		}



		if ((ret = compare_rrsets_w_ldns_rrlist(packet->authority,
		                             ldns_pkt_authority(ldns_packet),
			knot_packet_authority_rrset_count(packet))) != 0) {
			diag("Authority rrsets wrongly converted - %d", ret);
			errors++;
		}

		/* We don't want to test OPT RR, which is the last rrset
		 * in the additional section */

		if ((ret = compare_rrsets_w_ldns_rrlist(packet->additional,
		                           ldns_pkt_additional(ldns_packet),
			knot_packet_additional_rrset_count(packet) - 1)) != 0) {
			diag("Additional rrsets wrongly converted");
			errors++;
		}

	}

	if (check_edns) {

		/* OPT RR */

		if (ldns_pkt_edns(ldns_packet)) {
			/* if (packet->edns_packet == NULL) {
   diag("ldns has edns section, knot has not");
   return 1;
  } */

			knot_opt_rr_t *opt = &(packet->opt_rr);

			if (ldns_pkt_edns_udp_size(ldns_packet) !=
			                knot_edns_get_payload(opt)) {
				diag("Payloads in EDNS are different");
				errors++;
			}

			if (ldns_pkt_edns_version(ldns_packet) !=
			                knot_edns_get_version(opt)) {
				diag("Versions in EDNS are different");
				errors++;
			}

			if (ldns_pkt_edns_extended_rcode(ldns_packet) !=
			                knot_edns_get_ext_rcode(opt)) {
				diag("Extended rcodes in EDNS are different");
				errors++;
			}

			/* TODO parse flags do bit, z value ... */
		}
	}

	return errors;
}
#endif

extern knot_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset);
extern knot_dname_t *dname_from_test_dname(const test_dname_t *test_dname);

/* Converts knot_rrset_t to knot_opt_rr */
static knot_opt_rr_t *opt_rrset_to_opt_rr(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	knot_opt_rr_t *opt_rr = knot_edns_new();
	assert(opt_rr);

	knot_edns_set_payload(opt_rr, rrset->rclass);

	knot_edns_set_ext_rcode(opt_rr, rrset->ttl);

	/* TODO rdata? mostly empty, I guess, but should be done */

	return opt_rr;
}

knot_packet_t *packet_from_test_response(test_response_t *test_packet)
{
	knot_rrset_t *parsed_opt = NULL;

	for (int j = 0; j < test_packet->arcount; j++) {
		if (test_packet->additional[j]->type ==
		    KNOT_RRTYPE_OPT) {
			parsed_opt =
				rrset_from_test_rrset(
				test_packet->additional[j]);
			assert(parsed_opt);
			break;
		}
	}

	knot_opt_rr_t *opt_rr = NULL;
	if (parsed_opt != NULL) {
		opt_rr =
			opt_rrset_to_opt_rr(parsed_opt);
		assert(opt_rr);
	} else {
		opt_rr = NULL;
	}

	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	assert(packet);
	knot_packet_set_max_size(packet, 1024 * 10);

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
		malloc(sizeof(knot_rrset_t *) * test_packet->ancount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->ancount; j++) {
		if (&(test_packet->answer[j])) {
			packet->answer[packet->an_rrsets++] =
			  rrset_from_test_rrset(test_packet->answer[j]);
		}
	}

	packet->authority =
		malloc(sizeof(knot_rrset_t *) * test_packet->nscount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->nscount; j++) {
		if (&(test_packet->authority[j])) {
			packet->authority[packet->ns_rrsets++] =
			  rrset_from_test_rrset(test_packet->authority[j]);
		}
	}

	packet->authority =
		malloc(sizeof(knot_rrset_t *) * test_packet->arcount);
	assert(packet->answer);

	for (int j = 0; j < test_packet->arcount; j++) {
		if (&(test_packet->additional[j])) {
			if (test_packet->additional[j]->type ==
			    KNOT_RRTYPE_OPT) {
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
#ifdef TEST_WITH_LDNS
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n ,raw_response_list) {
		test_raw_packet_t *raw_packet = (test_raw_packet_t *)n;
		knot_packet_t *packet =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		int ret = 0;
		if ((ret =
		     knot_packet_parse_from_wire(packet, raw_packet->data,
		                                   raw_packet->size, 0)) !=
		    KNOT_EOK) {
			diag("Warning: could not parse wire! "
			     "(might be caused by malformed dump) - "
			     "knot error: %s", knot_strerror(ret));
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
		knot_packet_free(&packet);
	}

	return (errors == 0);
#endif
#ifndef TEST_WITH_LDNS
	diag("Enable ldns to test this feature");
	return 0;
#endif
}

static int test_packet_to_wire(list raw_response_list)
{
#ifdef TEST_WITH_LDNS
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
		knot_packet_t *packet =
			knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
		assert(packet);
		test_raw_packet_t *raw_packet = (test_raw_packet_t *)n;
		if (knot_packet_parse_from_wire(packet, raw_packet->data,
		                                  raw_packet->size, 0) !=
		    KNOT_EOK) {
			diag("Warning: could not parse wire! "
			     "(might be caused be malformed dump)");
			continue;
		}
		knot_packet_set_max_size(packet, 1024 * 10);
		/* Use this packet to create wire */
		uint8_t *wire = NULL;
		size_t size = 0;
		if (knot_packet_to_wire(packet, &wire ,&size) != KNOT_EOK) {
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
		knot_packet_free(&packet);
		ldns_pkt_free(ldns_packet);
	}

	return (errors == 0);
#endif
#ifndef TEST_WITH_LDNS
	diag("Enable ldns to test this feature!");
	return 0;
#endif
}

static const uint KNOT_PACKET_TEST_COUNT = 2;

static int packet_tests_count(int argc, char *argv[])
{
	return KNOT_PACKET_TEST_COUNT;
}

static int packet_tests_run(int argc, char *argv[])
{
	const test_data_t *data = data_for_knot_tests;

	int res = 0;
	todo();
	ok(res = test_packet_parse_from_wire(data->raw_packet_list),
	   "packet: from wire");
	diag("Resolve issue with arcount.");
	endtodo;
//	skip(!res, 1);
	ok(test_packet_to_wire(data->raw_packet_list), "packet: to wire");
//	endskip;

	return 1;
}

