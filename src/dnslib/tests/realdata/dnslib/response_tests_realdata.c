#include <assert.h>
#include <inttypes.h>

//#define RESP_TEST_DEBUG
#include "dnslib/tests/realdata/dnslib/response_tests_realdata.h"
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/response.h"
#include "dnslib/rdata.h"
#include "dnslib/rrset.h"
#include "dnslib/dname.h"
#include "dnslib/descriptor.h"
#include "dnslib/edns.h"
#include "common/lists.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

/*
 * Resources
 * \note .rc files are generated on compile-time.
 */
#include "dnslib/tests/parsed_data_queries.rc"
#include "dnslib/tests/parsed_data.rc"
#include "dnslib/tests/raw_data_queries.rc"
#include "dnslib/tests/raw_data.rc"

static int dnslib_response_tests_count(int argc, char *argv[]);
static int dnslib_response_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api response_tests_api = {
	"DNS library - response",      //! Unit name
	&dnslib_response_tests_count,  //! Count scheduled tests
	&dnslib_response_tests_run     //! Run scheduled tests
};

/*
 * Helper functions.
 */

/* Virtual I/O over memory. */
static int mem_read(void *dst, size_t n, const char **src,
		    unsigned *remaining) {
	if (n > *remaining) {
		return 0;
	}

	memcpy(dst, *src, n);
	*src += n;
	*remaining -= n;
	return 1;
}

/*
 *  Unit implementation.
 */

enum { DNAME_MAX_WIRE_LENGTH = 256 };

static int load_raw_packets(test_raw_packet_t ***raw_packets, uint32_t *count,
			    const char *src, unsigned src_size)
{
	assert(*raw_packets == NULL);
	uint16_t tmp_size = 0;

	/* Packets are stored like this: [size][packet_data]+ */

	if(!mem_read(count, sizeof(uint32_t), &src, &src_size)) {
		return -1;
	}

	*raw_packets = malloc(sizeof(test_raw_packet_t *) * *count);

	for (int i = 0; i < *count; i++) {
		if(!mem_read(&tmp_size, sizeof(uint16_t), &src, &src_size)) {
			return -1;
		}

		(*raw_packets)[i] = malloc(sizeof(test_raw_packet_t));
		(*raw_packets)[i]->size = tmp_size;
		(*raw_packets)[i]->data = malloc(sizeof(uint8_t) * (tmp_size));
		if(!mem_read((*raw_packets)[i]->data,
			     sizeof(uint8_t) * tmp_size, &src, &src_size)) {
			return -1;
		}
	}

	return 0;
}

void free_raw_packets(test_raw_packet_t ***raw_packets, uint32_t *count)
{
	if (*raw_packets != NULL) {
		for (int i = 0; i < *count; i++) {
			if ((*raw_packets)[i] != NULL) {
				if ((*raw_packets)[i]->data != NULL) {
					free((*raw_packets)[i]->data);
				}
				free((*raw_packets)[i]);
			}
		}
		free(*raw_packets);
	}
}

extern dnslib_rrset_t *rrset_from_test_rrset(test_rrset_t *test_rrset);

static int test_response_add_rrset(int (*add_func)
				   (dnslib_response_t *,
				   const dnslib_rrset_t *, int, int, int),
				   list rrset_list,
                                   uint array_id)
{
	/*
	 * Tests add_rrset by adding it and then manually looking for it
	 * in the array using compare_rrsets.
	 */
	int errors = 0;

	dnslib_response_t *resp = dnslib_response_new_empty(NULL);
	assert(resp);

	const dnslib_rrset_t **array;

	switch (array_id) {
		case 1: {
			array = resp->answer;
			break;
		}
		case 2: {
			array = resp->authority;
			break;
		}
		case 3: {
			array = resp->additional;
			break;
		}
		default: {
			dnslib_response_free(&resp);
			return 0;
		}
	} /* switch */

	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		dnslib_rrset_t *rrset = rrset_from_test_rrset(test_rrset);
		assert(rrset && rrset->owner);
//		diag("Trying to add rrset with owner: %s\n",
//		     dnslib_dname_to_str(rrset->owner));
		if (dnslib_dname_compare(rrset->owner,
		                         dnslib_dname_new_from_str(".", 1,
		                                                   NULL)) != 0) {
			if (add_func(resp, rrset, 0, 0, 0) != 0) {
				diag("Could not add RRSet to response!\n");
				return 0;
			}
		}
		dnslib_rrset_free(&rrset);
	}

	dnslib_response_free(&resp);

	return (errors == 0);
}

static int test_response_add_rrset_answer(list rrset_list)
{
	return test_response_add_rrset(&dnslib_response_add_rrset_answer,
				       rrset_list, 1);
}

static int test_response_add_rrset_authority(list rrset_list)
{
	return test_response_add_rrset(&dnslib_response_add_rrset_authority,
				       rrset_list, 2);
}
static int test_response_add_rrset_additional(list rrset_list)
{
	return test_response_add_rrset(&dnslib_response_add_rrset_additional,
				       rrset_list, 3);
}

static dnslib_dname_t *dname_from_test_dname(const test_dname_t *test_dname)
{
	return dnslib_dname_new_from_wire(test_dname->wire, test_dname->size,
	                                  NULL);
}

static int check_response(dnslib_response_t *resp, test_response_t *test_resp,
			  int check_header, int check_question,
			  int check_answer, int check_additional,
			  int check_authority)
{
	int errors = 0; /* TODO maybe use it everywhere, or not use it at all */

	if (check_question) {
		/* again, in case of dnames, pointer would probably suffice */
		if (dnslib_dname_compare(resp->question.qname,
		                dname_from_test_dname(test_resp->qname)) != 0) {
			char *tmp_dname;
			tmp_dname = dnslib_dname_to_str(resp->question.qname);
			diag("Qname in response is wrong:\
			      should be: %s is: %s\n",
			     tmp_dname, test_resp->qname->str);
			free(tmp_dname);
			return 0;
		}

		if (resp->question.qtype != test_resp->qtype) {
			diag("Qtype value is wrong: is %u should be %u\n",
			     resp->question.qtype, test_resp->qtype);
			return 0;
		}
		if (resp->question.qclass != test_resp->qclass) {
			diag("Qclass value is wrong: is %u should be %u\n",
			     resp->question.qclass, test_resp->qclass);
			return 0;
		}
	}

	if (check_header) {
		/* Disabled, since these check make no sense
		 * if we have parsed the query, flags are now set to
		 * the ones response should have */

		/*
		if (resp->header.flags1 != test_resp->flags1) {
			diag("Flags1 value is wrong: is %u should be %u\n",
			     resp->header.flags1, test_resp->flags1);
			//return 0;
		}
		if (resp->header.flags2 != test_resp->flags2) {
			diag("Flags2 value is wrong: is %u should be %u\n",
			     resp->header.flags2, test_resp->flags2);
			return 0;
		}
		*/

		if (resp->header.qdcount != test_resp->qdcount) {
			diag("Qdcount value is wrong: is %u should be %u\n",
			     resp->header.qdcount, test_resp->qdcount);
			return 0;
		}
		if (resp->header.ancount != test_resp->ancount) {
			diag("Ancount value is wrong: is %u should be %u\n",
			     resp->header.ancount, test_resp->ancount);
			return 0;
		}
		if (resp->header.nscount != test_resp->nscount) {
			diag("Nscount value is wrong: is %u should be %u\n",
			     resp->header.nscount, test_resp->nscount);
			return 0;
		}
		if (resp->header.arcount != test_resp->arcount) {
			diag("Arcount value is different: is %u should be %u\n",
			     resp->header.arcount, test_resp->arcount);
//			return 0;
		}
	}

	if (check_question) {
		/* Currently just one question RRSET allowed */
		if (dnslib_dname_compare(resp->question.qname,
		    dname_from_test_dname(test_resp->qname)) != 0) {
			diag("Qname is wrongly set");
			errors++;
		}

		if (resp->question.qtype != test_resp->qtype) {
			diag("Qtype is wrongly set");
			errors++;
		}

		if (resp->question.qclass != test_resp->qclass) {
			diag("Qclass is wrongly set");
			errors++;
		}

	}

	/* Following code is not used anywhere currently. */

//	if (check_authority) {
//		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
//			if (resp->authority[i] != (test_resp->authority[i])) {
//				diag("Authority rrset #%d is wrongly set.\n",
//				     i);
//				errors++;
//			}
//		}
//	}

//	if (check_answer) {
//		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
//			if (resp->authority[i] != (test_resp->authority[i])) {
//				diag("Authority rrset #%d is wrongly set.\n",
//				     i);
//				errors++;
//			}
//		}
//	}

//	if (check_additional) {
//		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
//			if (resp->authority[i] != (test_resp->authority[i])) {
//				diag("Authority rrset #%d is wrongly set.\n",
//				     i);
//				errors++;
//			}
//		}
//	}

	return (errors == 0);
}

static int test_response_parse_query(list response_list,
				     test_raw_packet_t **raw_queries,
				     uint count)
{
	assert(raw_queries);

	int errors = 0;
	dnslib_response_t *resp = NULL;
	node *n = NULL;
	int i = 0;
	WALK_LIST(n, response_list) {
		assert(i < count);
		test_response_t *test_response = (test_response_t *)n;
		resp = dnslib_response_new_empty(NULL);
		assert(resp);

//		hex_print(raw_queries[i]->data, raw_queries[i]->size);

		if (dnslib_response_parse_query(resp,
						raw_queries[i]->data,
						raw_queries[i]->size) != 0) {
			diag("Could not parse query\n");
			errors++;
		}
		errors += !check_response(resp, test_response, 1, 1, 0, 0, 0);
		dnslib_response_free(&resp);
		i++;
	}

	return (errors == 0);
}

#ifndef TEST_WITH_LDNS
/*! \note disabled */
//static int compare_wires(uint8_t *wire1, uint8_t *wire2, uint size)
//{
//	uint ret = 0;
//	for (int i = 0; i < size; i++) {
//		if (wire1[i] != wire2[i]) {
//			if (i != 2 && i != 11) {
//				ret+=1;
//				diag("Bytes on position %d differ", i);
//				diag("pcap:");
//				hex_print((char *)&wire2[i], 1);
//				diag("response");
//				hex_print((char *)&wire1[i], 1);
//			} else {
//				diag("Wires differ at tolerated "
//				     "positions (AA bit, Additional section)");
//			}
//		}
//	}
//	return ret;
//}
#endif

/* count1 == count2 */
int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count)
{
	int i = 0;
	while (i < count &&
	       wire1[i] == wire2[i]) {
		i++;
	}
	return (!(count == i));
}

#ifdef TEST_WITH_LDNS

/* Compares one rdata dnslib with rdata from ldns.
 * Comparison is done through comparing wireformats.
 * Returns 0 if rdata are the same, 1 otherwise
 */
static int compare_rr_rdata(dnslib_rdata_t *rdata, ldns_rr *rr,
			    uint16_t type)
{
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	for (int i = 0; i < rdata->count; i++) {
		/* check for ldns "descriptors" as well */

		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME) {
			if (rdata->items[i].dname->size !=
			    ldns_rdf_size(ldns_rr_rdf(rr, i))) {
				diag("%s", rdata->items[i].dname->name);
				diag("%s", ldns_rdf_data(ldns_rr_rdf(rr, i)));
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
				 * length, dnslib does not */
				diag("Raw data sizes in rdata differ");
				diag("dnslib: %d ldns: %d",
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
				hex_print((char *)
					  (rdata->items[i].raw_data + 1),
					  rdata->items[i].raw_data[0]);
				hex_print((char *)
					  ldns_rdf_data(ldns_rr_rdf(rr, i)),
					  rdata->items[i].raw_data[0]);
				diag("Raw data wires in rdata differ in item "
				     "%d", i);

				return 1;
			}
		}
	}

	return 0;
}

static int compare_rrset_w_ldns_rr(const dnslib_rrset_t *rrset,
				      ldns_rr *rr, char check_rdata)
{
	/* We should have only one rrset from ldns, although it is
	 * represented as rr_list ... */

	assert(rr);
	assert(rrset);

	/* compare headers */

	if (rrset->owner->size != ldns_rdf_size(ldns_rr_owner(rr))) {
		char *tmp_dname = dnslib_dname_to_str(rrset->owner);
		diag("RRSet owner names differ in length");
		diag("ldns: %d, dnslib: %d", ldns_rdf_size(ldns_rr_owner(rr)),
		     rrset->owner->size);
		diag("%s", tmp_dname);
		diag("%s", ldns_rdf_data(ldns_rr_owner(rr)));
		free(tmp_dname);
		return 1;
	}

	if (compare_wires_simple(rrset->owner->name,
				 ldns_rdf_data(ldns_rr_owner(rr)),
				 rrset->owner->size) != 0) {
		diag("RRSet owner wireformats differ");
		return 1;
	}

	if (rrset->type != ldns_rr_get_type(rr)) {
		diag("RRset types differ");
		diag("Dnslib type: %d Ldns type: %d", rrset->type,
		     ldns_rr_get_type(rr));
		return 1;
	}

	if (rrset->rclass != ldns_rr_get_class(rr)) {
		diag("RRset classes differ");
		return 1;
	}

	if (rrset->ttl != ldns_rr_ttl(rr)) {
		diag("RRset TTLs differ");
		diag("dnslib: %d ldns: %d", rrset->ttl, ldns_rr_ttl(rr));
		return 1;
	}

	/* compare rdatas */

	/* commented code for multiple rdata */

//	dnslib_rdata_t *tmp_rdata = rrset->rdata;

//	int i = 0;

//	while (tmp_rdata->next != rrset->rdata) {
//		rr = ldns_rr_list_rr(rr_set, i);
//		/* TODO use this in the other cases as
//		 * well, it's better than pop */
//		if (rr == NULL) {
//			diag("ldns rrset has more rdata entries"
//			     "than the one from dnslib");
//			return 1;
//		}

//		if (compare_rr_rdata(tmp_rdata, rr, rrset->type) != 0) {
//			diag("Rdata differ");
//			return 1;
//		}

//		tmp_rdata = tmp_rdata->next;
//		i++;
//	}

//	/* TODO double check the indexing */
//	rr = ldns_rr_list_rr(rr_set, i);
//	if (rr == NULL) {
//		diag("ldns rrset has more rdata entries"
//		     "than the one from dnslib");
//		return 1;
//	}

//	if (compare_rr_rdata(tmp_rdata, rr, rrset->type) != 0) {
//		diag("Rdata differ");
//		return 1;
//	}

	if (check_rdata) {
		if (compare_rr_rdata(rrset->rdata, rr, rrset->type) != 0) {
			diag("Rdata differ");
			return 1;
		}
	}

	return 0;
}

static int compare_rrsets_w_ldns_rrlist(const dnslib_rrset_t **rrsets,
					ldns_rr_list *rrlist, int count)
{
	int errors = 0;

	/* There are no rrsets currenty. Everything is just rr */

	ldns_rr *rr = NULL;

	if (count < 0) {
		return 0;
	}

	for (int i = 0; i < count ; i++) {
		/* normally ldns_pop_rrset or such should be here */
		rr = ldns_rr_list_rr(rrlist, i);

		if (rr == NULL) {
			diag("Ldns and dnslib structures have different "
			     "counts of rrsets.");
			diag("dnslib: %d ldns: %d",
			     count, (count - 1) - i);
			return -1;
		}

		if (compare_rrset_w_ldns_rr(rrsets[i],
					rr, 1) != 0) {
			errors++;
		}
	}

	return errors;
}

/* This is not actuall compare, it just returns 1 everytime anything is
 * different.
 * TODO well, call it "check" then
 */
static int compare_response_w_ldns_packet(dnslib_response_t *response,
					  ldns_pkt *packet)
{
	if (response->header.id != ldns_pkt_id(packet)) {
		diag("response ID does not match. Is: %d should be: %d",
		     response->header.id, ldns_pkt_id(packet));
		return 1;
	}

	/* qdcount is always 1 in dnslib's case */

	/* TODO check flags1 and flags2 - no API for that, write my own*/

	if (dnslib_response_answer_rrset_count(response) !=
	    ldns_pkt_ancount(packet)) {
		diag("Answer RRSet count wrongly converted");
		return 1;
	}

	if (dnslib_response_authority_rrset_count(response) !=
	    ldns_pkt_nscount(packet)) {
		diag("Authority RRSet count wrongly converted");
		return 1;
	}

	if (dnslib_response_additional_rrset_count(response) !=
	    ldns_pkt_arcount(packet)) {
		diag("Additional RRSet count wrongly converted");
		return 1;
	}

	/* Header checked */

	/* Question section */

	int ret = 0;

	dnslib_rrset_t *question_rrset = dnslib_rrset_new(response->
							  question.qname,
							  response->
							  question.qtype,
							  response->
							  question.qclass,
							  3600);

	if ((ret = compare_rrset_w_ldns_rr(question_rrset,
			ldns_rr_list_rr(ldns_pkt_question(packet),
					0), 0)) != 0) {
		diag("Question rrsets wrongly converted");
		return 1;
	}

	dnslib_rrset_free(&question_rrset);

	/* other RRSets */

	if ((ret = compare_rrsets_w_ldns_rrlist(response->answer,
					 ldns_pkt_answer(packet),
					 response->header.ancount)) != 0) {
		diag("Answer rrsets wrongly converted");
		return 1;
	}



	if ((ret = compare_rrsets_w_ldns_rrlist(response->authority,
					 ldns_pkt_authority(packet),
					 response->header.nscount)) != 0) {
		diag("Authority rrsets wrongly converted - %d", ret);
		return 1;
	}

	/* We don't want to test OPT RR, which is the last rrset
	 * in the additional section */

	if ((ret = compare_rrsets_w_ldns_rrlist(response->additional,
					 ldns_pkt_additional(packet),
					 response->header.arcount - 1)) != 0) {
		diag("Additional rrsets wrongly converted");
		return 1;
	}

	/* OPT RR */

	if (ldns_pkt_edns(packet)) {
/*                if (response->edns_response == NULL) {
			diag("ldns has edns section, dnslib has not");
			return 1;
		} */

		dnslib_opt_rr_t *opt = &(response->edns_response);

		if (ldns_pkt_edns_udp_size(packet) !=
		    dnslib_edns_get_payload(opt)) {
			diag("Payloads in EDNS are different");
			return 1;
		}

		if (ldns_pkt_edns_version(packet) !=
		    dnslib_edns_get_version(opt)) {
			diag("Versions in EDNS are different");
			return 1;
		}

		if (ldns_pkt_edns_extended_rcode(packet) !=
		    dnslib_edns_get_ext_rcode(opt)) {
			diag("Extended rcodes in EDNS are different");
			return 1;
		}

		/* TODO parse flags do bit, z value ... */
	}

	return 0;
}

#endif

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

/*
 * Tests response_to_wire by creating wireformat from parsed response, then,
 * using that wire, creates ldns structure which is then compared with the
 * original dnslib structure.
 */
static int test_response_to_wire(list response_list,
				 test_raw_packet_t **raw_data,
				 uint count)
{
	diag("There is some issue with creation of response from opt_rr");
	return 0;
	int errors = 0;
	dnslib_response_t *resp;
	dnslib_opt_rr_t *opt_rr = NULL;
	dnslib_rrset_t *parsed_opt = NULL;

	node *n = NULL;
	int i = 0;
	WALK_LIST(n, response_list) {

	/* This cycle creates actual dnslib_response_t's from parsed ones */

		test_response_t *test_response = (test_response_t *)n;
		parsed_opt = NULL;

		for (int j = 0; j < test_response->arcount; j++) {
			if (test_response->additional[j]->type ==
			    DNSLIB_RRTYPE_OPT) {
				parsed_opt =
			rrset_from_test_rrset(test_response->additional[j]);
			}
		}

		opt_rr = opt_rrset_to_opt_rr(parsed_opt);

		resp = dnslib_response_new_empty(opt_rr);

		if (opt_rr != NULL) {
			dnslib_edns_free(&opt_rr);
		}

		resp->header.id = test_response->id;
		resp->header.qdcount = test_response->qdcount;

		assert(test_response->qname);

		resp->question.qname =
			dname_from_test_dname(test_response->qname);
		resp->size += test_response->qname->size;
		resp->question.qtype = test_response->qtype;
		resp->question.qclass = test_response->qclass;

		resp->size += 4;

		for (int j = 0; j < test_response->ancount; j++) {
			if (&(test_response->answer[j])) {
				if (dnslib_response_add_rrset_answer(resp,
					rrset_from_test_rrset(test_response->answer[j]),
							0, 0, 0) != 0) {
					diag("Could not add answer rrset");
					diag("owner: %s type: %d",
					test_response->answer[j]->owner->str,
					test_response->answer[j]->type);
					return 0;
				}
			}
		}


		assert(resp->header.ancount == test_response->ancount);

		for (int j = 0; j < test_response->nscount; j++) {
			if (&(test_response->authority[j])) {
				if (dnslib_response_add_rrset_authority(resp,
					rrset_from_test_rrset(test_response->authority[j]),
					0, 0, 0) != 0) {
					diag("Could not add authority rrset");
					return 0;
				}
			}
		}


		assert(resp->header.nscount == test_response->nscount);

		for (int j = 0; j < test_response->arcount; j++) {
			if (&(test_response->additional[j])) {
				if (test_response->additional[j]->type ==
				    DNSLIB_RRTYPE_OPT) {
					continue;
				}
				if (dnslib_response_add_rrset_additional(resp,
					rrset_from_test_rrset(test_response->additional[j]),
					0, 0, 0) != 0) {
					diag("Could not add additional rrset");
					return 0;
				}
			}
		}

		/* Response is created */

//		assert(resp->header.arcount == test_response->arcount);

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
	i++;
	}

	return (errors == 0);
}

static const int DNSLIB_RESPONSE_TEST_COUNT = 4;

int dnslib_response_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE_TEST_COUNT;
}

int dnslib_response_tests_run(int argc, char *argv[])
{
	int ret;

	test_data_t *data = data_for_dnslib_tests;

	ok(test_response_add_rrset_answer(data->rrset_list),
	   "response: add rrset answer");
	ok(test_response_add_rrset_authority(data->rrset_list),
	   "response: add rrset authority");
	ok(test_response_add_rrset_additional(data->rrset_list),
	   "response: add rrset additional");

	test_raw_packet_t **raw_responses = NULL;
	test_raw_packet_t **raw_queries = NULL;
	uint32_t response_raw_count = 0;
	uint32_t query_raw_count = 0;

	if (load_raw_packets(&raw_responses, &response_raw_count,
			 raw_data_rc, raw_data_rc_size) != 0) {
		diag("Could not load raw responses, skipping");
		free_raw_packets(&raw_responses, &response_raw_count);
		return 0;
	}

	diag("read %d raw responses\n", response_raw_count);

	if (load_raw_packets(&raw_queries, &query_raw_count,
			     raw_data_queries_rc,
			     raw_data_queries_rc_size) != 0) {
		diag("Could not load raw queries, skipping");
		free_raw_packets(&raw_queries, &query_raw_count);
		free_raw_packets(&raw_responses, &response_raw_count);
		return 0;
	}

	diag("read %d raw queries\n", query_raw_count);

	/* Disabled for now... */
//	ok(test_response_parse_query(data->response_list,
//				     raw_queries,
//				     query_raw_count),
//	   "response: parse query");

	ok(test_response_to_wire(data->response_list, raw_responses,
				 response_raw_count), "response: to wire");

	free_raw_packets(&raw_responses, &response_raw_count);

	free_raw_packets(&raw_queries, &query_raw_count);

	return 0;
}
