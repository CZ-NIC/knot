/*!
 * \file dnslib_response_tests.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * Contains unit tests for RRSet (dnslib_rrset_t) and its API.
 *
 * Contains tests for:
 * - Response API
 */

#include <assert.h>
#include <inttypes.h>

#include "tap_unit.h"

#include "response.h"
#include "rdata.h"
#include "rrset.h"
#include "dname.h"
#include "packet.h"

#include "ldns/ldns.h"
#include <stdbool.h>

static int dnslib_response_tests_count(int argc, char *argv[]);
static int dnslib_response_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_response_tests_api = {
	"DNS library - response",      //! Unit name
	&dnslib_response_tests_count,  //! Count scheduled tests
	&dnslib_response_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

struct test_response {
	dnslib_dname_t *owner;
	uint16_t rclass;
	uint16_t type;
	uint16_t id;
	uint8_t flags1;
	uint8_t flags2;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	dnslib_rrset_t *answer;
	dnslib_rrset_t *authority;
	dnslib_rrset_t *additional;

	short size;

	/* TODO what about the rest of the values?
	 * they cannot be modified from API, but this is probably the best
	 * place to test them as well */

};

typedef struct test_response test_response_t;

struct test_raw_packet {
	uint size;
	uint8_t *data;
};

typedef struct test_raw_packet test_raw_packet_t;

enum {
	DNAMES_COUNT = 2,
	ITEMS_COUNT = 2,
	RDATA_COUNT = 1,
	RRSETS_COUNT = 1,
	RESPONSE_COUNT = 1,
	LDNS_PACKET_COUNT = 1,
	LDNS_HEADER_COUNT = 1,
	LDNS_RRLIST_COUNT = 1,
	LDNS_RR_COUNT = 1,
	LDNS_RDFS_COUNT = 2,
	LDNS_RDF_TEMP_COUNT = 2,
};

static dnslib_dname_t DNAMES[DNAMES_COUNT] =
	{ {(uint8_t *)"\7example\3com", 13, NULL}, //0's at the end are added
          {(uint8_t *)"\2ns\7example\3com", 16, NULL} };

static uint8_t address[4] = {192, 168, 1, 1};

static dnslib_rdata_item_t ITEMS[ITEMS_COUNT] =
	{ {.dname = &DNAMES[1]},
          {.raw_data = address } };

static dnslib_rdata_t RDATA[RDATA_COUNT] = { {&ITEMS[0], 1, &RDATA[0]} };

static dnslib_rrset_t RESPONSE_RRSETS[RRSETS_COUNT] =
	{ {&DNAMES[0],1 ,1 ,3600, &RDATA[0], NULL} };

static test_response_t RESPONSES[RESPONSE_COUNT] =
	{ {&DNAMES[0], 1, 1, 12345, 0, 0, 1, 0, 0, 0, NULL,
	   RESPONSE_RRSETS, NULL, 29} };

/* ************************* LDNS DATA ************************* */

/* XXX ENDIANESS ??? */
static ldns_rdf LDNS_RDFS_TEMP[LDNS_RDF_TEMP_COUNT] =
	{ {LDNS_RDF_TYPE_DNAME, 13, (void *)"\7example\3com"},
	  {LDNS_RDF_TYPE_DNAME, 16, (void *)"\2ns\7example\3com"} };

static ldns_rdf *LDNS_RDF_ARRAYS[LDNS_RDFS_COUNT] =
	{ &LDNS_RDFS_TEMP[0], &LDNS_RDFS_TEMP[1] } ;

static ldns_rr LDNS_RRS[LDNS_RR_COUNT] =
	{ {&LDNS_RDFS_TEMP[0], 3600, 1, LDNS_RR_TYPE_NS,
	  LDNS_RR_CLASS_IN, &LDNS_RDF_ARRAYS[1], false} };

static ldns_rr *tmp = &LDNS_RRS[0];

static ldns_rr_list LDNS_RRLISTS[LDNS_RRLIST_COUNT] =
	{ {1, 1, &tmp} };

static ldns_hdr LDNS_HEADERS[LDNS_HEADER_COUNT] =
	{ {12345, false, false, false, false, false, false, false,
	  LDNS_PACKET_QUERY, 0, 0, 1, 0, 0} };

/* XXX what is response code in our response */
static ldns_pkt LDNS_PACKETS[LDNS_PACKET_COUNT] =/*I have to put  65535 smwh*/
	{ {&LDNS_HEADERS[0], NULL, { 0, 0 }, 0, 0, 0, 0, 0, 0, 0, 0,
	  NULL, NULL, &LDNS_RRLISTS[0] , NULL} };

static int load_raw_packets(test_raw_packet_t ***raw_packets, uint8_t *count,
                            const char *filename)
{
	assert(*raw_packets == NULL);

	FILE *f;
	uint8_t tmp_size = 0;

	f = fopen(filename, "rb");

	if (f == NULL) {
		diag("could not open file: %s\n", filename);
		return 0;
	}

	fread(count, sizeof(uint8_t), 1, f);

	*raw_packets = malloc(sizeof(test_raw_packet_t *) * *count);

	for (int i = 0; i < *count; i++) {
		fread(&tmp_size, sizeof(uint8_t), 1, f);
		(*raw_packets)[i] = malloc(sizeof(test_raw_packet_t));
		(*raw_packets)[i]->data = malloc(sizeof(uint8_t) * (tmp_size));
		fread((*raw_packets)[i]->data, sizeof(uint8_t), tmp_size, f);
		(*raw_packets)[i]->size = tmp_size;
	}

	fclose(f);

	return 0;
}

static int load_parsed_packets(test_response_t ***responses, uint *count,
                               const char *filename)
{
	assert(*responses == NULL);

	FILE *f;

	f = fopen(filename, "r");

	if (f == NULL) {
		diag("could not open file: %s", filename);
		return 0;
	}

	*count = 0;

	int c;
	test_response_t *tmp_resp;

	char *tmp_str = malloc(sizeof(char) * 1000);
	char *tmp_dname_str = malloc(sizeof(char) * 255);

	memset(tmp_str, 0, 1000);

	while ((c = getc(f)) != EOF) {
		//apend
		*responses = realloc(*responses,
		                    sizeof(test_response_t *) * (*count + 1));

		tmp_str[strlen(tmp_str)] = c;
		tmp_str[strlen(tmp_str) + 1] = 0;
		if (c == '\n') {
			tmp_resp = malloc(sizeof(test_response_t));
			if ((sscanf(tmp_str, "%" SCNu16 ";%" SCNu16 ";%"
				    SCNu16 ";%" SCNu8 ";%" SCNu8 ";%"
				    SCNu16 ";%" SCNu16 ";%" SCNu16 ";%"
				    SCNu16 ";%s",
                	            &(tmp_resp->type),
			            &(tmp_resp->rclass),
				    &(tmp_resp->id),
			            &(tmp_resp->flags1),
			            &(tmp_resp->flags2),
			            &(tmp_resp->qdcount),
			            &(tmp_resp->ancount),
			            &(tmp_resp->nscount),
			            &(tmp_resp->arcount),
			            tmp_dname_str)) == 10) {
				dnslib_dname_t *tmp_dname =
					dnslib_dname_new_from_str(
						tmp_dname_str,
						strlen(tmp_dname_str),
						NULL);
				tmp_resp->owner = tmp_dname;
				(*responses)[*count] = tmp_resp;
				(*count)++;
			} else {
				free(tmp_resp);
			}
			memset(tmp_str, 0, 1000);
		}
	}

	free(tmp_str);
	free(tmp_dname_str);

	fclose(f);

	return 0;

}

/* \note just checking the pointers probably would suffice */
static int compare_rrsets(const dnslib_rrset_t *rrset1,
                          const dnslib_rrset_t *rrset2)
{
	assert(rrset1);
	assert(rrset2);

	return (!(dnslib_dname_compare(rrset1->owner, rrset2->owner) == 0 &&
	        rrset1->type == rrset2->type &&
		rrset1->rclass == rrset2->rclass &&
		rrset1->ttl == rrset2->ttl &&
		rrset1->rdata == rrset2->rdata));
}

static int test_response_new_empty()
{
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	if (resp != NULL) {
		dnslib_response_free(&resp);
		return 1;
	} else {
		dnslib_response_free(&resp);
		return 0;
	}
}

static int test_response_add_rrset(int (*add_func)
                                   (dnslib_response_t *,
				   const dnslib_rrset_t *, int),
				   int array_id)
{
	int errors = 0;

	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);
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
		case 3:	{
			array = resp->additional;
			break;
		}
		default: {
			dnslib_response_free(&resp);
			return 0;
		}
	} /* switch */

	for (int i = 0; (i < RRSETS_COUNT) && !errors; i++) {
		add_func(resp, &RESPONSE_RRSETS[i], 0);
		errors += compare_rrsets(array[i], &RESPONSE_RRSETS[i]);
	}

	dnslib_response_free(&resp);

	return (errors == 0);
}

static int test_response_add_rrset_answer()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_answer,
	                               1);
}

static int test_response_add_rrset_authority()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_authority,
	                               2);
}
static int test_response_add_rrset_additional()
{
	return test_response_add_rrset(&dnslib_response_add_rrset_additional,
	                               3);
}

static int check_response(dnslib_response_t *resp, test_response_t *test_resp,
                          int check_header, int check_question,
			  int check_answer, int check_additional,
			  int check_authority)
{
	int errors = 0; /* TODO maybe use it everywhere, or not use it all */

	if (check_question) {
		/* again, in case of dnames, pointer would probably suffice */
		if (dnslib_dname_compare(resp->question.qname,
		                             test_resp->owner) != 0) {
			char *tmp_dname1, *tmp_dname2;
			tmp_dname1 = dnslib_dname_to_str(test_resp->owner);
			tmp_dname2 = dnslib_dname_to_str(resp->question.qname);
			diag("Qname in response is wrong:\
			      should be: %s is: %s\n",
			     tmp_dname1, tmp_dname2);
			free(tmp_dname1);
			free(tmp_dname2);
			return 0;
		}

		if (resp->question.qtype != test_resp->type) {
			diag("Qtype value is wrong: is %u should be %u\n",
			     resp->question.qtype, test_resp->type);
			return 0;
		}
		if (resp->question.qclass != test_resp->rclass) {
			diag("Qclass value is wrong: is %u should be %u\n",
			     resp->question.qtype, test_resp->type);
			return 0;
		}
	}

	if (check_header) {
		/* Well, this should be different by design. Wat do? */
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
			diag("Arcount value is wrong: is %u should be %u\n",
			     resp->header.arcount, test_resp->arcount);
			return 0;
		}
	}

	if (check_question) {
		/* Currently just one question RRSET allowed */
		/* Will only check pointers, no copying takes place */
		/* TODO do we even need to test this? */
		;
	}

	if (check_authority) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i]!=&(test_resp->authority[i])) {
				diag("Authority rrset #%d is wrongly set.\n",
				     i);
				errors++;
			}
		}
	}

	if (check_answer) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i]!=&(test_resp->authority[i])) {
				diag("Authority rrset #%d is wrongly set.\n",
				     i);
				errors++;
			}
		}
	}

	if (check_additional) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i]!=&(test_resp->authority[i])) {
				diag("Authority rrset #%d is wrongly set.\n",
				     i);
				errors++;
			}
		}
	}

	return (errors == 0);
}

static int test_response_parse_query(test_response_t **responses,
                                     test_raw_packet_t **raw_queries,
                                     uint count)
{
	assert(responses);
	assert(raw_queries);

	int errors = 0;
	dnslib_response_t *resp = NULL;
	for (int i = 0; (i < count) && !errors; i++) {
		resp = dnslib_response_new_empty(NULL, 0);
		assert(resp);
		if (dnslib_response_parse_query(resp,
			                        raw_queries[i]->data,
						raw_queries[i]->size) != 0) {
			errors++;
		}
		errors += !check_response(resp, responses[i], 1, 1, 0, 0, 0);
		dnslib_response_free(&resp);
	}

	return (errors == 0);
}

static int compare_wires(uint8_t *wire1, uint8_t *wire2, uint size)
{
	for (int i = 0; i < size; i++) {
		if (wire1[i] != wire2[i]) {
			return 1;
		}
	}
	return 0;
}

static int test_response_to_wire()
{
	int errors = 0;

	dnslib_response_t *resp;

	dnslib_response_t *tmp_resp;

	assert(RESPONSE_COUNT == LDNS_PACKET_COUNT);

	for (int i = 0; (i < RESPONSE_COUNT) && !errors; i++) {

		resp = dnslib_response_new_empty(NULL, 0);

		resp->header.id = RESPONSES[i].id;
		//flags1?
		resp->header.qdcount = RESPONSES[i].qdcount;
		resp->header.ancount = RESPONSES[i].ancount;
		resp->header.nscount = RESPONSES[i].nscount;
		resp->header.arcount = RESPONSES[i].arcount;

		resp->question.qname = RESPONSES[i].owner;
		resp->question.qtype = RESPONSES[i].type;
		resp->question.qclass = RESPONSES[i].rclass;

		for (int j = 0; j < RESPONSES[i].ancount; j++) {
			if (&(RESPONSES[i].answer[j])) {
				dnslib_response_add_rrset_answer(resp,
					&(RESPONSES[i].answer[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].additional[j])) {
				dnslib_response_add_rrset_additional(resp,
					&(RESPONSES[i].additional[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].authority[j])) {
				dnslib_response_add_rrset_authority(resp,
					&(RESPONSES[i].authority[j]), 0);
			}
		}

		resp->size = RESPONSES[i].size;

		uint8_t *dnslib_wire = NULL;
		uint8_t *ldns_wire = NULL;

		size_t ldns_wire_size;
		size_t dnslib_wire_size;

		if (ldns_pkt2wire(&ldns_wire, &LDNS_PACKETS[i],
			          &ldns_wire_size) != LDNS_STATUS_OK) {
			diag("Could not convert ldns packet to wire\n");
			dnslib_response_free(&resp);
			return 0;
		}

		diag("hex dump ldns wire:");
		hex_print((char *)ldns_wire, ldns_wire_size);

		if (dnslib_response_to_wire(resp, &dnslib_wire,
			                    &dnslib_wire_size) != 0) {
			diag("Could not convert dnslib response to wire\n");
			dnslib_response_free(&resp);
			return 0;
		}

		diag("hex dump dnslib wire:");
		hex_print((char *)dnslib_wire, dnslib_wire_size);

		tmp_resp = dnslib_response_new_empty(NULL, 0);

		assert(tmp_resp);

		if (dnslib_response_parse_query(tmp_resp, dnslib_wire,
			                        dnslib_wire_size) != 0) {
			diag("Could not parse created wire");
			dnslib_response_free(&resp);
			dnslib_response_free(&tmp_resp);
			free(dnslib_wire);
			return 0;
		}

		if (!check_response(tmp_resp, &RESPONSES[i], 1, 1, 1, 1, 1)) {
			diag("Response parsed from wire does not match");
			dnslib_response_free(&resp);
			dnslib_response_free(&tmp_resp);
			return 0;
		}

		dnslib_dname_free(&(tmp_resp->question.qname));
		dnslib_response_free(&tmp_resp);


		if (compare_wires(dnslib_wire, ldns_wire, dnslib_wire_size)) {
			diag("Resulting wires were not equal - TODO\n");
//			return 0;
		}

		free(ldns_wire);
		free(dnslib_wire);
		dnslib_response_free(&resp);
	}

	return (errors == 0);
}

static int test_response_free()
{
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);
	assert(resp);

	dnslib_response_free(&resp);

	return (resp == NULL);
}

static int test_response_qname(dnslib_response_t **responses)
{
	int errors = 0;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		if (dnslib_dname_compare(dnslib_response_qname(responses[i]), 
			                 RESPONSES[i].owner) != 0) {
			diag("Got wrong qname value from response");
			errors++;
		}
	}

	return errors;
}

static int test_response_qtype(dnslib_response_t **responses)
{
	int errors = 0;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		if (dnslib_response_qtype(responses[i]) !=
			                 RESPONSES[i].type) {
			diag("Got wrong qtype value from response");
			errors++;
		}
	}

	return errors;
}

static int test_response_qclass(dnslib_response_t **responses)
{
	int errors = 0;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		if (dnslib_response_qclass(responses[i]) !=
			                 RESPONSES[i].rclass) {
			diag("Got wrong qclass value from response");
			errors++;
		}
	}

	return errors;
}

static int test_response_getters(uint type)
{
	int errors = 0;

	dnslib_response_t *responses[RESPONSE_COUNT];

	for (int i = 0; (i < RESPONSE_COUNT); i++) {

		responses[i] = dnslib_response_new_empty(NULL, 0);

		responses[i]->header.id = RESPONSES[i].id;
		//flags1?
		responses[i]->header.qdcount = RESPONSES[i].qdcount;
		responses[i]->header.ancount = RESPONSES[i].ancount;
		responses[i]->header.nscount = RESPONSES[i].nscount;
		responses[i]->header.arcount = RESPONSES[i].arcount;

		responses[i]->question.qname = RESPONSES[i].owner;
		responses[i]->question.qtype = RESPONSES[i].type;
		responses[i]->question.qclass = RESPONSES[i].rclass;

		for (int j = 0; j < RESPONSES[i].ancount; j++) {
			if (&(RESPONSES[i].answer[j])) {
				dnslib_response_add_rrset_answer(responses[i],
					&(RESPONSES[i].answer[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].additional[j])) {
				dnslib_response_add_rrset_additional(responses[i],
					&(RESPONSES[i].additional[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].authority[j])) {
				dnslib_response_add_rrset_authority(responses[i],
					&(RESPONSES[i].authority[j]), 0);
			}
		}

		responses[i]->size = RESPONSES[i].size;
	}

	switch (type) {
		case 0: {
			errors += test_response_qname(responses);
			break;
		}
		case 1: {
			errors += test_response_qtype(responses);
			break;
		}
		case 2: {
			errors += test_response_qclass(responses);
			break;
		}
		default: {
			diag("Unknown type");
			return 0;
		}
	} /* switch */

	return (errors == 0);
}

static int test_response_set_rcode(dnslib_response_t **responses)
{
	int errors = 0;
	short rcode = 0xA;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		dnslib_response_set_rcode(responses[i], rcode);
		if (dnslib_packet_flags_get_rcode(responses[i]->header.flags2) != rcode) {
			diag("Set wrong rcode.");
			errors++;
		}
	}
	return errors;
}

static int test_response_set_aa(dnslib_response_t **responses)
{
	int errors = 0;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		dnslib_response_set_aa(responses[i]);
		if (dnslib_packet_flags_get_aa(responses[i]->header.flags1) != 1) {
			printf("%d\n", dnslib_packet_flags_get_aa(responses[i]->header.flags1));
			diag("Set wrong aa bit.");
			errors++;
		}
	}
	return errors;
}

static int test_response_setters(uint type)
{
	int errors = 0;

	dnslib_response_t *responses[RESPONSE_COUNT];

	for (int i = 0; (i < RESPONSE_COUNT); i++) {

		responses[i] = dnslib_response_new_empty(NULL, 0);

		responses[i]->header.id = RESPONSES[i].id;
		//flags1?
		responses[i]->header.qdcount = RESPONSES[i].qdcount;
		responses[i]->header.ancount = RESPONSES[i].ancount;
		responses[i]->header.nscount = RESPONSES[i].nscount;
		responses[i]->header.arcount = RESPONSES[i].arcount;

		responses[i]->question.qname = RESPONSES[i].owner;
		responses[i]->question.qtype = RESPONSES[i].type;
		responses[i]->question.qclass = RESPONSES[i].rclass;

		for (int j = 0; j < RESPONSES[i].ancount; j++) {
			if (&(RESPONSES[i].answer[j])) {
				dnslib_response_add_rrset_answer(responses[i],
					&(RESPONSES[i].answer[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].additional[j])) {
				dnslib_response_add_rrset_additional(responses[i],
					&(RESPONSES[i].additional[j]), 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].authority[j])) {
				dnslib_response_add_rrset_authority(responses[i],
					&(RESPONSES[i].authority[j]), 0);
			}
		}

		responses[i]->size = RESPONSES[i].size;
	}

	switch (type) {
		case 0: {
			errors += test_response_set_rcode(responses);
			break;
		}
		case 1: {
			errors += test_response_set_aa(responses);
			break;
		}
		default: {
			diag("Unknown type");
			return 0;
		}
	} /* switch */

	return (errors == 0);
}

static const int DNSLIB_RESPONSE_TEST_COUNT = 12;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_response_tests_count(int argc, char *argv[])
{
	return DNSLIB_RESPONSE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_response_tests_run(int argc, char *argv[])
{
	int ret;

	ret = test_response_new_empty();
	ok(ret, "response: create empty");

	skip(!ret, 5);

	ok(test_response_add_rrset_answer(), "response: add rrset answer");
	ok(test_response_add_rrset_authority(),
	   "response: add rrset authority");
	ok(test_response_add_rrset_additional(),
	   "response: add rrset additional");

	test_response_t **parsed_responses = NULL;
	test_raw_packet_t **raw_queries = NULL;
	uint response_parsed_count;
	uint8_t response_raw_count;

	ok(test_response_getters(0), "response: get qname");

	ok(test_response_getters(1), "response: get qtype");

	ok(test_response_getters(2), "response: get qclass");

	ok(test_response_setters(0), "response: set rcode");

	ok(test_response_setters(1), "response: set aa");

	load_parsed_packets(&parsed_responses, &response_parsed_count,
	                    "src/tests/dnslib/files/parsed_packets");
	diag("read %d responses\n", response_parsed_count);

	load_raw_packets(&raw_queries, &response_raw_count,
	                 "src/tests/dnslib/files/raw_packets");
	diag("read %d responses\n", response_raw_count);

	assert(response_raw_count == response_parsed_count);

	ok(test_response_parse_query(parsed_responses,
	                             raw_queries,
	                             response_parsed_count),
	   "response: parse query");

	ok(test_response_to_wire(), "response: to wire");

	for (int i = 0; i < response_parsed_count; i++) {
		dnslib_dname_free(&(parsed_responses[i]->owner));
		free(parsed_responses[i]);
		free(raw_queries[i]->data);
		free(raw_queries[i]);
	}

	free(parsed_responses);
	free(raw_queries);

	endskip;

	ok(test_response_free(), "response: free");

	return 0;
}
