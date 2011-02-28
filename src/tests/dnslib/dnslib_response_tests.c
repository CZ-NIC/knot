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

/*
 * Resources
 * \note .rc files are generated on compile-time.
 */
#include "parsed_data_queries.rc"
#include "parsed_data.rc"
#include "raw_data_queries.rc"
#include "raw_data.rc"

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
 * Helper functions.
 */

/* Virtual I/O over memory. */
static int mem_read(void *dst, size_t n, const char **src, unsigned *remaining) {
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

struct test_response {
	dnslib_dname_t *qname;
	uint16_t qclass;
	uint16_t qtype;
	uint16_t id;
	uint8_t flags1;
	uint8_t flags2;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

/* XXX	dnslib_rrset_t *question; */
	dnslib_rrset_t **answer;
	dnslib_rrset_t **authority;
	dnslib_rrset_t **additional;

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

enum { DNAME_MAX_WIRE_LENGTH = 256 };

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

//static uint8_t address[4] = {192, 168, 1, 1};

static dnslib_rdata_item_t ITEMS[ITEMS_COUNT] =
	{ {.dname = &DNAMES[1]},
	  {.raw_data = (uint16_t *)address } };

static dnslib_rdata_t RDATA[RDATA_COUNT] = { {&ITEMS[0], 1, &RDATA[0]} };

static dnslib_rrset_t RESPONSE_RRSETS[RRSETS_COUNT] =
	{ {&DNAMES[0], 1, 1, 3600, &RDATA[0], NULL} };

static test_response_t RESPONSES[RESPONSE_COUNT] =
	{ {&DNAMES[0], 1, 1, 12345, 0, 0, 1, 0, 0, 0, NULL,
	   (dnslib_rrset_t **)&RESPONSE_RRSETS, NULL, 29} };


static int load_raw_packets(test_raw_packet_t ***raw_packets, uint32_t *count,
			    const char *src, unsigned src_size)
{
	assert(*raw_packets == NULL);
	uint16_t tmp_size = 0;

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

static dnslib_rdata_t *load_response_rdata(uint16_t type, const char **src, unsigned *src_size)
{
	dnslib_rdata_t *rdata;

	rdata = dnslib_rdata_new();

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dnslib_rdata_item_t *items =
		malloc(sizeof(dnslib_rdata_item_t) * desc->length);

	uint8_t raw_data_length; /* TODO should be bigger */

/*	if (type != DNSLIB_RRTYPE_NS) {
		if (!fread_safe(&raw_data_length,
		     sizeof(raw_data_length), 1, f)) {
			return NULL;
		}
	} */

	for (int i = 0; i < desc->length; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{

			/* TODO maybe this does not need to be stored this big*/

			/* TODO freeing upon failed fread*/

			uint8_t dname_size;
			uint8_t *dname_wire = NULL;

			if (!mem_read(&dname_size,
				      sizeof(dname_size), src, src_size)) {
				return NULL;
			}

			assert(dname_size < DNAME_MAX_WIRE_LENGTH);

			dname_wire = malloc(sizeof(uint8_t) * dname_size);

			if (!mem_read(dname_wire, sizeof(uint8_t) * dname_size,
				      src, src_size)) {
				return NULL;
			}

			items[i].dname =
				dnslib_dname_new_from_wire(dname_wire,
							   dname_size,
							   NULL);

			free(dname_wire);

			assert(items[i].dname);

		} else {
			if (desc->wireformat[i] ==
			    DNSLIB_RDATA_WF_BINARYWITHLENGTH) {
				if (!mem_read(&raw_data_length,
				     sizeof(raw_data_length), src, src_size)) {
					return NULL;
				}

				items[i].raw_data =
					malloc(sizeof(uint8_t) *
					       raw_data_length + 1);
				*(items[i].raw_data) = raw_data_length;
				if (!mem_read(items[i].raw_data + 1,
					      sizeof(uint8_t) * raw_data_length,
					      src, src_size)) {
					return NULL;
				}
/*				printf("read len (from wire): %d\n",
				       items[i].raw_data[0]);
				hex_print((char *)items[i].raw_data + 1,
					  items[i].raw_data[0]);
				*/


			} else {
				uint8_t size_fr_desc =
					dnslib_wireformat_size(desc->
							       wireformat[i]);

				if (size_fr_desc == 0) { /* unknown length */
					size_fr_desc = 1;
				}

				items[i].raw_data =
					malloc(sizeof(uint8_t) *
					       size_fr_desc + 1);

				items[i].raw_data[0] = size_fr_desc;


				if (!mem_read(items[i].raw_data + 1,
					      size_fr_desc,
					      src, src_size)) {
					return NULL;
				}

/*				printf("read len (from descriptor): %d\n",
				       items[i].raw_data[0]);
				hex_print((char *)items[i].raw_data + 1,
					  items[i].raw_data[0]);
				*/
			}
		}
	}

	if (dnslib_rdata_set_items(rdata, items, desc->length) != 0) {
		fprintf(stderr, "Error: could not set items\n");
	}

	free(items);

	return rdata;
}

/*dnslib_rrsig_set_t *dnslib_load_rrsig(FILE *f)
{
	dnslib_rrsig_set_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;

	if (!fread_safe(&rrset_type, sizeof(rrset_type), 1, f)) {
		return NULL;
	}
	debug_zp("rrset type: %d\n", rrset_type);
	if (!fread_safe(&rrset_class, sizeof(rrset_class), 1, f)) {
		return NULL;
	}
	debug_zp("rrset class %d\n", rrset_class);
	if (!fread_safe(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return NULL;
	}
	debug_zp("rrset ttl %d\n", rrset_ttl);

	if (!fread_safe(&rdata_count, sizeof(rdata_count), 1, f)) {
		return NULL;
	}

	rrsig = dnslib_rrsig_set_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	debug_zp("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(DNSLIB_RRTYPE_RRSIG, f);
		dnslib_rrsig_set_add_rdata(rrsig, tmp_rdata);
	}

	return rrsig;
} */

static dnslib_rrset_t *load_response_rrset(const char **src, unsigned *src_size,
					   char is_question)
{
	dnslib_rrset_t *rrset;
	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	/* Each rrset will only have one rdata entry */
	/* RRSIGs will be read as separate RRSets for now */
	/* TODO probably change it in python dump so that it complies with our
	 * implementation
	 */

/*	uint8_t rdata_count;
	uint8_t rrsig_count; */

	uint8_t dname_size;
	uint8_t *dname_wire = NULL;

	if (!mem_read(&dname_size, sizeof(dname_size), src, src_size)) {
		return NULL;
	}

	assert(dname_size < DNAME_MAX_WIRE_LENGTH);

	dname_wire = malloc(sizeof(uint8_t) * dname_size);

	if (!mem_read(dname_wire, sizeof(uint8_t) * dname_size, src, src_size)) {
		return NULL;
	}

	dnslib_dname_t *owner =
		dnslib_dname_new_from_wire(dname_wire,
					   dname_size,
					   NULL);

	free(dname_wire);

	if (!mem_read(&rrset_type, sizeof(rrset_type), src, src_size)) {
		return NULL;
	}
	if (!mem_read(&rrset_class, sizeof(rrset_class), src, src_size)) {
		return NULL;
	}

	if (!is_question) {
		if (!mem_read(&rrset_ttl, sizeof(rrset_ttl), src, src_size)) {
			return NULL;
		}
	}

	rrset = dnslib_rrset_new(owner, rrset_type, rrset_class, rrset_ttl);

	if (is_question) {
		return rrset;
	}

	dnslib_rdata_t *tmp_rdata;

	tmp_rdata = load_response_rdata(rrset->type, src, src_size);
	dnslib_rrset_add_rdata(rrset, tmp_rdata);

	return rrset;
}

static test_response_t *load_parsed_response(const char **src, unsigned *src_size)
{
	test_response_t *resp = malloc(sizeof(test_response_t));

	if (!mem_read(&resp->id, sizeof(resp->id), src, src_size)) {
		return NULL;
	}

//	printf("id %d\n", resp->id);

	if (!mem_read(&resp->qdcount, sizeof(resp->qdcount), src, src_size)) {
		return NULL;
	}

//	printf("qdcount: %d\n", resp->qdcount);

	if (!mem_read(&resp->ancount, sizeof(resp->ancount), src, src_size)) {
		return NULL;
	}

//	printf("ancount: %d\n", resp->ancount);

	if (!mem_read(&resp->nscount, sizeof(resp->nscount), src, src_size)) {
		return NULL;
	}

//	printf("nscount: %d\n", resp->nscount);

	if (!mem_read(&resp->arcount, sizeof(resp->arcount), src, src_size)) {
		return NULL;
	}

//	printf("arcount: %d\n", resp->arcount);

	dnslib_rrset_t **question_rrsets;

	question_rrsets = malloc(sizeof(dnslib_rrset_t *) * resp->qdcount);

	for (int i = 0; i < resp->qdcount; i++) {
		question_rrsets[i] = load_response_rrset(src, src_size, 1);
		if (question_rrsets[i] == NULL) {
			diag("Could not load question rrsets");
			return NULL;
		}
	}

	/* only one question in our case */

	resp->qname = question_rrsets[0]->owner;
	resp->qtype = question_rrsets[0]->type;
	resp->qclass = question_rrsets[0]->rclass;

	for (int i = 0; i < resp->qdcount; i++) {
		dnslib_rrset_free(&(question_rrsets[i]));
	}

	free(question_rrsets);

	if (resp->ancount > 0) {
		resp->answer =
			malloc(sizeof(dnslib_rrset_t *) * resp->ancount);
	} else {
		resp->answer = NULL;
	}

	for (int i = 0; i < resp->ancount; i++) {
		resp->answer[i] = load_response_rrset(src, src_size, 0);
		if (resp->answer[i] == NULL) {
			diag("Could not load answer rrsets");
			return NULL;
		}
	}

	if (resp->nscount > 0) {
		resp->authority =
			malloc(sizeof(dnslib_rrset_t *) * resp->nscount);
	} else {
		resp->authority = NULL;
	}

	for (int i = 0; i < resp->nscount; i++) {
		resp->authority[i] = load_response_rrset(src, src_size, 0);
		if (resp->authority[i] == NULL) {
			diag("Could not load authority rrsets");
			return NULL;
		}
	}

	if (resp->arcount > 0) {
		resp->additional =
			malloc(sizeof(dnslib_rrset_t *) * resp->arcount);
	} else {
		resp->additional = NULL;
	}

	for (int i = 0; i < resp->arcount; i++) {
		resp->additional[i] = load_response_rrset(src, src_size, 0);
		if (resp->additional[i] == NULL) {
			diag("Could not load additional rrsets");
			return NULL;
		}
	}

	/* this will never be used */

	resp->flags1 = 0;
	resp->flags2 = 0;

	return resp;
}

static int load_parsed_responses(test_response_t ***responses, uint32_t *count,
				 const char* src, unsigned src_size)
{
	assert(*responses == NULL);

	if (!mem_read(count, sizeof(*count), &src, &src_size)) {
		diag("Wrong read");
		return -1;
	}

	*responses = malloc(sizeof(test_response_t *) * *count);

	for (int i = 0; i < *count; i++) {
		(*responses)[i] = load_parsed_response(&src, &src_size);
		if ((*responses)[i] == NULL) {
			diag("Could not load response - returned NULL");
			return -1;
		}
	}

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
	dnslib_response_t *resp = dnslib_response_new_empty(NULL);

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
				   const dnslib_rrset_t *, int, int),
				   int array_id)
{
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
		add_func(resp, &RESPONSE_RRSETS[i], 0, 0);
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
	int errors = 0; /* TODO maybe use it everywhere, or not use it at all */

	if (check_question) {
		/* again, in case of dnames, pointer would probably suffice */
		if (dnslib_dname_compare(resp->question.qname,
					     test_resp->qname) != 0) {
			char *tmp_dname1, *tmp_dname2;
			tmp_dname1 = dnslib_dname_to_str(test_resp->qname);
			tmp_dname2 = dnslib_dname_to_str(resp->question.qname);
			diag("Qname in response is wrong:\
			      should be: %s is: %s\n",
			     tmp_dname1, tmp_dname2);
			free(tmp_dname1);
			free(tmp_dname2);
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
		/* Well, this should be different by design.*/
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
			diag("Arcount value is wrong: is %u should be %u\n",
			     resp->header.arcount, test_resp->arcount);
			return 0;
		}
	}

	if (check_question) {
		/* Currently just one question RRSET allowed */
		if (dnslib_dname_compare(resp->question.qname,
					test_resp->qname) != 0) {
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

	if (check_authority) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i] != (test_resp->authority[i])) {
				diag("Authority rrset #%d is wrongly set.\n",
				     i);
				errors++;
			}
		}
	}

	if (check_answer) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i] != (test_resp->authority[i])) {
				diag("Authority rrset #%d is wrongly set.\n",
				     i);
				errors++;
			}
		}
	}

	if (check_additional) {
		for (int i = 0; (i < resp->header.arcount) && !errors; i++) {
			if (resp->authority[i] != (test_resp->authority[i])) {
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
		resp = dnslib_response_new_empty(NULL);
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
	uint ret = 0;
	for (int i = 0; i < size; i++) {
		if (wire1[i] != wire2[i]) {
			if (i != 2 && i != 11) {
			ret+=1;
			diag("Bytes on position %d differ", i);
			diag("pcap:");
			hex_printf((char *)&wire2[i], 1, &diag);
			diag("response");
			hex_printf((char *)&wire1[i], 1, &diag);
		} else {
			diag("Wires differ at tolerated "
			     "positions (AA bit, Additional section)");
		}
		}
	}

	return ret;
}

static int test_response_to_wire(test_response_t **responses,
				 test_raw_packet_t **raw_data,
				 uint count)
{
	int errors = 0;

	assert(responses);

	dnslib_response_t *resp;

	assert(RESPONSE_COUNT == LDNS_PACKET_COUNT);

	for (int i = 0; i < count; i++) {

		assert(responses[i]);

		resp = dnslib_response_new_empty(NULL);

		resp->header.id = responses[i]->id;
		//flags1?
		resp->header.qdcount = responses[i]->qdcount;

		assert(responses[i]->qname);

		resp->question.qname = responses[i]->qname;
		resp->size += responses[i]->qname->size;
		resp->question.qtype = responses[i]->qtype;
		resp->question.qclass = responses[i]->qclass;

		resp->size += 4;

		for (int j = 0; j < responses[i]->ancount; j++) {
			if (&(responses[i]->answer[j])) {
				dnslib_response_add_rrset_answer(resp,
					responses[i]->answer[j], 0, 0);
			}
		}
		for (int j = 0; j < responses[i]->arcount; j++) {
			if (&(responses[i]->additional[j])) {
				dnslib_response_add_rrset_additional(resp,
					responses[i]->additional[j], 0, 0);
			}
		}
		for (int j = 0; j < responses[i]->nscount; j++) {
			if (&(responses[i]->authority[j])) {
				dnslib_response_add_rrset_authority(resp,
					responses[i]->authority[j], 0, 0);
			}
		}

		uint8_t *dnslib_wire = NULL;

		size_t dnslib_wire_size;

		assert(resp->question.qname);

		if (dnslib_response_to_wire(resp, &dnslib_wire,
					    &dnslib_wire_size) != 0) {
			diag("Could not convert dnslib response to wire\n");
			dnslib_response_free(&resp);
			return 0;
		}

/*		tmp_resp = dnslib_response_new_empty(NULL);

		assert(tmp_resp);

		if (dnslib_response_parse_query(tmp_resp, dnslib_wire,
						dnslib_wire_size) != 0) {
			diag("Could not parse created wire");
			dnslib_response_free(&resp);
			dnslib_response_free(&tmp_resp);
			free(dnslib_wire);
			return 0;
		}

		if (!check_response(tmp_resp, responses[i], 1, 1, 1, 1, 1)) {
			diag("Response parsed from wire does not match");
			dnslib_response_free(&resp);
			dnslib_response_free(&tmp_resp);
			return 0;
		}

		dnslib_dname_free(&(tmp_resp->question.qname));
		dnslib_response_free(&tmp_resp);

		*/

		assert(dnslib_wire_size == raw_data[i]->size);

		uint tmp_places = compare_wires(dnslib_wire, raw_data[i]->data,
						dnslib_wire_size);

		if (tmp_places) {
			diag("Wires did not match - differ in %d places",
			     tmp_places);
			errors++;
		}

		free(dnslib_wire);
		dnslib_response_free(&resp);
	}

	return (errors == 0);
}

static int test_response_free()
{
	dnslib_response_t *resp = dnslib_response_new_empty(NULL);
	assert(resp);

	dnslib_response_free(&resp);

	return (resp == NULL);
}

static int test_response_qname(dnslib_response_t **responses)
{
	int errors = 0;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		if (dnslib_dname_compare(dnslib_response_qname(responses[i]),
					 RESPONSES[i].qname) != 0) {
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
					 RESPONSES[i].qtype) {
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
					 RESPONSES[i].qclass) {
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

		responses[i] = dnslib_response_new_empty(NULL);

		responses[i]->header.id = RESPONSES[i].id;
		//flags1?
		responses[i]->header.qdcount = RESPONSES[i].qdcount;
		responses[i]->header.ancount = RESPONSES[i].ancount;
		responses[i]->header.nscount = RESPONSES[i].nscount;
		responses[i]->header.arcount = RESPONSES[i].arcount;

		responses[i]->question.qname = RESPONSES[i].qname;
		responses[i]->question.qtype = RESPONSES[i].qtype;
		responses[i]->question.qclass = RESPONSES[i].qclass;

		dnslib_response_t *tmp_resp = responses[i];

		for (int j = 0; j < RESPONSES[i].ancount; j++) {
			if (&(RESPONSES[i].answer[j])) {
				dnslib_response_add_rrset_answer(tmp_resp,
					RESPONSES[i].answer[j], 0, 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].additional[j])) {
				dnslib_response_add_rrset_additional(tmp_resp,
					RESPONSES[i].additional[j], 0, 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].authority[j])) {
				dnslib_response_add_rrset_authority(tmp_resp,
					 RESPONSES[i].authority[j], 0, 0);
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

	for (int i = 0; (i < RESPONSE_COUNT); i++) {
		dnslib_response_free(&responses[i]);
	}

	return (errors == 0);
}

static int test_response_set_rcode(dnslib_response_t **responses)
{
	int errors = 0;
	short rcode = 0xA;
	for (int i = 0; i < RESPONSE_COUNT; i++) {
		dnslib_response_set_rcode(responses[i], rcode);
		if (dnslib_packet_flags_get_rcode(responses[i]->
						  header.flags2) != rcode) {
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
		/* TODO this returns 4 - shouldn't it return 1?
		It would work, yes, but some checks might be neccessary */
		if (!dnslib_packet_flags_get_aa(responses[i]->header.flags1)) {
			diag("%d",
			     dnslib_packet_flags_get_aa(responses[i]->
							header.flags1));
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

		responses[i] = dnslib_response_new_empty(NULL);

		responses[i]->header.id = RESPONSES[i].id;
		//flags1?
		responses[i]->header.qdcount = RESPONSES[i].qdcount;
		responses[i]->header.ancount = RESPONSES[i].ancount;
		responses[i]->header.nscount = RESPONSES[i].nscount;
		responses[i]->header.arcount = RESPONSES[i].arcount;

		responses[i]->question.qname = RESPONSES[i].qname;
		responses[i]->question.qtype = RESPONSES[i].qtype;
		responses[i]->question.qclass = RESPONSES[i].qclass;

		dnslib_response_t *tmp_resp = responses[i];

		for (int j = 0; j < RESPONSES[i].ancount; j++) {
			if (&(RESPONSES[i].answer[j])) {
				dnslib_response_add_rrset_answer(tmp_resp,
					(RESPONSES[i].answer[j]), 0, 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].additional[j])) {
				dnslib_response_add_rrset_additional(tmp_resp,
					(RESPONSES[i].additional[j]), 0, 0);
			}
		}
		for (int j = 0; j < RESPONSES[i].arcount; j++) {
			if (&(RESPONSES[i].authority[j])) {
				dnslib_response_add_rrset_authority(tmp_resp,
					(RESPONSES[i].authority[j]), 0, 0);
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

	for (int i = 0; (i < RESPONSE_COUNT); i++) {
		dnslib_response_free(&responses[i]);
	}

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

	skip(!ret, 10);

	ok(test_response_add_rrset_answer(), "response: add rrset answer");
	ok(test_response_add_rrset_authority(),
	   "response: add rrset authority");
	ok(test_response_add_rrset_additional(),
	   "response: add rrset additional");

	test_response_t **parsed_responses = NULL;
	test_response_t **parsed_queries = NULL;
	test_raw_packet_t **raw_responses = NULL;
	test_raw_packet_t **raw_queries = NULL;
	uint32_t response_parsed_count = 0;
	uint32_t query_parsed_count = 0;
	uint32_t response_raw_count = 0;
	uint32_t query_raw_count = 0;

	ok(test_response_getters(0), "response: get qname");

	ok(test_response_getters(1), "response: get qtype");

	ok(test_response_getters(2), "response: get qclass");

	ok(test_response_setters(0), "response: set rcode");

	ok(test_response_setters(1), "response: set aa");

	if (load_parsed_responses(&parsed_responses, &response_parsed_count,
			    parsed_data_rc, parsed_data_rc_size) != 0) {
		diag("Could not load parsed responses, skipping");
		return 0;
	}

	diag("read %d parsed responses\n", response_parsed_count);

	if (load_raw_packets(&raw_responses, &response_raw_count,
			 raw_data_rc, raw_data_rc_size) != 0) {
		diag("Could not load raw responses, skipping");
		return 0;
	}

	diag("read %d raw responses\n", response_raw_count);

	assert(response_raw_count == response_parsed_count);

	if (load_parsed_responses(&parsed_queries, &query_parsed_count,
				  parsed_data_queries_rc,
				  parsed_data_queries_rc_size) != 0) {
		diag("Could not load parsed queries, skipping");
		return 0;
	}

	diag("read %d parsed queries\n", query_parsed_count);

	if (load_raw_packets(&raw_queries, &query_raw_count,
			     raw_data_queries_rc,
			     raw_data_queries_rc_size) != 0) {
		diag("Could not load raw queries, skipping");
		return 0;
	}

	diag("read %d parsed queries\n", query_raw_count);

	assert(query_raw_count == query_parsed_count);

	ok(test_response_parse_query(parsed_queries,
				     raw_queries,
				     query_parsed_count),
	   "response: parse query");

	ok(test_response_to_wire(parsed_responses, raw_responses,
				 response_parsed_count), "response: to wire");

	for (int i = 0; i < response_parsed_count; i++) {
		dnslib_dname_free(&(parsed_responses[i]->qname));
		for (int j = 0; j < parsed_responses[i]->arcount; j++) {
			dnslib_rrset_deep_free(&(parsed_responses[i]->
					       additional[j]), 1, 1);
		}

		free(parsed_responses[i]->additional);

		for (int j = 0; j < parsed_responses[i]->ancount; j++) {
			dnslib_rrset_deep_free(&(parsed_responses[i]->
					       answer[j]), 1, 1);
		}

		free(parsed_responses[i]->answer);

		for (int j = 0; j < parsed_responses[i]->nscount; j++) {
			dnslib_rrset_deep_free(&(parsed_responses[i]->
					       authority[j]), 1, 1);
		}

		free(parsed_responses[i]->authority);

		free(parsed_responses[i]);
		free(raw_responses[i]->data);
		free(raw_responses[i]);
	}

	free(parsed_responses);
	free(raw_responses);

	for (int i = 0; i < query_parsed_count; i++) {
		dnslib_dname_free(&(parsed_queries[i]->qname));
		free(parsed_queries[i]);
		free(raw_queries[i]->data);
		free(raw_queries[i]);
	}

	free(parsed_queries);
	free(raw_queries);

	endskip;

	ok(test_response_free(), "response: free");

	return 0;
}
