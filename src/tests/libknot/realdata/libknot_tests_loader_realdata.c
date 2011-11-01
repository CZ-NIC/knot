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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "common/libtap/tap.h"
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "libknot/util/descriptor.h"

#include "tests/libknot/realdata/parsed_data.rc"
#include "tests/libknot/realdata/raw_data.rc"
TREE_DEFINE(test_node, avl);

/* Virtual I/O over memory. */
static int mem_read(void *dst, size_t n, const char **src,
		    unsigned *remaining)
{
//	printf("reading %u\n", n);
	if (n > *remaining) {
		return 0;
	}


	memcpy(dst, *src, n);
	*src += n;
	*remaining -= n;
//	printf("remaining %u\n", *remaining);
	return 1;
}

static int load_raw_packets(test_data_t *data, uint32_t *count,
			    const char *src, unsigned src_size)
{

	uint16_t tmp_size = 0;

	/* Packets are stored like this: [size][packet_data]+ */

	if(!mem_read(count, sizeof(uint32_t), &src, &src_size)) {
		return -1;
	}

	for (int i = 0; i < *count; i++) {
		uint16_t query = 0;
		if (!mem_read(&query, sizeof(query), &src, &src_size)) {
			return -1;
		}

		if(!mem_read(&tmp_size, sizeof(uint16_t), &src, &src_size)) {
			return -1;
		}

		test_raw_packet_t *packet = malloc(sizeof(test_raw_packet_t));


		packet->size = tmp_size;
		packet->data = malloc(sizeof(uint8_t) * (tmp_size));
		if(!mem_read(packet->data,
			     sizeof(uint8_t) * tmp_size, &src, &src_size)) {
			return -1;
		}

		if (query) {
			add_tail(&data->raw_query_list, (void *)packet);
		} else {
			add_tail(&data->raw_response_list, (void *)packet);
		}

		test_raw_packet_t *new_packet =
			malloc(sizeof(test_raw_packet_t));
		assert(new_packet);
		new_packet->data = packet->data;
		new_packet->size = packet->size;

		add_tail(&data->raw_packet_list, (void *)new_packet);
	}

	return 0;
}

/* Returns size of type where avalailable */
size_t wireformat_size_load(uint wire_type)
{
	switch(wire_type) {
		case KNOT_RDATA_WF_BYTE:
			return 1;
			break;
		case KNOT_RDATA_WF_SHORT:
			return 2;
			break;
		case KNOT_RDATA_WF_LONG:
			return 4;
			break;
		case KNOT_RDATA_WF_A:
			return 4;
			break;
		case KNOT_RDATA_WF_AAAA:
			return 16;
			break;
		default: /* unknown size */
			return 0;
			break;
	} /* switch */
}

static int add_label(uint8_t **labels, const uint8_t label,
                     uint *label_count)
{
	void *ret = realloc(*labels, sizeof(uint8_t) * (*label_count + 1));
	if (ret == NULL) {
		return -1;
	}

	*labels = ret;
	(*labels)[(*label_count)++] = label;

	return 0;
}
/* Dnames are stored label by label in the dump */
/* TODO STRING AS WELL */
static test_dname_t *load_test_dname(const char **src,
				     unsigned *src_size)
{
	test_dname_t *ret = malloc(sizeof(test_dname_t));
	CHECK_ALLOC_LOG(ret, NULL);

	ret->size = 0;
	ret->str = NULL;
	ret->labels = NULL;
	ret->wire = NULL;
	ret->label_count = 0;
	ret->next = NULL;
	ret->prev = NULL;

	uint8_t label_size = 0;
	uint8_t *label_wire = NULL;
	uint8_t *labels = NULL;
	char *dname_str = NULL;
	uint label_count = 0;
	uint dname_length = 0;
	do {
		/* Read label size */
		if (!mem_read(&label_size,
			      sizeof(uint8_t),
			      src,
			      src_size)) {
			fprintf(stderr, "Faulty read\n");
			return NULL;
		}

//		diag("%d", label_size);

		add_label(&labels, ret->size, &label_count);

		dname_length += label_size + 1;

		label_wire = malloc(sizeof(uint8_t) * (label_size + 2));

		if (label_wire == NULL) {
			ERR_ALLOC_FAILED;
			free(ret);
			return NULL;
		}

		label_wire[0] = label_size;

		/* Read label wire */
		if (!mem_read(label_wire + 1,
			      sizeof(uint8_t) *
			      label_size,
			      src,
			      src_size)) {
			free(label_wire);
			fprintf(stderr, "Faulty read\n");
			return NULL;
		}

		label_wire[label_size + 1] = '\0';

		dname_str = malloc(sizeof(char) * (label_size + 2));

		if (label_size != 0) {
			/* n - 1 : . */
			dname_str[label_size] = '.';
			dname_str[label_size + 1] = '\0';

			memcpy(dname_str, label_wire + 1, label_size);
		}

		if (ret->size == 0) {
			ret->wire = malloc(sizeof(uint8_t) * (label_size + 2));
			if (ret->wire == NULL) {
				ERR_ALLOC_FAILED;
				free(ret);
				return NULL;
			}

			memcpy(ret->wire, label_wire, label_size + 2);

			if (label_size != 0) {

				ret->str =
					malloc(sizeof(char) * (label_size + 2));
				if (ret->str == NULL) {
					ERR_ALLOC_FAILED;
					free(ret->wire);
					free(ret);
					return NULL;
				}

				memcpy(ret->str, dname_str, label_size + 2);
			}

			ret->size = label_size + 2;
		} else {
			/* Concatenate */
			void *p = realloc(ret->wire,
			                  ret->size + (label_size + 2));
			if (p == NULL) {
				ERR_ALLOC_FAILED;
				free(ret->wire);
				free(ret->labels);
				free(ret);
				return NULL;
			}
			ret->wire = p;

			/* TODO Safe concat? But I set the values myself, right? */
			/* or maybe memcpy... */
			strcat((char *)ret->wire, (char *)label_wire);
			assert(ret->wire);


			if (label_size != 0) {

				p = realloc(ret->str,
				            ret->size + (label_size + 2));
				if (p == NULL) {
					ERR_ALLOC_FAILED;
					free(ret->wire);
					free(ret->str);
					free(ret->labels);
					free(ret);
					return NULL;
				}
				ret->str = p;

				strcat(ret->str, dname_str);
				assert(ret->str);
			}

			ret->size += label_size + 2;
		}

		free(label_wire);
		free(dname_str);

	} while (label_size != 0);

	/*!< \warning even wireformat is ended with 0 every time !!! */

	/* Root domain */
//	if (ret->size == 0) {
//		assert(ret->wire == NULL);

//		ret->wire = malloc(sizeof(uint8_t) * 1);
//		if (ret->wire == NULL) {
//			ERR_ALLOC_FAILED;
//			free(ret);
//			return NULL;
//		}

//		ret->wire[0] = '\0';

//		ret->labels = malloc(sizeof(uint8_t) * 1);
//		if (ret->labels == NULL) {
//			ERR_ALLOC_FAILED;
//			free(ret->wire);
//			free(ret);
//			return NULL;
//		}

//		ret->labels[0] = '\0';
//		ret->label_count = 1;
//	}

//	printf("OK: %s (%d)\n",ret->str, ret->size);

	ret->labels = labels;
	ret->size = ret->size - (label_count);
	ret->label_count = --label_count;
	ret->next = NULL;
	ret->prev = NULL;

	assert(ret != NULL);

	return ret;
}

/*!
 * \brief Reads dname label by label
 */
static test_rdata_t *load_response_rdata(uint16_t type,
					 const char **src,
					 unsigned *src_size)
{

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "reading rdata for type: %s\n",
	        knot_rrtype_to_string(type));
#endif
	/*
	 * Binary format of rdata is as following:
	 * [total_length(except for some types) - see below][rdata_item]+
	 * Dname items are read label by label
	 */

	test_rdata_t *rdata = malloc(sizeof(test_rdata_t));

	CHECK_ALLOC_LOG(rdata, NULL);

	rdata->count = 0;
	rdata->items = NULL;
	rdata->type = 0;

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	rdata->type = type;

	test_item_t *items =
		malloc(sizeof(test_item_t) * desc->length);

	if (items == NULL) {
		ERR_ALLOC_FAILED;
		free(rdata);
		return NULL;
	}

	/* TODO consider realloc */

	uint16_t total_raw_data_length = 0;
	uint8_t raw_data_length;

	/*
	 * These types have no length, unfortunatelly (python library
	 * does not provide this)
	 */
	/* TODO the are more types with no length for sure ... */

	if (type != KNOT_RRTYPE_A &&
	    type != KNOT_RRTYPE_NS &&
	    type != KNOT_RRTYPE_AAAA) {
		if (!mem_read(&total_raw_data_length,
		     sizeof(total_raw_data_length), src, src_size)) {
			free(rdata);
			free(items);
			fprintf(stderr, "Faulty read\n");
			return NULL;
		}
	}

	size_t total_read = 0;

	int i;

	/*
	 * TODO save number of items
	 * in the dump - of minor importance, however
	 */
	for (i = 0; i < desc->length; i++) {
		if ((desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME)) {
			unsigned tmp_remaining = *src_size;
			items[i].dname = load_test_dname(src, src_size);

			if (items[i].dname == NULL) {
				fprintf(stderr, "Could not load DNAME!\n");
				free(rdata);
				free(items);

				/* TODO something like Marek's purge */

				return NULL;
			}

//			diag("Created DNAME %p item: %d %s %s\n",
//			     items[i].dname, i, knot_rrtype_to_string(type),
//			     items[i].dname->str);

			rdata->count++;
			items[i].type = TEST_ITEM_DNAME;
			items[i].raw_data = NULL;
			total_read += tmp_remaining - *src_size;
		} else {
			if (desc->wireformat[i] ==
			    KNOT_RDATA_WF_BINARYWITHLENGTH) {
				if (!mem_read(&raw_data_length,
				     sizeof(raw_data_length), src, src_size)) {
					return NULL;
				}

				total_read++;

				items[i].raw_data =
					malloc(sizeof(uint8_t) *
					       (raw_data_length + 3));

				items[i].raw_data[0] =
					(uint16_t) raw_data_length + 1;

				/* let's store the length again */

				((uint8_t *)items[i].raw_data)[2] =
					raw_data_length;

				if (!mem_read(((uint8_t *)
				    items[i].raw_data) + 3,
				    sizeof(uint8_t) * (raw_data_length),
				    src, src_size)) {
					fprintf(stderr, "Wrong read!\n");
					return NULL;
				}

				rdata->count++;
				items[i].type = TEST_ITEM_RAW_DATA;
				items[i].dname = NULL;
				total_read += sizeof(uint8_t) * raw_data_length;
/*				printf("read len (from wire): %d\n",
				       items[i].raw_data[0]);
				hex_print((char *)items[i].raw_data + 1,
					  items[i].raw_data[0]);
				*/
			} else {
				/* Other type than dname or BINARYWITHLENGTH */
				/* Set dname to NULL */
				items[i].dname = NULL;

				uint16_t size_fr_desc =
					(uint16_t)
					wireformat_size_load(desc->wireformat[i]);
#ifdef RESP_TEST_DEBUG
				fprintf(stderr, "reading %d\n", size_fr_desc);
#endif

				if (size_fr_desc == 0) { /* unknown length */
/*					size_fr_desc = wireformat_size_n(type,
									 items,
									i);
									*/
					if ((i != desc->length - 1) &&
					    desc->wireformat[i] !=
					    KNOT_RDATA_WF_TEXT ) {
						fprintf(stderr,
						        "I dont know how "
						"to parse this type: %d\n",
						type);
						return NULL;
					} else {
						size_fr_desc =
						total_raw_data_length -
						total_read;
						if (desc->wireformat[i] ==
						KNOT_RDATA_WF_TEXT) {
							break;
						}

//						fprintf(stderr,
//						        "Guessed size: %d"
//						     " for type: %s"
//						     " and index: %d\n",
//						     size_fr_desc,
//					    knot_rrtype_to_string(type),
//						    i);
						}
				}

				items[i].raw_data =
				malloc(sizeof(uint8_t) * size_fr_desc + 2);

//				diag("creating raw_data for item %d type %s %p\n",
//				     i, knot_rrtype_to_string(type),
//				     items[i].raw_data);

				if (items[i].raw_data == NULL) {
					ERR_ALLOC_FAILED;
					free(rdata);
					free(items);
					return NULL;
				}

				items[i].raw_data[0] = size_fr_desc;

				if (!mem_read(items[i].raw_data + 1,
					      size_fr_desc,
					      src, src_size)) {
					fprintf(stderr, "Wrong read\n!");
					return NULL;
				}

				rdata->count++;
				items[i].type = TEST_ITEM_RAW_DATA;
				items[i].dname = NULL;
				total_read += size_fr_desc;

#ifdef RESP_TEST_DEBUG
				fprintf(stderr,
				        "read len (from descriptor): %d\n",
				       items[i].raw_data[0]);
/*				hex_print((char *)items[i].raw_data + 1,
					  items[i].raw_data[0]); */

				if (desc->zoneformat[i] ==
				    KNOT_RDATA_ZF_ALGORITHM) {
					hex_print((char *)items[i].raw_data,
						  items[i].raw_data[0] + 2);
				} else {
					hex_print((char *)items[i].raw_data,
						  items[i].raw_data[0] + 2);
				}
#endif
			}
		}
	}

/*	if (knot_rdata_set_items(rdata, items, i) != 0) {
		diag("Error: could not set items\n");
		return NULL;
	} */

	rdata->items = items;

	return rdata;
}

static test_rrset_t *load_response_rrset(const char **src, unsigned *src_size,
					   char is_question)
{
	test_rrset_t *rrset = NULL;
	uint16_t rrset_type = 0;
	uint16_t rrset_class = 0;
	uint32_t rrset_ttl = 0;

	/* Each rrset will only have one rdata entry */

	/*
	 * RRSIGs will be read as separate RRSets because that's the way they
	 * are stored in responses
	 */

	/* Read owner first */

	uint8_t dname_size;
//	uint8_t *dname_wire = NULL;

	rrset = malloc(sizeof(test_rrset_t));

	rrset->rrsigs = NULL;

	CHECK_ALLOC_LOG(rrset, NULL);

	init_list(&rrset->rdata_list);

	/* TODO change in dump, size is useless now! */
	if (!mem_read(&dname_size, sizeof(dname_size), src, src_size)) {
		free(rrset);
		return NULL;
	}

/*	dname_wire = malloc(sizeof(uint8_t) * dname_size);

	CHECK_ALLOC_LOG(dname_wire, NULL);

	if (!mem_read(dname_wire, sizeof(uint8_t) * dname_size, src,
		      src_size)) {
		free(dname_wire);
		return NULL;
	} */

	test_dname_t *owner = load_test_dname(src, src_size);

	if (owner == NULL) {
		free(rrset);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	{
		fprintf(stderr, "Got owner: %s", owner->str);
	}
#endif
	/* Read other data */

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
	} else {
		rrset_ttl = 0;
	}

//	rrset = knot_rrset_new(owner, rrset_type, rrset_class, rrset_ttl);

	rrset->owner = owner;
	rrset->type = rrset_type;
	rrset->rclass = rrset_class;
	rrset->ttl = rrset_ttl;

	/* Question rrsets have no rdata */

	if (!is_question) {
		test_rdata_t *tmp_rdata;

		tmp_rdata = load_response_rdata(rrset->type, src, src_size);

		if (tmp_rdata == NULL) {
			fprintf(stderr,
			        "Could not load rrset rdata - type: %d",
			     rrset->type);
			free(rrset);
			return NULL;
		}

		assert(tmp_rdata->type == rrset->type);

		add_tail(&rrset->rdata_list, (node *)tmp_rdata);
	}

	return rrset;
}

static test_response_t *load_parsed_response(const char **src,
					     unsigned *src_size)
{
	/* Loads parsed response/query from binary format,
	 * which is as following:
	 * [id][qdcount][ancount][nscount][arcount]
	 * [question_rrset+][answer_rrset+][authority_rrset+]
	 * [additional_rrset]+
	 */

	test_response_t *resp = malloc(sizeof(test_response_t));

	CHECK_ALLOC_LOG(resp, NULL);

	if (!mem_read(&resp->id, sizeof(resp->id), src, src_size)) {
		free(resp);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "id %d\n", resp->id);
#endif

	if (!mem_read(&resp->qdcount, sizeof(resp->qdcount), src, src_size)) {
		free(resp);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "qdcount: %d\n", resp->qdcount);
#endif

	if (!mem_read(&resp->ancount, sizeof(resp->ancount), src, src_size)) {
		free(resp);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "ancount: %d\n", resp->ancount);
#endif

	if (!mem_read(&resp->nscount, sizeof(resp->nscount), src, src_size)) {
		free(resp);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "nscount: %d\n", resp->nscount);
#endif

	if (!mem_read(&resp->arcount, sizeof(resp->arcount), src, src_size)) {
		free(resp);
		return NULL;
	}

#ifdef RESP_TEST_DEBUG
	fprintf(stderr, "arcount: %d\n", resp->arcount);
#endif

	if (!mem_read(&resp->query, sizeof(resp->query), src, src_size)) {
		free(resp);
		return NULL;
	}

	test_rrset_t **question_rrsets;

	question_rrsets = malloc(sizeof(test_rrset_t *) * resp->qdcount);

	for (int i = 0; i < resp->qdcount; i++) {
		question_rrsets[i] = load_response_rrset(src, src_size, 1);
		if (question_rrsets[i] == NULL) {
			fprintf(stderr, "Could not load question rrsets\n");

			for (int j = 0; j < i; j++) {
				free(question_rrsets[i]);
			}
			free(question_rrsets);
			free(resp);
			return NULL;
		}
	}

	/* only one question in our case */

	resp->qname = question_rrsets[0]->owner;
	resp->qtype = question_rrsets[0]->type;
	resp->qclass = question_rrsets[0]->rclass;

	resp->question = NULL;

/*	for (int i = 0; i < resp->qdcount; i++) {
		knot_rrset_free(&(question_rrsets[i]));
	} */

	free(question_rrsets);

	test_rrset_t *tmp_rrset = NULL;

	if (resp->ancount > 0) {
		resp->answer =
			malloc(sizeof(test_rrset_t *) * resp->ancount);
	} else {
		resp->answer = NULL;
	}

	for (int i = 0; i < resp->ancount; i++) {
		tmp_rrset = load_response_rrset(src, src_size, 0);
		resp->answer[i] = tmp_rrset;
		if (resp->answer[i] == NULL) {
			fprintf(stderr, "Could not load answer rrsets\n");
			free(resp->answer);
			free(resp);
			return NULL;
		}
	}

	if (resp->nscount > 0) {
		resp->authority =
			malloc(sizeof(test_rrset_t *) * resp->nscount);
	} else {
		resp->authority = NULL;
	}

	for (int i = 0; i < resp->nscount; i++) {
		tmp_rrset = load_response_rrset(src, src_size, 0);
		resp->authority[i] = tmp_rrset;
		if (resp->authority[i] == NULL) {
			fprintf(stderr, "Could not load authority rrsets\n");
			free(resp->authority);
			free(resp->answer);
			free(resp);
			return NULL;
		}
	}

	if (resp->arcount > 0) {
		resp->additional =
			malloc(sizeof(test_rrset_t *) * resp->arcount);
	} else {
		resp->additional = NULL;
	}

	for (int i = 0; i < resp->arcount; i++) {
		tmp_rrset = load_response_rrset(src, src_size, 0);
		if (tmp_rrset == NULL) {
			fprintf(stderr, "Could not load rrset (additional)\n");
			free(resp->additional);
			free(resp->authority);
			free(resp->answer);
			free(resp);
			return NULL;
		}

		resp->additional[i] = tmp_rrset;
	}

	/* this will never be used */

	resp->flags1 = 0;
	resp->flags2 = 0;

	return resp;
}

static void test_dname_free(test_dname_t **dname)
{
	assert(dname != NULL && *dname != NULL);
	free((*dname)->labels);
//	free((*dname)->str);
	free((*dname)->wire);

	free(*dname);
	*dname = NULL;
}

static int wire_is_dname(uint type)
{
	return (type == KNOT_RDATA_WF_COMPRESSED_DNAME ||
	        type == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
	        type == KNOT_RDATA_WF_LITERAL_DNAME);
}

static void test_rdata_free(test_rdata_t **rdata)
{
	assert(rdata != NULL && *rdata != NULL);

	/* Free all the items */
	const knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type((*rdata)->type);

	for (int i = 0; i < (*rdata)->count; i++) {
		if ((wire_is_dname(desc->wireformat[i])) &&
		    ((*rdata)->items[i].dname != NULL)) {
			test_dname_free(&(*rdata)->items[i].dname);
		} else if ((*rdata)->items[i].raw_data != NULL) {
			free((*rdata)->items[i].raw_data);
			(*rdata)->items[i].raw_data = NULL;
		}
	}
//	free((*rdata)->items);
//	free(*rdata);
	*rdata = NULL;
}

static void test_rrset_free(test_rrset_t **rrset)
{
	assert(rrset && *rrset);

	test_dname_free(&(*rrset)->owner);
	/* Free all the rdatas */
	node *n = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, (*rrset)->rdata_list) {
		test_rdata_t *tmp_rdata = (test_rdata_t *)n;
		assert(tmp_rdata);
		if (tmp_rdata != NULL) {
			test_rdata_free(&tmp_rdata);
		}
	}

	free(*rrset);
	*rrset = NULL;
}

static void test_response_free(test_response_t **response)
{
	assert(response && *response);
	if ((*response)->qname != NULL) {
		test_dname_free(&(*response)->qname);
	}

	if ((*response)->additional != NULL) {
		for (int j = 0; j < (*response)->arcount; j++) {
			test_rrset_free(&((*response)->additional[j]));
		}

		free((*response)->additional);
	}

	if ((*response)->answer != NULL) {
		for (int j = 0; j < (*response)->ancount; j++) {
			test_rrset_free(&((*response)->answer[j]));
		}

		free((*response)->answer);
	}

	if ((*response)->authority != NULL) {
		for (int j = 0; j < (*response)->nscount; j++) {
			test_rrset_free(&((*response)->authority[j]));
		}

		free((*response)->authority);
	}

	free((*response));
	*response = NULL;
}

static void get_and_save_data_from_rdata(test_rdata_t *rdata,
                                         test_data_t *data, uint16_t type)
{
	/* We only want to extract dnames */
	const knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);

	if (rdata->count == 0) {
//		diag("Rdata count not set!\n");
		rdata->count = desc->length;
	}

	for(int i = 0; i < rdata->count; i++) {
		if ((desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME)) {
			add_tail(&data->dname_list,
			         (node *)rdata->items[i].dname);
			test_item_t *temp_item = malloc(sizeof(test_item_t));
			temp_item->dname = rdata->items[i].dname;
			temp_item->type = TEST_ITEM_DNAME;
			temp_item->raw_data = NULL;
			add_tail(&data->item_list, (node *)temp_item);
		} else {
			test_item_t *temp_item = malloc(sizeof(test_item_t));
			temp_item->dname = NULL;
			temp_item->type = TEST_ITEM_RAW_DATA;
			temp_item->raw_data = rdata->items[i].raw_data;
			add_tail(&data->item_list, (node *)temp_item);
		}
	}
}

static void get_and_save_data_from_rrset(const test_rrset_t *rrset,
                                         test_data_t *data)
{
//	knot_rrtype_descriptor_t *desc =
//		knot_rrtype_descriptor_by_type(rrset->type);
	/* RDATA are in a list. */
	node *n = NULL;
	int i = 0;
	WALK_LIST(n, rrset->rdata_list) {
		test_rdata_t *tmp_rdata = (test_rdata_t *)n;
		assert(tmp_rdata);
		assert(&data->rdata_list);
		assert(&data->rdata_list != &rrset->rdata_list);
		assert(tmp_rdata->type == rrset->type);

		test_rdata_t *new_rdata = malloc(sizeof(test_rdata_t));
		new_rdata->count = tmp_rdata->count;
		new_rdata->items = tmp_rdata->items;
		new_rdata->type = tmp_rdata->type;

		add_tail(&data->rdata_list, (node *)new_rdata);
		get_and_save_data_from_rdata(tmp_rdata, data, rrset->type);
		i++;
	}
	assert(i == 1);
}

static int add_rrset_to_node(const test_rrset_t *rrset, test_data_t *data)
{
	/* First, create node from rrset */
	test_node_t *tmp_node = malloc(sizeof(test_node_t));
	memset(tmp_node, 0, sizeof(test_node_t));
	CHECK_ALLOC_LOG(tmp_node, -1);

	tmp_node->owner = rrset->owner;
	tmp_node->parent = NULL;
	tmp_node->rrset_count = 0;

	/* Will not be used in list now */
	tmp_node->prev = NULL;
	tmp_node->next = NULL;


//	printf("%s\n", rrset->owner->wire);
//	getchar();

/*	tmp_node->avl_left = NULL;
	tmp_node->avl_right = NULL;
	tmp_node->avl_height = 0; */

	test_node_t *found_node =
		TREE_FIND(data->node_tree, test_node, avl, tmp_node);

	if (found_node == NULL) {
		/* Insert new node with current rrset */
		init_list(&tmp_node->rrset_list);
		add_tail(&tmp_node->rrset_list, (node *)rrset);
		tmp_node->rrset_count++;

		TREE_INSERT(data->node_tree, test_node, avl, tmp_node);
	} else {
		free(tmp_node);
		/* append rrset */

		add_tail(&found_node->rrset_list, (node *)rrset);
		found_node->rrset_count++;
	}

	return 0;
}

static void get_and_save_data_from_response(const test_response_t *response,
                                            test_data_t *data)
{
	/* Go through all the rrsets in the response */

	for (int i = 0; i < response->ancount; i++) {
		assert(response->answer[i]);
		/* Add rrset to the list of rrsets - there will be duplicates
		 * But not the same pointers */
		add_tail(&data->rrset_list, (node *)response->answer[i]);
		get_and_save_data_from_rrset(response->answer[i], data);
		if (add_rrset_to_node(response->answer[i], data) != 0) {
			return;
		}
	}

	for (int i = 0; i < response->arcount; i++) {
		/* Add rrset to the list of rrsets - there will be duplicates */
		assert(response->additional[i]);
		add_tail(&data->rrset_list, (node *)response->additional[i]);
		get_and_save_data_from_rrset(response->additional[i], data);
		if (add_rrset_to_node(response->additional[i], data) != 0) {
			return;
		}
	}

	for (int i = 0; i < response->nscount; i++) {
		assert(response->authority[i]);
		/* Add rrset to the list of rrsets - there will be duplicates */
		add_tail(&data->rrset_list, (node *)response->authority[i]);
		get_and_save_data_from_rrset(response->authority[i], data);
		if (add_rrset_to_node(response->authority[i], data) != 0) {
			return;
		}
	}

//	for (int i = 0; i < response->qdcount; i++) {
//		/* Add rrset to the list of rrsets - there will be duplicates */
//		add_tail(&data->rrset_list, (node *)response->question[i]);
//		get_and_save_data_from_rrset(response->question[i], data);
//	}
}

static int load_parsed_responses(test_data_t *data, uint32_t *count,
				 const char* src, unsigned src_size)
{
	if (!mem_read(count, sizeof(*count), &src, &src_size)) {
		fprintf(stderr, "Wrong read\n");
		return -1;
	}

//	*responses = malloc(sizeof(test_response_t *) * *count);

	for (int i = 0; i < *count; i++) {
		test_response_t *tmp_response =
			load_parsed_response(&src, &src_size);

		if (tmp_response == NULL) {
			fprintf(stderr, "Could not load response - %d"
			        "- returned NULL\n",
			     i);
			return -1;
		}

		if (tmp_response->query) {
			add_tail(&data->query_list, (node *)tmp_response);
		} else {
			add_tail(&data->response_list, (node *)tmp_response);
		}

		/* Create new node */
		test_response_t *resp = malloc(sizeof(test_response_t));
		assert(resp);
		memcpy(resp, tmp_response, sizeof(test_response_t));
		add_tail(&data->packet_list,
		         (node *)resp);
	}

	return 0;
}

//void free_parsed_responses(test_response_t ***responses, uint32_t *count)
//{
//	if (*responses != NULL) {
//		for (int i = 0; i < *count; i++) {
//			free_parsed_response((*responses)[i]);
//		}
//		free(*responses);
//	}
//}

static int compare_nodes(test_node_t *node1, test_node_t *node2)
{
	assert(node1->owner && node2->owner);
	/*!< \warning Wires have to be \0 terminated. */
	return (strcmp((char *)node1->owner->wire, (char *)node2->owner->wire));
}

static int init_data(test_data_t *data)
{
	if (data == NULL) {
		return 0;
	}

	/* Initialize all the lists */
	init_list(&data->dname_list);
	init_list(&data->edns_list);
	init_list(&data->node_list);
	init_list(&data->response_list);
	init_list(&data->rdata_list);
	init_list(&data->rrset_list);
	init_list(&data->item_list);
	init_list(&data->raw_response_list);
	init_list(&data->raw_query_list);
	init_list(&data->raw_packet_list);
	init_list(&data->query_list);
	init_list(&data->packet_list);

	data->node_tree = malloc(sizeof(avl_tree_test_t));
	CHECK_ALLOC_LOG(data->node_tree, 0);

	TREE_INIT(data->node_tree, compare_nodes);

	return 1;
}

static void print_stats(test_data_t *data)
{
	uint resp_count = 0, dname_count = 0, node_count = 0,
	     rdata_count = 0, rrset_count = 0, item_count = 0, query_count = 0,
	     raw_query_count = 0, response_count = 0, packet_count = 0,
	     raw_packet_count = 0, raw_response_count = 0;

	node *n = NULL; /* Will not be used */

	WALK_LIST(n, data->response_list) {
		resp_count++;
	}

	WALK_LIST(n, data->rrset_list) {
//		node *tmp = NULL;
//		assert(((test_rrset_t *)n)->owner);
//		WALK_LIST(tmp, ((test_rrset_t *)n)->rdata_list) {
//			test_rdata_t *rdata = (test_rdata_t *)tmp;
//			assert(rdata->type == ((test_rrset_t *)n)->type);
//		}
		rrset_count++;
	}

	WALK_LIST(n, data->rdata_list) {
		rdata_count++;
	}

	WALK_LIST(n, data->dname_list) {
		dname_count++;
	}

	WALK_LIST(n, data->node_list) {
		node_count++;
	}

	WALK_LIST(n, data->item_list) {
		item_count++;
	}

	WALK_LIST(n, data->raw_response_list) {
		raw_response_count++;
	}

	WALK_LIST(n, data->query_list) {
		query_count++;
	}

	WALK_LIST(n, data->response_list) {
		response_count++;
	}

	WALK_LIST(n, data->raw_query_list) {
		raw_query_count++;
	}

	WALK_LIST(n, data->packet_list) {
		packet_count++;
	}

	WALK_LIST(n, data->raw_packet_list) {
		raw_packet_count++;
	}

	printf("Loaded: Responses: %d RRSets: %d RDATAs: %d Dnames: %d "
	       "Nodes: %d Items: %d Raw_responses: %d Queries: %d \n"
	       "Raw_queries; %d Total packets: %d Total_raw_packets: %d\n", resp_count, rrset_count,
	       rdata_count, dname_count, node_count, item_count,
	       raw_response_count, query_count, raw_query_count, packet_count,
	       raw_packet_count);
}

static void save_node_to_list(test_node_t *n, void *p)
{
	test_data_t *data = (test_data_t *)p;

	add_tail(&data->node_list, (node *)n);
}

static void del_node(test_node_t *n, void *p)
{
//	test_data_t *data = (test_data_t *)p;
	free(n);
}


void free_data(test_data_t **data)
{
	assert(data && *data);
	/* We will free all the data using responses
	 * (others are just references )*/
	node *n = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, (*data)->response_list) {
		test_response_t *tmp_response = (test_response_t *)n;
		if (tmp_response != NULL) {
			test_response_free(&tmp_response);
		}
	}

	TREE_POST_ORDER_APPLY((*data)->node_tree, test_node, avl, del_node,
	                      NULL);

	free((*data)->node_tree);

	free(*data);
	*data = NULL;
}

test_data_t *create_test_data_from_dump()
{
	test_data_t *ret = malloc(sizeof(test_data_t));
	CHECK_ALLOC_LOG(ret, NULL);

	if (!init_data(ret)) {
		free(ret);
		return NULL;
	}

	uint32_t raw_packet_count = 0;

	if (load_raw_packets(ret, &raw_packet_count, raw_data_rc,
	                     raw_data_rc_size) != 0) {
		fprintf(stderr, "Could not load raw_data, quitting");
		/* TODO walk the lists*/
		free(ret);
		return NULL;
	}

	uint32_t response_count = 0;

	if (load_parsed_responses(ret, &response_count, parsed_data_rc,
	                          parsed_data_rc_size) != 0) {
		fprintf(stderr, "Could not load responses, quitting");
		/* TODO walk the lists*/
		free(ret);
		return NULL;
	}

	/* For each parsed response - create more data from it. */
	/* Probably not the most effective way, but it is better than to
	 * rewrite most of the code .*/

	node *n = NULL;

	WALK_LIST(n , ret->response_list) {
		get_and_save_data_from_response((test_response_t *)n, ret);
	}

	/* Create list from AVL tree */

	TREE_FORWARD_APPLY(ret->node_tree, test_node, avl,
	                   save_node_to_list, ret);

	print_stats(ret);

	return ret;
}
