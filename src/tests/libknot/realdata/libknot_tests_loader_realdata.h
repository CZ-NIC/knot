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

#ifndef KNOT_TESTS_LOADER_H
#define KNOT_TESTS_LOADER_H

#include <stdint.h>

#include "libknot/common.h"
#include "common/lists.h"
#include "common/tree.h"


/* Parsed raw packet*/
struct test_raw_packet {
	struct node *next, *prev;
	uint size;
	uint8_t *data;
};

typedef struct test_raw_packet test_raw_packet_t;

/* Test type definitions */

struct test_dname {
	struct node *next, *prev;
	char *str;
	uint8_t *wire;
	uint size;
	uint8_t *labels;
	short label_count;
};

typedef struct test_dname test_dname_t;

struct test_edns_options {
	struct node *next, *prev;
	uint16_t code;
	uint16_t length;
	uint8_t *data;
};

struct test_edns {
	struct node *next, *prev;
	struct test_edns_options *options;
	uint16_t payload;
	uint8_t ext_rcode;
	uint8_t version;
	uint16_t flags;
	uint16_t *wire;
	short option_count;
	short options_max;
	short size;
};

typedef struct test_edns test_edns_t;

typedef TREE_HEAD(avl_tree_test, test_node) avl_tree_test_t;

struct test_node {
	struct node *next, *prev;
	test_dname_t *owner;
	short rrset_count;
	struct test_node *parent;
	list rrset_list;

	TREE_ENTRY(test_node) avl;
};

typedef struct test_node test_node_t;

enum item_type {
	TEST_ITEM_DNAME,
	TEST_ITEM_RAW_DATA
};

typedef enum item_type item_type_t;

struct test_item {
	uint16_t *raw_data;
	test_dname_t *dname;
	item_type_t type;
};

typedef struct test_item test_item_t;

struct test_rdata {
	struct node *next, *prev;
	uint count;
	uint type;  /*!< Might be handy */
	test_item_t *items;
};

typedef struct test_rdata test_rdata_t;

struct test_rrset {
	struct node *next, *prev;
	test_dname_t *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	struct test_rrset *rrsigs;
	uint16_t *wire;
	list rdata_list;
};

typedef struct test_rrset test_rrset_t;

struct test_response {
	struct node *next, *prev;
	/* This is basically same thing as actual response structure */
	uint16_t query;
	test_dname_t *qname;
	uint16_t qclass;
	uint16_t qtype;
	uint16_t id;
	uint8_t flags1;
	uint8_t flags2;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	/* Arrays of rrsets */

	test_rrset_t **question;
	test_rrset_t **answer;
	test_rrset_t **authority;
	test_rrset_t **additional;

	short size;

	/* what about the rest of the values?
	 * they cannot be modified from API, but this is probably the best
	 * place to test them as well */
};

typedef struct test_response test_response_t;

/*!< \brief contains lists of all the structures */
struct test_data {
	list dname_list;
	list edns_list;
	list rdata_list;
	list node_list;
	list rrset_list;
	list response_list;
	list raw_response_list;
	list query_list;
	list raw_query_list;
	list item_list;
	/* responses and queries together */
	list packet_list;
	list raw_packet_list;

	avl_tree_test_t *node_tree;
};

typedef struct test_data test_data_t;

/*!< \brief Parses resource with data and creates all possible structures. */
test_data_t *create_test_data_from_dump();

test_data_t *data_for_knot_tests;

#endif // KNOT_TESTS_LOADER_H
