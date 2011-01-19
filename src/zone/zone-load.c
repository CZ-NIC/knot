#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zone-load.h"
#include "dnslib/dnslib.h"
#include "common.h"
#include "debug.h"

enum { MAGIC_LENGTH = 6 };

enum { DNAME_MAX_WIRE_LENGTH = 256 };

//TODO move to parameters
static dnslib_dname_t **id_array;

dnslib_rdata_t *dnslib_load_rdata(uint16_t type, FILE *f)
{
	dnslib_rdata_t *rdata;

	rdata = dnslib_rdata_new();

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dnslib_rdata_item_t *items =
		malloc(sizeof(dnslib_rdata_item_t) * desc->length);

	uint8_t raw_data_length;

	debug_zp("Reading %d items\n", desc->length);

	debug_zp("current type: %s\n", dnslib_rrtype_to_string(type));

	for (int i = 0; i < desc->length; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{

			/* TODO maybe this does not need to be stored this big */

			void *tmp_id;
			uint8_t dname_in_zone;

			uint8_t dname_size;
			uint8_t *dname_wire = NULL; //[DNAME_MAX_WIRE_LENGTH] = { 0 };
			short label_count;
			uint8_t *labels;

			uint8_t has_wildcard;

			fread(&dname_in_zone, sizeof(dname_in_zone), 1, f);
			if (dname_in_zone) {
				fread(&tmp_id, sizeof(void *), 1, f);
				items[i].dname = id_array[(uint)tmp_id];
			} else {
				fread(&dname_size, sizeof(dname_size), 1, f);
				assert(dname_size < DNAME_MAX_WIRE_LENGTH);

				dname_wire = malloc(sizeof(uint8_t) * dname_size);
				fread(dname_wire, sizeof(uint8_t),
				      dname_size, f);

				fread(&label_count, sizeof(label_count), 1, f);

				labels = malloc(sizeof(uint8_t) * label_count);
				fread(labels, sizeof(uint8_t), label_count, f);

				fread(&has_wildcard, sizeof(uint8_t), 1, f);

				items[i].dname = malloc(sizeof(dnslib_dname_t));

				items[i].dname->name = dname_wire;
				items[i].dname->size = dname_size;
				items[i].dname->labels = labels;
				items[i].dname->label_count = label_count;

				if (has_wildcard) {
					fread(&tmp_id, sizeof(void *), 1, f);
					printf("read ID: %d\n", (uint)tmp_id);
					getchar();
					items[i].dname->node = id_array[(uint)tmp_id]->node;
				} else {
					items[i].dname->node = NULL;
				}
			}

			assert(items[i].dname);

		} else {
			fread(&raw_data_length, sizeof(raw_data_length), 1, f);
			debug_zp("read len: %d\n", raw_data_length);
			items[i].raw_data =
				malloc(sizeof(uint8_t) * raw_data_length + 1);
			*(items[i].raw_data) = raw_data_length;
			fread(items[i].raw_data + 1, sizeof(uint8_t),
			      raw_data_length, f);
		}
	}

	if (dnslib_rdata_set_items(rdata, items, desc->length) != 0) {
		fprintf(stderr, "Error: could not set items\n");
	}

	free(items);

	return rdata;
}

dnslib_rrsig_set_t *dnslib_load_rrsig(FILE *f)
{
	dnslib_rrsig_set_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;

	fread(&rrset_type, sizeof(rrset_type), 1, f);
	debug_zp("rrset type: %d\n", rrset_type);
	fread(&rrset_class, sizeof(rrset_class), 1, f);
	debug_zp("rrset class %d\n", rrset_class);
	fread(&rrset_ttl, sizeof(rrset_ttl), 1, f);
	debug_zp("rrset ttl %d\n", rrset_ttl);

	fread(&rdata_count, sizeof(rdata_count), 1, f);

	rrsig = dnslib_rrsig_set_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	debug_zp("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(DNSLIB_RRTYPE_RRSIG, f);
		dnslib_rrsig_set_add_rdata(rrsig, tmp_rdata);
	}

	return rrsig;
}

dnslib_rrset_t *dnslib_load_rrset(FILE *f)
{
	dnslib_rrset_t *rrset;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;
	uint8_t rrsig_count;

	fread(&rrset_type, sizeof(rrset_type), 1, f);
	fread(&rrset_class, sizeof(rrset_class), 1, f);
	fread(&rrset_ttl, sizeof(rrset_ttl), 1, f);

	fread(&rdata_count, sizeof(rdata_count), 1, f);
	fread(&rrsig_count, sizeof(rrsig_count), 1, f);

	rrset = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	debug_zp("RRSet type: %d\n", rrset->type);

	dnslib_rdata_t *tmp_rdata;

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(rrset->type, f);
		dnslib_rrset_add_rdata(rrset, tmp_rdata);
	}

	dnslib_rrsig_set_t *tmp_rrsig = NULL;

	if (rrsig_count) {
		tmp_rrsig = dnslib_load_rrsig(f);
	}

	rrset->rrsigs = tmp_rrsig;

	return rrset;
}

dnslib_node_t *dnslib_load_node(FILE *f)
{

	uint8_t dname_size = 0;
	uint8_t flags = 0;
	dnslib_node_t *node;
	/* first, owner */
	
	uint8_t dname_wire[DNAME_MAX_WIRE_LENGTH]; 
	//XXX in respect to remark below, should be dynamic 
	//(malloc happens either way)
	//but I couldn't make it work - really strange error
	//when fread() was rewriting other variables

	uint8_t rrset_count;
	void *dname_id; //ID, technically it's an integer(32 or 64 bites)
	void *parent_id;

	short label_count = 0;
	uint8_t *labels = NULL;

	fread(&dname_size, sizeof(dname_size), 1, f);

	debug_zp("%d\n", dname_size);

	assert(dname_size < DNAME_MAX_WIRE_LENGTH);

	fread(dname_wire, sizeof(uint8_t), dname_size, f);
	/* refactor */
	fread(&label_count, sizeof(label_count), 1, f);

	labels = malloc(sizeof(uint8_t) * label_count);

	fread(labels, sizeof(uint8_t), label_count, f);

	/* refactor */

	fread(&dname_id, sizeof(dname_id), 1, f);

	debug_zp("id: %p\n", dname_id);

	fread(&parent_id, sizeof(dname_id), 1, f);

	fread(&flags, sizeof(flags), 1, f);

	fread(&rrset_count, sizeof(rrset_count), 1, f);

	dnslib_dname_t *owner = id_array[(uint)dname_id];

	owner->name = malloc(sizeof(uint8_t) * dname_size);
	memcpy(owner->name, dname_wire, dname_size);
	owner->size = dname_size;

	owner->labels = labels;
	owner->label_count = label_count;

	debug_zp("Node owned by: %s\n", dnslib_dname_to_str(owner));
	debug_zp("labels: %d\n", owner->label_count);
//	hex_print(owner->labels, owner->label_count);

	debug_zp("Number of RRSets in a node: %d\n", rrset_count);

	node = owner->node;

	node->owner = owner;

	if (node == NULL) {
		fprintf(stderr, "Error: could not create node\n");
		return NULL;
	}

	node->flags = flags;

	//XXX will have to be set already...canonical order should do it

	if ((uint)parent_id != 0) {
		node->parent = id_array[(uint)parent_id]->node;
		assert(node->parent != NULL);
	} else {
		node->parent = NULL;
	}

	dnslib_rrset_t *tmp_rrset;

	for (int i = 0; i < rrset_count; i++) {
		if ((tmp_rrset = dnslib_load_rrset(f)) == NULL) {
			dnslib_node_free(&node, 1);
			//TODO what else to free?
			printf("could not load rrset\n");
			return NULL;
		}
		tmp_rrset->owner = node->owner;
		if (tmp_rrset->rrsigs != NULL) {
			tmp_rrset->rrsigs->owner = node->owner;
		}
		if (dnslib_node_add_rrset(node, tmp_rrset) != 0) {
			fprintf(stderr, "Error: could not add rrset\n");
			return NULL;
		}
	}
	assert(node != NULL);
	return node;
}

void find_and_set_wildcard_child(dnslib_zone_t *zone,
                                 dnslib_node_t *node, int nsec3)
{
	dnslib_dname_t *chopped = dnslib_dname_left_chop(node->owner);
	assert(chopped);
	dnslib_node_t *wildcard_parent;
	if (!nsec3) {
		wildcard_parent =
			dnslib_zone_get_node(zone, chopped);
	} else {
		wildcard_parent =
			dnslib_zone_get_nsec3_node(zone, chopped);
	}

	dnslib_dname_free(&chopped);

	assert(wildcard_parent); /* it *has* to be there */

	wildcard_parent->wildcard_child = node;
}

int dnslib_check_magic(FILE *f, const uint8_t* MAGIC, uint MAGIC_LENGTH)
{
	uint8_t tmp_magic[MAGIC_LENGTH];

	fread(&tmp_magic, sizeof(uint8_t), MAGIC_LENGTH, f);

	for (int i = 0; i < MAGIC_LENGTH; i++) {
		if (tmp_magic[i] != MAGIC[i]) {
			return 0;
		}
	}

	return 1;
}

dnslib_zone_t *dnslib_zone_load(const char *filename)
{
	FILE *f = fopen(filename, "rb");

	dnslib_node_t *tmp_node;

	uint node_count;

	uint nsec3_node_count;

	uint auth_node_count;

	static const uint8_t MAGIC[MAGIC_LENGTH] = {99, 117, 116, 101, 0, 1};
	                                           /*c   u    t    e   0.1*/

	if (!dnslib_check_magic(f, MAGIC, MAGIC_LENGTH)) {
		fprintf(stderr, "Error: unknown file format\n");
		return NULL;
	}

	fread(&node_count, sizeof(node_count), 1, f);
	fread(&nsec3_node_count, sizeof(nsec3_node_count), 1, f);
	fread(&auth_node_count,
	      sizeof(auth_node_count), 1, f);

	debug_zp("authorative nodes: %u\n", auth_node_count);

	uint8_t dname_size;
	uint8_t dname_wire[DNAME_MAX_WIRE_LENGTH];

	fread(&dname_size, sizeof(dname_size), 1, f);
	assert(dname_size < DNAME_MAX_WIRE_LENGTH);

	fread(dname_wire, sizeof(uint8_t), dname_size, f);

	dnslib_dname_t *apex_dname = malloc(sizeof(dnslib_dname_t));

	apex_dname->size = dname_size;

	apex_dname->name = malloc(sizeof(uint8_t) * dname_size);

	memcpy(apex_dname->name, dname_wire, dname_size);

	fread(&apex_dname->label_count, sizeof(apex_dname->label_count), 1, f);

	apex_dname->labels = malloc(sizeof(uint8_t) * apex_dname->label_count);

	fread(apex_dname->labels, sizeof(uint8_t), apex_dname->label_count, f);

	id_array =
		malloc(sizeof(dnslib_dname_t *) *
		(node_count + nsec3_node_count + 1));

	printf("loading %u nodes\n", node_count);

	for (uint i = 1; i < (node_count + nsec3_node_count + 1); i++) {
		id_array[i] = malloc(sizeof(dnslib_dname_t));
		id_array[i]->node = dnslib_node_new(NULL, NULL);
	}

	dnslib_node_t *apex = dnslib_load_node(f);

	if (!apex) {
		fprintf(stderr, "Could not load apex node.\n");
		return NULL;
	}

	dnslib_zone_t *zone = dnslib_zone_new(apex, auth_node_count);

	for (uint i = 1; i < node_count; i++) {
		tmp_node = dnslib_load_node(f);
		if (tmp_node != NULL) {
			dnslib_zone_add_node(zone, tmp_node);
			if (dnslib_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(zone,
				                            tmp_node,
							    0);
			}
		} else {
			fprintf(stderr, "Node error!\n");
		}
	}

	printf("loading %u nsec3 nodes\n", nsec3_node_count);

	for (uint i = 0; i < nsec3_node_count; i++) {
		tmp_node = dnslib_load_node(f);
		if (tmp_node != NULL) {
			dnslib_zone_add_nsec3_node(zone, tmp_node);
		} else {
			fprintf(stderr, "Node error!\n");
		}
		if (dnslib_dname_is_wildcard(tmp_node->owner)) {
			find_and_set_wildcard_child(zone,
			                            tmp_node,
						    1);
		}
	}

	fclose(f);

	return zone;
}

