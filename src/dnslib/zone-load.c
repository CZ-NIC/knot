#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zone-load.h"
#include "dnslib/dnslib.h"
#include "common.h"
#include "debug.h"

/* \note Contents of dump file:
 * MAGIC(cutexx) NUMBER_OF_NORMAL_NODES NUMBER_OF_NSEC3_NODES
 * [normal_nodes] [nsec3_nodes]
 * node has following format:
 * owner_size owner_wire owner_label_size owner_labels owner_id
 * node_flags node_rrset_count [node_rrsets]
 * rrset has following format:
 * rrset_type rrset_class rrset_ttl rrset_rdata_count rrset_rrsig_count
 * [rrset_rdata] [rrset_rrsigs]
 * rdata can either contain full dnames (that is with labels but without ID)
 * or dname ID, if dname is in the zone
 * or raw data stored like this: data_len [data]
 */

enum { MAGIC_LENGTH = 6 };

enum { DNAME_MAX_WIRE_LENGTH = 256 };

//TODO move to parameters
static dnslib_dname_t **id_array;

static void load_rdata_purge(dnslib_rdata_t *rdata,
                               dnslib_rdata_item_t *items,
                               int count,
                               uint16_t type)
{
	dnslib_rdata_set_items(rdata, items, count);
	dnslib_rdata_deep_free(&rdata, type, 0);
	free(items);
}

dnslib_rdata_t *dnslib_load_rdata(uint16_t type, FILE *f)
{
	dnslib_rdata_t *rdata;

	rdata = dnslib_rdata_new();

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dnslib_rdata_item_t *items =
		malloc(sizeof(dnslib_rdata_item_t) * desc->length);

	uint16_t raw_data_length;

	debug_zp("Reading %d items\n", desc->length);

	debug_zp("current type: %s\n", dnslib_rrtype_to_string(type));

	for (int i = 0; i < desc->length; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{

			/* TODO maybe this does not need to be stored this big*/

			void *tmp_id;
			uint8_t dname_in_zone;

			uint8_t dname_size;
			uint8_t *dname_wire = NULL;
			short label_count;
			uint8_t *labels;

			uint8_t has_wildcard;

			if(!fread_safe(&dname_in_zone, sizeof(uint8_t), 1, f)) {
				load_rdata_purge(rdata, items, i, type);
				return 0;
			}
			if (dname_in_zone) {
				if(!fread_safe(&tmp_id, sizeof(void *), 1, f)) {
					load_rdata_purge(rdata, items, i, type);
					return 0;
				}
				items[i].dname = id_array[(size_t)tmp_id];
			} else {
				if(!fread_safe(&dname_size,
				               sizeof(uint8_t), 1, f)) {
					load_rdata_purge(rdata, items, i, type);
					return 0;
				}
				assert(dname_size < DNAME_MAX_WIRE_LENGTH);

				dname_wire =
					malloc(sizeof(uint8_t) * dname_size);
				if(!fread_safe(dname_wire, sizeof(uint8_t),
				               dname_size, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					return 0;
				}


				if(!fread_safe(&label_count,
				               sizeof(label_count), 1, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					return 0;
				}

				labels = malloc(sizeof(uint8_t) * label_count);
				if(!fread_safe(labels,sizeof(uint8_t),
				               label_count, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					return 0;
				}

				if(!fread_safe(&has_wildcard, sizeof(uint8_t),
				               1, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					return 0;
				}

				if (has_wildcard) {
					if(!fread_safe(&tmp_id, sizeof(void *),
					               1, f)) {
						load_rdata_purge(rdata, items,
						                 i, type);
						free(dname_wire);
						return 0;
					}
				} else {
					tmp_id = NULL;
				}

				items[i].dname = dnslib_dname_new();

				items[i].dname->name = dname_wire;
				items[i].dname->size = dname_size;
				items[i].dname->labels = labels;
				items[i].dname->label_count = label_count;

				if (has_wildcard) {
					if (!fread_safe(&tmp_id, sizeof(void *),
					           1, f)) {
						load_rdata_purge(rdata, items,
						                 i + 1, type);
						return 0;
					}
					items[i].dname->node =
					         id_array[(size_t)tmp_id]->node;
				} else {
					items[i].dname->node = NULL;
				}
			}

			assert(items[i].dname);

		} else {
			if (!fread_safe(&raw_data_length,
			                sizeof(raw_data_length), 1, f)) {
				load_rdata_purge(rdata, items, i, type);
				return 0;
			}

			debug_zp("read len: %d\n", raw_data_length);
			items[i].raw_data =
				malloc(sizeof(uint8_t) * raw_data_length + 2);
			*(items[i].raw_data) = raw_data_length;

			if (!fread_safe(items[i].raw_data + 1, sizeof(uint8_t),
			      raw_data_length, f)) {
				load_rdata_purge(rdata, items, i + 1, type);
				return 0;
			}
		}
	}

	if (dnslib_rdata_set_items(rdata, items, desc->length) != 0) {
		log_error("!! could not set items when loading rdata\n");
	}

	free(items);

	return rdata;
}

dnslib_rrset_t *dnslib_load_rrsig(FILE *f)
{
	dnslib_rrset_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;

	if (!fread_safe(&rrset_type, sizeof(rrset_type), 1, f)) {
		return 0;
	}

	if (rrset_type != DNSLIB_RRTYPE_RRSIG) {
		log_error("!! Error: rrsig has wrong type\n");
		return 0;
	}
	debug_zp("rrset type: %d\n", rrset_type);
	if (!fread_safe(&rrset_class, sizeof(rrset_class), 1, f)) {
		return 0;
	}
	debug_zp("rrset class %d\n", rrset_class);

	if (!fread_safe(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return 0;
	}
	debug_zp("rrset ttl %d\n", rrset_ttl);

	if (!fread_safe(&rdata_count, sizeof(rdata_count), 1, f)) {
		return 0;
	}

	rrsig = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	debug_zp("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(DNSLIB_RRTYPE_RRSIG, f);
		if (tmp_rdata) {
			dnslib_rrset_add_rdata(rrsig, tmp_rdata);
		} else {
			dnslib_rrset_deep_free(&rrsig, 0, 1);
			return 0;
		}
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

	if (!fread_safe(&rrset_type, sizeof(rrset_type), 1, f)) {
		return 0;
	}
	if (!fread_safe(&rrset_class, sizeof(rrset_class), 1, f)) {
		return 0;
	}
	if (!fread_safe(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return 0;
	}
	if (!fread_safe(&rdata_count, sizeof(rdata_count), 1, f)) {
		return 0;
	}
	if (!fread_safe(&rrsig_count, sizeof(rrsig_count), 1, f)) {
		return 0;
	}

	rrset = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	debug_zp("RRSet type: %d\n", rrset->type);

	dnslib_rdata_t *tmp_rdata;

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(rrset->type, f);
		if (tmp_rdata) {
			dnslib_rrset_add_rdata(rrset, tmp_rdata);
		} else {
			dnslib_rrset_deep_free(&rrset, 0, 1);
			return 0;
		}
	}

	dnslib_rrset_t *tmp_rrsig = NULL;

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
	void *nsec3_node_id;

	short label_count = 0;
	uint8_t *labels = NULL;

	if (!fread_safe(&dname_size, sizeof(dname_size), 1, f)) {
		return 0;
	}

	debug_zp("%d\n", dname_size);

	assert(dname_size < DNAME_MAX_WIRE_LENGTH);

	if (!fread_safe(dname_wire, sizeof(uint8_t), dname_size, f)) {
		return 0;
	}

	/* refactor */
	if (!fread_safe(&label_count, sizeof(label_count), 1, f)) {
		return 0;
	}

	labels = malloc(sizeof(uint8_t) * label_count);
	if (!fread_safe(labels, sizeof(uint8_t), label_count, f)) {
		return 0;
	}

	/* refactor */

	if (!fread_safe(&dname_id, sizeof(dname_id), 1, f)) {
		free(labels);
		return 0;
	}

	debug_zp("id: %p\n", dname_id);

	if (!fread(&parent_id, sizeof(dname_id), 1, f)) {
		free(labels);
		return 0;
	}

	if (!fread(&flags, sizeof(flags), 1, f)) {
		free(labels);
		return 0;
	}

	if (!fread_safe(&nsec3_node_id, sizeof(nsec3_node_id), 1, f)) {
		free(labels);
		return 0;
	}

	if (!fread(&rrset_count, sizeof(rrset_count), 1, f)) {
		free(labels);
		return 0;
	}

	dnslib_dname_t *owner = id_array[(size_t)dname_id];

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

	if (node == NULL) {
		log_error("!! could not create node.\n");
		return NULL;
	}

	/* XXX can it be 0, ever? I think not. */
	if ((size_t)nsec3_node_id != 0) {
		node->nsec3_node = id_array[(size_t)nsec3_node_id]->node;
	} else {
		node->nsec3_node = NULL;
	}

	node->owner = owner;

	node->flags = flags;

	//XXX will have to be set already...canonical order should do it

	if (parent_id != 0) {
		node->parent = id_array[(size_t)parent_id]->node;
		assert(node->parent != NULL);
	} else {
		node->parent = NULL;
	}

	dnslib_rrset_t *tmp_rrset;

	for (int i = 0; i < rrset_count; i++) {
		if ((tmp_rrset = dnslib_load_rrset(f)) == NULL) {
			dnslib_node_free(&node, 1);
			//TODO what else to free?
			log_error("!! could not load rrset.\n");
			return NULL;
		}
		tmp_rrset->owner = node->owner;
		if (tmp_rrset->rrsigs != NULL) {
			tmp_rrset->rrsigs->owner = node->owner;
		}
		if (dnslib_node_add_rrset(node, tmp_rrset) != 0) {
			log_error("!! could not add rrset.\n");
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

	if (!fread_safe(&tmp_magic, sizeof(uint8_t), MAGIC_LENGTH, f)) {
		return 0;
	}

	for (int i = 0; i < MAGIC_LENGTH; i++) {
		if (tmp_magic[i] != MAGIC[i]) {
			return 0;
		}
	}

	return 1;
}

dnslib_zone_t *dnslib_zload_load(const char *filename)
{
	FILE *f = fopen(filename, "rb");

	if (f == NULL) {
		log_error("Could not open file '%s'\n", filename);
		return NULL;
	}

	dnslib_node_t *tmp_node;

	uint node_count;

	uint nsec3_node_count;

	uint auth_node_count;

	static const uint8_t MAGIC[MAGIC_LENGTH] = {99, 117, 116, 101, 0, 3};
						   /*c   u    t    e   0.3*/

	if (!dnslib_check_magic(f, MAGIC, MAGIC_LENGTH)) {
		log_error("!! compiled zone file '%s' has unknown format\n",
		          filename);
		fclose(f);
		return 0;
	}

	if (!fread_safe(&node_count, sizeof(node_count), 1, f)) {
		fclose(f);
		return 0;
	}
	if (!fread_safe(&nsec3_node_count, sizeof(nsec3_node_count), 1, f)) {
		fclose(f);
		return 0;
	}
	if (!fread_safe(&auth_node_count,
	      sizeof(auth_node_count), 1, f)) {
		fclose(f);
		return 0;
	}

	debug_zp("authorative nodes: %u\n", auth_node_count);

	id_array =
		malloc(sizeof(dnslib_dname_t *) *
		(node_count + nsec3_node_count + 1));

	debug_zp("loading %u nodes\n", node_count);

	for (uint i = 1; i < (node_count + nsec3_node_count + 1); i++) {
		id_array[i] = dnslib_dname_new();
		id_array[i]->node = dnslib_node_new(NULL, NULL);
	}

	dnslib_node_t *apex = dnslib_load_node(f);

	if (!apex) {
		log_error("!! could not load apex node (in %s)\n", filename);
		return NULL;
	}

	dnslib_zone_t *zone = dnslib_zone_new(apex, auth_node_count);

	apex->prev = NULL;

        dnslib_node_t *last_node;

        if (dnslib_node_get_rrset(apex, DNSLIB_RRTYPE_NSEC) != NULL) {
                last_node = apex;
        } else {
                last_node = NULL;
        }

	for (uint i = 1; i < node_count; i++) {
		tmp_node = dnslib_load_node(f);

		if (tmp_node != NULL) {
			dnslib_zone_add_node(zone, tmp_node);
			if (dnslib_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(zone,
				                            tmp_node,
				                            0);
			}

			tmp_node->prev = last_node;

                        if (skip_first(tmp_node->rrsets) != NULL &&
                            dnslib_node_get_rrset(tmp_node,
                                                  DNSLIB_RRTYPE_NSEC) != NULL) {
                                last_node = tmp_node;
                        }

		} else {
			log_error("!! node error (in %s)\n", filename);
		}
	}

	assert(zone->apex->prev == NULL);

	zone->apex->prev = last_node;

	debug_zp("loading %u nsec3 nodes\n", nsec3_node_count);

	dnslib_node_t *nsec3_first = NULL;

	if (nsec3_node_count > 0) {
		nsec3_first = dnslib_load_node(f);

		assert(nsec3_first != NULL);

		nsec3_first->prev = NULL;

		last_node = nsec3_first;
	}

	for (uint i = 1; i < nsec3_node_count; i++) {
		tmp_node = dnslib_load_node(f);

		if (tmp_node != NULL) {
			dnslib_zone_add_nsec3_node(zone, tmp_node);

			if (dnslib_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(zone,
				                            tmp_node,
				                            1);
                        }

                        if (skip_first(tmp_node->rrsets) != NULL) {
                                last_node = tmp_node;
                        }

			tmp_node->prev = last_node;

		} else {
			log_error("!! node error (in %s)\n", filename);
		}
	}

	if (nsec3_node_count) {
		assert(nsec3_first->prev == NULL);
		nsec3_first->prev = last_node;
	}

	fclose(f);

	return zone;
}

