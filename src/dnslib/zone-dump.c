#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "common.h"
#include "dnslib/zone-dump.h"
#include "dnslib/dnslib.h"
#include "lib/skip-list.h"

/* \note For space and speed purposes, dname ID (to be later used in loading)
 * is being stored in dname->node field. Not to be confused with dname's actual
 * node.
 */

/* \note Contents of dump file:
 * MAGIC(knotxx) NUMBER_OF_NORMAL_NODES NUMBER_OF_NSEC3_NODES
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

struct arg {
	void *arg1; /* FILE *f / zone */
	void *arg2; /* skip_list_t */
	void *arg3; /* zone */
};

typedef struct arg arg_t;

/* we only need ordering for search purposes, therefore it is OK to compare
 * pointers directly */
static int compare_pointers(void *p1, void *p2)
{
	return ((size_t)p1 == (size_t)p2 ? 0 : (size_t)p1 < (size_t)p2 ? -1 : 1);
}

/* Functions for zone traversal are taken from dnslib/zone.c */
static void dnslib_zone_save_encloser_rdata_item(dnslib_rdata_t *rdata,
                                                 dnslib_zone_t *zone, uint pos,
					         skip_list_t *list)
{
	const dnslib_rdata_item_t *dname_item
		= dnslib_rdata_item(rdata, pos);

	if (dname_item != NULL) {
		dnslib_dname_t *dname = dname_item->dname;
		const dnslib_node_t *n = NULL;
		const dnslib_node_t *closest_encloser = NULL;
		const dnslib_node_t *prev = NULL;

		int exact = dnslib_zone_find_dname(zone, dname, &n,
		                                   &closest_encloser, &prev);

//		n = dnslib_zone_find_node(zone, dname);

		assert(!exact || n == closest_encloser);

		if (!exact && (closest_encloser != NULL)) {
			debug_dnslib_zone("Saving closest encloser to RDATA.\n");
			// save pointer to the closest encloser
			dnslib_rdata_item_t *item =
				dnslib_rdata_get_item(rdata, pos);
			assert(item->dname != NULL);
			assert(item->dname->node == NULL);
			skip_insert(list, (void *)item->dname,
				    (void *)closest_encloser->owner, NULL);
		}
	}
}

static void dnslib_zone_save_enclosers_node(dnslib_node_t *node,
                                            dnslib_rr_type_t type,
                                            dnslib_zone_t *zone,
					    skip_list_t *list)
{
	dnslib_rrset_t *rrset = dnslib_node_get_rrset(node, type);
	if (!rrset) {
		return;
	}

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	dnslib_rdata_t *rdata_first = dnslib_rrset_get_rdata(rrset);
	dnslib_rdata_t *rdata = rdata_first;

	if (rdata == NULL) {
		return;
	}

	while (rdata->next != rdata_first) {
		for (int i = 0; i < rdata->count; ++i) {
			if (desc->wireformat[i]
			    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
				debug_dnslib_zone("Adjusting domain name at "
				  "position %d of RDATA of record with owner "
				  "%s and type %s.\n",
				  i, rrset->owner->name,
				  dnslib_rrtype_to_string(type));

				dnslib_zone_save_encloser_rdata_item(rdata,
				                                     zone,
								     i,
								     list);
			}
		}
		rdata = rdata->next;
	}

	for (int i = 0; i < rdata->count; ++i) {
		if (desc->wireformat[i]
		    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			debug_dnslib_zone("Adjusting domain name at "
			  "position %d of RDATA of record with owner "
			  "%s and type %s.\n",
			  i, rrset->owner->name,
			  dnslib_rrtype_to_string(type));

				dnslib_zone_save_encloser_rdata_item(rdata,
				                                     zone,
								     i,
								     list);
		}
	}
}

static void dnslib_zone_save_enclosers_in_tree(dnslib_node_t *node, void *data)
{
	assert(data != NULL);
	arg_t *args = (arg_t *)data;

	for (int i = 0; i < DNSLIB_COMPRESSIBLE_TYPES; ++i) {
		dnslib_zone_save_enclosers_node(node, dnslib_compressible_types[i],
		                                  (dnslib_zone_t *)args->arg1,
					          (skip_list_t *)args->arg2);
	}
}

void dnslib_zone_save_enclosers(dnslib_zone_t *zone, skip_list_t *list)
{
	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg2 = list;

	dnslib_zone_tree_apply_inorder(zone,
	                   dnslib_zone_save_enclosers_in_tree,
			   (void *)&arguments);
}

/* TODO Think of a better way than a global variable */
static uint node_count = 0;

static void dnslib_labels_dump_binary(dnslib_dname_t *dname, FILE *f)
{
	debug_zp("label count: %d\n", dname->label_count);
	fwrite(&(dname->label_count), sizeof(dname->label_count), 1, f);
//	hex_print(dname->labels, dname->label_count);
	fwrite(dname->labels, sizeof(uint8_t), dname->label_count, f);
}

static void dnslib_dname_dump_binary(dnslib_dname_t *dname, FILE *f)
{
	fwrite(&(dname->size), sizeof(uint8_t), 1, f);
	fwrite(dname->name, sizeof(uint8_t), dname->size, f);
	debug_zp("dname size: %d\n", dname->size);
	dnslib_labels_dump_binary(dname, f);
}

static dnslib_dname_t *dnslib_find_wildcard(dnslib_dname_t *dname,
					    skip_list_t *list)
{
	dnslib_dname_t *d = (dnslib_dname_t *)skip_find(list, (void *)dname);
	return d;
}

static void dnslib_rdata_dump_binary(dnslib_rdata_t *rdata,
                                     uint32_t type, void *data)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	skip_list_t *list = (skip_list_t *)((arg_t *)data)->arg2;
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	debug_zp("dumping type: %s\n", dnslib_rrtype_to_string(type));

	for (int i = 0; i < desc->length; i++) {
		if (&(rdata->items[i]) == NULL) {
			debug_zp("Item n. %d is not set!\n", i);
			continue;
		}
		debug_zp("Item n: %d\n", i);
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			/* TODO some temp variables - this is way too long */
			assert(rdata->items[i].dname != NULL);
			dnslib_dname_t *wildcard = NULL;

			if (rdata->items[i].dname->node == NULL) {
				wildcard =
					dnslib_find_wildcard(rdata->items[i].dname,
						     list);
				debug_zp("Not in the zone: %s\n",
				       dnslib_dname_to_str((rdata->items[i].dname)));

				fwrite((uint8_t *)"\0", sizeof(uint8_t), 1, f);
				dnslib_dname_dump_binary(rdata->items[i].dname, f);
				if (wildcard) {
					fwrite((uint8_t *)"\1",
					       sizeof(uint8_t), 1, f);
					fwrite(&wildcard->node,
					       sizeof(void *), 1, f);
				} else {
					fwrite((uint8_t *)"\0", sizeof(uint8_t), 1, f);
				}
			} else {
				debug_zp("In the zone\n");
				fwrite((uint8_t *)"\1", sizeof(uint8_t), 1, f);
				fwrite(&(rdata->items[i].dname->node),
				       sizeof(void *), 1, f);
			}

		} else {
			assert(rdata->items[i].raw_data != NULL);
			fwrite(rdata->items[i].raw_data, sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 2, f);

			debug_zp("Written %d long raw data\n",
			         rdata->items[i].raw_data[0]);
		}
	}
}

static void dnslib_rrsig_set_dump_binary(dnslib_rrset_t *rrsig, arg_t *data)
{
	assert(rrsig->type == DNSLIB_RRTYPE_RRSIG);
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	fwrite(&rrsig->type, sizeof(rrsig->type), 1, f);
	fwrite(&rrsig->rclass, sizeof(rrsig->rclass), 1, f);
	fwrite(&rrsig->ttl, sizeof(rrsig->ttl), 1, f);

	uint8_t rdata_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	assert(rrsig->rdata);

	dnslib_rdata_t *tmp_rdata = rrsig->rdata;

	while (tmp_rdata->next != rrsig->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, data);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, data);
	rdata_count++;

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	fsetpos(f, &tmp_pos);
}

static void dnslib_rrset_dump_binary(dnslib_rrset_t *rrset, void *data)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;

	fwrite(&rrset->type, sizeof(rrset->type), 1, f);
	fwrite(&rrset->rclass, sizeof(rrset->rclass), 1, f);
	fwrite(&rrset->ttl, sizeof(rrset->ttl), 1, f);

	uint8_t rdata_count = 0;
	uint8_t rrsig_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);

	dnslib_rdata_t *tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, rrset->type, data);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, rrset->type, data);
	rdata_count++;

	/* This is now obsolete, although I'd rather not use recursion - that
	 * would probably not work */

	if (rrset->rrsigs != NULL) {
		dnslib_rrsig_set_dump_binary(rrset->rrsigs, data);
		rrsig_count = 1;
	}

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);

	fsetpos(f, &tmp_pos);
}

static void dnslib_node_dump_binary(dnslib_node_t *node, void *data)
{
	arg_t *args = (arg_t *)data;

	dnslib_zone_t *zone = (dnslib_zone_t *)args->arg3;

	FILE *f = (FILE *)args->arg1;


	node_count++;
	/* first write dname */
	assert(node->owner != NULL);

	if (!dnslib_node_is_non_auth(node)) {
		zone->node_count++;
	}

	dnslib_dname_dump_binary(node->owner, f);

	fwrite(&(node->owner->node), sizeof(void *), 1, f);

	debug_zp("Written id: %p\n", node->owner->node);

	/* TODO investigate whether this is necessary */
	if (node->parent != NULL) {
		fwrite(&(node->parent->owner->node), sizeof(void *), 1, f);
	} else {
		fwrite(&(node->parent), sizeof(void *), 1, f);
	}

	fwrite(&(node->flags), sizeof(node->flags), 1, f);

	debug_zp("Written flags: %u\n", node->flags);

	if (node->nsec3_node != NULL) {
		fwrite(&node->nsec3_node->owner->node, sizeof(void *), 1, f);
		debug_zp("Written nsec3 node id: %p\n",
			 node->nsec3_node->owner->node);
	} else {
		fwrite(&node->nsec3_node, sizeof(void *), 1, f);
		debug_zp("Written nsec3 node id: %p\n",
			 node->nsec3_node);
	}

	/* Now we need (or do we?) count of rrsets to be read
	 * but that number is yet unknown */

	fpos_t rrset_count_pos;

	fgetpos(f, &rrset_count_pos);

	debug_zp("Position rrset_count: %ld\n", ftell(f));

	uint8_t rrset_count = 0;

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	const skip_node_t *skip_node = skip_first(node->rrsets);

	if (skip_node == NULL) {
		/* we can return, count is set to 0 */
		return;
	}

	dnslib_rrset_t *tmp;

	do {
		tmp = (dnslib_rrset_t *)skip_node->value;
		rrset_count++;
		dnslib_rrset_dump_binary(tmp, data);
	} while ((skip_node = skip_next(skip_node)) != NULL);

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	debug_zp("Position after all rrsets: %ld\n", ftell(f));

	fsetpos(f, &rrset_count_pos);

	debug_zp("Writing here: %ld\n", ftell(f));

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	fsetpos(f, &tmp_pos);

	debug_zp("Function ends with: %ld\n\n", ftell(f));

}

int dnslib_zdump_binary(dnslib_zone_t *zone, const char *filename,
                        const char *sfilename)
{
	FILE *f;

	f = fopen(filename, "wb");

	if (f == NULL) {
		return -1;
	}

	zone->node_count = 0;

	skip_list_t *encloser_list = skip_create_list(compare_pointers);

	dnslib_zone_save_enclosers(zone, encloser_list);

	/* Start writing header - magic bytes. */
	size_t header_len = MAGIC_LENGTH;
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	fwrite(&MAGIC, sizeof(uint8_t), MAGIC_LENGTH, f);

	/* Write source file length. */
	uint32_t sflen = 0;
	if (sfilename) {
		sflen = strlen(sfilename) + 1;
	}
	fwrite(&sflen, sizeof(uint32_t), 1, f);
	header_len += sizeof(uint32_t);

	/* Write source file. */
	fwrite(sfilename, sflen, 1, f);
	header_len += sflen;

	/* Notice: End of header,
	 * length must be marked for future return.
	 */

	/* Start writing compiled data. */
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&zone->node_count,
	       sizeof(zone->node_count),
	       1, f);

	arg_t arguments;

	arguments.arg1 = f;
	arguments.arg2 = encloser_list;
	arguments.arg3 = zone;

	/* TODO is there a way how to stop the traversal upon error? */
	dnslib_zone_tree_apply_inorder(zone, dnslib_node_dump_binary,
	                               (void *)&arguments);

	uint tmp_count = node_count;

	node_count = 0;
	dnslib_zone_nsec3_apply_inorder(zone, dnslib_node_dump_binary,
	                                (void *)&arguments);

	/* Update counters. */
	fseek(f, header_len, SEEK_SET);
	fwrite(&tmp_count, sizeof(tmp_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&zone->node_count,
	       sizeof(zone->node_count),
	       1, f);

	debug_zp("written %d normal nodes\n", tmp_count);

	debug_zp("written %d nsec3 nodes\n", node_count);

	debug_zp("authorative nodes: %u\n", zone->node_count);

	fclose(f);

	return 0;
}

