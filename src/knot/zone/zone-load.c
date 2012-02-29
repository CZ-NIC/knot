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

#include <config.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "common/crc.h"
#include "libknot/common.h"
#include "knot/other/debug.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone-dump.h"
#include "libknot/libknot.h"

/*!
 * \brief Compares two time_t values.
 *
 * \param x First time_t value to be compared.
 * \param y Second time_t value to be compared.
 *
 * \retval 0 when times are the some.
 * \retval 1 when y < x.
 * \retval -1 when x > y.
 */
static int timet_cmp(time_t x, time_t y)
{
	/* Calculate difference in the scale of seconds. */
	long diff = x - y;

	/* X and Y are equal. */
	if (diff == 0) {
		return 0;
	}

	/* X is newer. */
	if (diff > 0) {
		return 1;
	}

	/* Y is newer. */
	return -1;
}

/*!
 * \brief Safe wrapper around fread.
 *
 * \param dst Destination pointer.
 * \param size Size of element to be read.
 * \param n Number of elements to be read.
 * \param fp File to read from.
 *
 * \retval > 0 if succesfull.
 * \retval 0 if failed.
 */
static inline int fread_safe_from_file(void *dst,
                                       size_t size, size_t n, FILE *fp)
{
	int rc = fread(dst, size, n, fp);
	if (rc != n) {
		fprintf(stderr, "fread: invalid read %d (expected %zu)\n", rc,
			n);
	}

	return rc == n;
}

static uint8_t *knot_zload_stream = NULL;
static size_t knot_zload_stream_remaining = 0;
static size_t knot_zload_stream_size = 0;

static inline int read_from_stream(void *dst,
                                   size_t size, size_t n, FILE *fp)
{
	if (knot_zload_stream_remaining < (size * n)) {
		return 0;
	}

	memcpy(dst,
	       knot_zload_stream +
	       (knot_zload_stream_size - knot_zload_stream_remaining),
	       size * n);
	knot_zload_stream_remaining -= size * n;

	return 1;
}

static int (*fread_wrapper)(void *dst, size_t size, size_t n, FILE *fp);

/*! \note Contents of dump file:
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

enum { DNAME_MAX_WIRE_LENGTH = 256 };

/*!
 * \brief Helper function. Frees rdata items and temporary array of items.
 *
 * \param rdata Rdata to be freed.
 * \param items Items to be freed.
 * \param count Current count of rdata items.
 * \param type RRSet type.
 */
static void load_rdata_purge(knot_rdata_t *rdata,
			     knot_rdata_item_t *items,
			     int count,
			     knot_rrtype_descriptor_t *desc,
			     uint16_t type)
{
	/* Increase refcount manually, as the set_items() doesn't see the dname
	 * type and thus is unable to increment refcounter.
	 */
	for (int i = 0; i < count; ++i) {
		switch(desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:
				knot_dname_retain(items[i].dname);
			break;
		default:
			break;
		}
	}

	/* Copy items to rdata and free the temporary rdata. */
	knot_rdata_set_items(rdata, items, count);
	knot_rdata_deep_free(&rdata, type, 1);
	free(items);
}

static knot_dname_t *read_dname_with_id(FILE *f)
{
	knot_dname_t *ret = knot_dname_new();
	CHECK_ALLOC_LOG(ret, NULL);

	/* Read ID. */
	uint32_t dname_id = 0;
	if (!fread_wrapper(&dname_id, sizeof(dname_id), 1, f)) {
		knot_dname_release(ret);
		return NULL;
	}

	ret->id = dname_id;
	dbg_zload("loaded: dname id: %u\n", dname_id);

	/* Read size of dname. */
	uint32_t dname_size = 0;
	if (!fread_wrapper(&dname_size, sizeof(dname_size), 1, f)) {
		knot_dname_release(ret);
		return NULL;
	}
	ret->size = dname_size;
	dbg_zload("loaded: dname length: %u\n", ret->size);

	assert(ret->size <= DNAME_MAX_WIRE_LENGTH);

	/* Read wireformat of dname. */
	ret->name = malloc(sizeof(uint8_t) * ret->size);
	if (ret->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_release(ret);
		return NULL;
	}

	if (!fread_wrapper(ret->name, sizeof(uint8_t), ret->size, f)) {
		knot_dname_release(ret);
		return NULL;
	}

	/* Read labels. */
	uint16_t label_count = 0;
	if (!fread_wrapper(&label_count, sizeof(label_count), 1, f)) {
		knot_dname_release(ret);
		return NULL;
	}

	ret->label_count = label_count;

	ret->labels = malloc(sizeof(uint8_t) * ret->label_count);
	if (ret->labels == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_release(ret);
		return NULL;
	}

	if (!fread_wrapper(ret->labels, sizeof(uint8_t), ret->label_count, f)) {
		free(ret->name);
		free(ret);
		return NULL;
	}

	dbg_zload("loaded: %s (id: %d)\n", knot_dname_to_str(ret),
			 ret->id);

	return ret;
}

/*!
 * \brief Load rdata in binary format from file.
 *
 * \param type Type of RRSet containing read rdata.
 * \param f File to read binary data from.
 *
 * \return Pointer to read and created rdata on success, NULL otherwise.
 */
static knot_rdata_t *knot_load_rdata(uint16_t type, FILE *f,
                                         knot_dname_t **id_array,
                                         int use_ids)
{
	knot_rdata_t *rdata = knot_rdata_new();
	if (rdata == NULL) {
		return NULL;
	}

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);


	/* First, should read rdata count. */

	uint32_t rdata_count = 0;

	if(!fread_wrapper(&rdata_count, sizeof(rdata_count), 1, f)) {
		knot_rdata_free(&rdata);
		return NULL;
	}

	knot_rdata_item_t *items =
		malloc(sizeof(knot_rdata_item_t) * rdata_count);

	if (desc->fixed_items) {
		assert(desc->length == rdata_count);
	}

	uint16_t raw_data_length;

	dbg_zload("Reading %d items\n", rdata_count);

	dbg_zload("current type: %s\n", knot_rrtype_to_string(type));

	for (int i = 0; i < rdata_count; i++) {
		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME )	{

			/*!< \todo #1686
			 * Refactor these variables, some might be too big.
			 */

			uint32_t dname_id = 0;
			uint8_t has_wildcard = 0;
			uint8_t in_the_zone = 0;

			if (use_ids) {
				if(!fread_wrapper(&dname_id, sizeof(dname_id), 1, f)) {
					load_rdata_purge(rdata, items, i, desc, type);
					return NULL;
				}

				/* Store reference do dname. */
				knot_dname_retain(id_array[dname_id]);
				items[i].dname = id_array[dname_id];
			} else {
				items[i].dname = read_dname_with_id(f);
			}

			if(!fread_wrapper(&in_the_zone, sizeof(in_the_zone),
			               1, f)) {
				load_rdata_purge(rdata, items, i, desc, type);
				return NULL;
			}

			if(!fread_wrapper(&has_wildcard, sizeof(uint8_t),
				       1, f)) {
				load_rdata_purge(rdata, items, i, desc, type);
				return NULL;
			}

			if (use_ids && has_wildcard) {
				if(!fread_wrapper(&dname_id, sizeof(dname_id),
					       1, f)) {
					load_rdata_purge(rdata, items,
							 i, desc, type);
					return NULL;
				}
				items[i].dname->node =
						id_array[dname_id]->node;
			} else if (use_ids && !in_the_zone) { /* destroy the node */
				if (id_array[dname_id]->node != NULL) {
					knot_node_free(&id_array[dname_id]->
							 node, 0);
				}
				/* Also sets node to NULL! */
			}
			assert(items[i].dname);
		} else {
			if (!fread_wrapper(&raw_data_length,
					sizeof(raw_data_length), 1, f)) {
				load_rdata_purge(rdata, items, i, desc, type);
				return NULL;
			}
			
			/*!< \todo this is not proper fix, see #1678 */
			items[i].raw_data = (uint16_t *)
				malloc(sizeof(uint8_t) * (raw_data_length + 2));
			items[i].raw_data[0] = raw_data_length;

			if (!fread_wrapper(items[i].raw_data + 1, sizeof(uint8_t),
			      raw_data_length, f)) {
				load_rdata_purge(rdata, items, i + 1, desc, type);
				return NULL;
			}
			dbg_zload("read raw_data len %d\n", raw_data_length);
		}
	}

	/* Each item has refcount already incremented for saving in rdata. */
	if (knot_rdata_set_items(rdata, items, rdata_count) != 0) {
		fprintf(stderr, "zoneload: Could not set items "
			"when loading rdata.\n");
	}

	free(items);

	dbg_zload("knot_load_rdata: all %d items read\n",
			 desc->length);

	assert(rdata->count == rdata_count);

	rdata->count = rdata_count;

	return rdata;
}

/*!
 * \brief Loads RRSIG from binary file.
 *
 * \param f File to read from.
 *
 * \return pointer to created and read RRSIG on success, NULL otherwise.
 */
static knot_rrset_t *knot_load_rrsig(FILE *f, knot_dname_t **id_array,
                                         int use_ids)
{
	knot_rrset_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint32_t rdata_count;

	if (!fread_wrapper(&rrset_type, sizeof(rrset_type), 1, f)) {
		return NULL;
	}

	if (rrset_type != KNOT_RRTYPE_RRSIG) {
		fprintf(stderr, "!! Error: rrsig has wrong type\n");
		return NULL;
	}
	dbg_zload("rrset type: %d\n", rrset_type);
	if (!fread_wrapper(&rrset_class, sizeof(rrset_class), 1, f)) {
		return NULL;
	}
	dbg_zload("rrset class %d\n", rrset_class);

	if (!fread_wrapper(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return NULL;
	}
	dbg_zload("rrset ttl %d\n", rrset_ttl);

	if (!fread_wrapper(&rdata_count, sizeof(rdata_count), 1, f)) {
		return NULL;
	}

	rrsig = knot_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	knot_rdata_t *tmp_rdata;

	dbg_zload("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = knot_load_rdata(KNOT_RRTYPE_RRSIG, f,
					      id_array, use_ids);
		if (tmp_rdata) {
			knot_rrset_add_rdata(rrsig, tmp_rdata);
		} else {
			knot_rrset_deep_free(&rrsig, 0, 1, 1);
			return NULL;
		}
	}

	return rrsig;
}

/*!
 * \brief Loads RRSet from binary file.
 *
 * \param f File to read from.
 *
 * \return pointer to created and read RRSet on success, NULL otherwise.
 */
static knot_rrset_t *knot_load_rrset(FILE *f, knot_dname_t **id_array,
                                         int use_ids)
{
	knot_rrset_t *rrset = NULL;

	uint16_t rrset_type = 0;
	uint16_t rrset_class = 0;
	uint32_t rrset_ttl = 0;

	uint32_t rdata_count = 0;
	uint8_t rrsig_count = 0;

	knot_dname_t *owner = NULL;

	if (!use_ids) {
		dbg_zload("Loading owner of new RRSet from wire.\n");
		owner = read_dname_with_id(f);
	}

	if (!fread_wrapper(&rrset_type, sizeof(rrset_type), 1, f)) {
		if (!use_ids) {
			knot_dname_free(&owner);
		}
		return NULL;
	}
	dbg_zload("Zone load: rrset load: type: %u\n", rrset_type);
	if (!fread_wrapper(&rrset_class, sizeof(rrset_class), 1, f)) {
		if (!use_ids) {
			knot_dname_free(&owner);
		}
		return NULL;
	}
	dbg_zload("Zone load: rrset class: type: %u\n", rrset_class);
	if (!fread_wrapper(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		if (!use_ids) {
			knot_dname_free(&owner);
		}
		return NULL;
	}
	dbg_zload("Zone load: rrset ttl: type: %u\n", rrset_ttl);
	if (!fread_wrapper(&rdata_count, sizeof(rdata_count), 1, f)) {
		if (!use_ids) {
			knot_dname_free(&owner);
		}
		return NULL;
	}
	dbg_zload("Zone load: rrset load: rdata count: %u\n", rdata_count);
	if (!fread_wrapper(&rrsig_count, sizeof(rrsig_count), 1, f)) {
		if (!use_ids) {
			knot_dname_free(&owner);
		}
		return NULL;
	}
	dbg_zload("Zone load: rrset load: type: %u\n", rrset_type);

dbg_zload_exec_detail(
	char *name = knot_dname_to_str(owner);
	dbg_zload("Loading RRSet owned by: %s\n",
	          name);
	free(name);
);

	rrset = knot_rrset_new(owner, rrset_type, rrset_class, rrset_ttl);
	
	if (rrset == NULL) {
		dbg_zload("zload: load_rrset: Could not create rrset.");
		knot_dname_free(&owner);
		return NULL;
	}

	if (!use_ids) {
		/* Directly release if allocated locally. */
		knot_dname_release(owner);
		owner = NULL;
	}

	dbg_zload("RRSet type: %d\n", rrset->type);

	knot_rdata_t *tmp_rdata = NULL;

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = knot_load_rdata(rrset->type, f,
					      id_array, use_ids);
		if (tmp_rdata) {
			knot_rrset_add_rdata(rrset, tmp_rdata);
		} else {
			knot_rrset_deep_free(&rrset, 0, 1, 1);
			return NULL;
		}
	}

	knot_rrset_t *tmp_rrsig = NULL;

	dbg_zload("Reading: %d RRSIGs\n", rrsig_count);
	if (rrsig_count) {
		tmp_rrsig = knot_load_rrsig(f, id_array, use_ids);
		if (!use_ids) {
			knot_rrset_set_owner(tmp_rrsig, rrset->owner);
		}
	}

	knot_rrset_set_rrsigs(rrset, tmp_rrsig);

	dbg_zload("Finished loading RRSet %p\n", rrset);

	return rrset;
}

/*!
 * \brief Loads node from binary file.
 *
 * \param f File to read from.
 *
 * \return Pointer to created and read node on success, NULL otherwise.
 */
static knot_node_t *knot_load_node(FILE *f, knot_dname_t **id_array)
{
	uint8_t flags = 0;
	knot_node_t *node = NULL;
	uint32_t parent_id = 0;
	uint32_t nsec3_node_id = 0;
	uint16_t rrset_count = 0;
	uint32_t dname_id = 0;

	/* At the beginning of node - just dname_id !!!.*/
	if (!fread_wrapper(&dname_id, sizeof(dname_id), 1, f)) {
		return NULL;
	}

	if (!fread_wrapper(&parent_id, sizeof(parent_id), 1, f)) {
		return NULL;
	}

	if (!fread_wrapper(&flags, sizeof(flags), 1, f)) {
		return NULL;
	}

	if (!fread_wrapper(&nsec3_node_id, sizeof(nsec3_node_id), 1, f)) {
		return NULL;
	}

	if (!fread_wrapper(&rrset_count, sizeof(rrset_count), 1, f)) {
		return NULL;
	}
	knot_dname_t *owner = id_array[dname_id];

	dbg_zload("Node owner id: %d\n", dname_id);
	dbg_zload("Node owned by: %s\n", knot_dname_to_str(owner));
	dbg_zload("Number of RRSets in a node: %d\n", rrset_count);

	node = owner->node;

	if (node == NULL) {
		fprintf(stderr, "zone: Could not create node.\n");
		return NULL;
	}
	/* XXX can it be 0, ever? I think not. */
	if (nsec3_node_id != 0) {
		knot_node_set_nsec3_node(node, id_array[nsec3_node_id]->node);
		/* CLEANUP */
//		node->nsec3_node = id_array[nsec3_node_id]->node;
	} else {
		knot_node_set_nsec3_node(node, NULL);
		/* CLEANUP */
//		node->nsec3_node = NULL;
	}

	/* Retain new owner while releasing replaced owner. */
	knot_node_set_owner(node, owner);
	node->flags = flags;

	//XXX will have to be set already...canonical order should do it

	if (parent_id != 0) {
		knot_node_set_parent(node, id_array[parent_id]->node);
		assert(knot_node_parent(node) != NULL);
	} else {
		knot_node_set_parent(node, NULL);
	}

	knot_rrset_t *tmp_rrset;

	for (int i = 0; i < rrset_count; i++) {
		if ((tmp_rrset = knot_load_rrset(f, id_array, 1)) == NULL) {
			knot_node_free(&node, 0);
			/*!< \todo #1686 
			 * Refactor freeing, might not be enough.
			 */
			fprintf(stderr, "zone: Could not load rrset.\n");
			return NULL;
		}
		/* Retain new owner while releasing replaced owner. */
		knot_rrset_set_owner(tmp_rrset, node->owner);
		if (tmp_rrset->rrsigs != NULL) {
			knot_rrset_set_owner(tmp_rrset->rrsigs, node->owner);
		}
		if (knot_node_add_rrset(node, tmp_rrset, 0) < 0) {
			fprintf(stderr, "zone: Could not add rrset.\n");
			return NULL;
		}
	}
	assert(node != NULL);
	dbg_zload("Node loaded: %p\n", node);
	return node;
}

/*!
 * \brief Finds and sets wildcard child for given node's owner.
 *
 * \param zone Current zone.
 * \param node Node to be used.
 * \param nsec3 Is NSEC3 node.
 */
static void find_and_set_wildcard_child(knot_zone_contents_t *zone,
				 knot_node_t *node, int nsec3)
{
	knot_dname_t *chopped = knot_dname_left_chop(node->owner);
	knot_node_t *wildcard_parent;
	if (!nsec3) {
		wildcard_parent =
			knot_zone_contents_get_node(zone, chopped);
	} else {
		wildcard_parent =
			knot_zone_contents_get_nsec3_node(zone, chopped);
	}

	/* Directly discard. */
	knot_dname_free(&chopped);

	assert(wildcard_parent); /* it *has* to be there */

	knot_node_set_wildcard_child(wildcard_parent, node);
}

/*!
 * \brief Checks if magic string at the beginning of the file is the same
 *        as defined.
 *
 * \param f File to read magic string from.
 * \param MAGIC Magic string.
 * \param MAGIC_LENGTH Length of magic string.
 *
 * \retval 1 if magic is the same.
 * \retval 0 otherwise.
 */
static int knot_check_magic(FILE *f, const uint8_t* MAGIC, uint MAGIC_LENGTH)
{
	uint8_t tmp_magic[MAGIC_LENGTH];

	if (!fread_wrapper(&tmp_magic, sizeof(uint8_t), MAGIC_LENGTH, f)) {
		return 0;
	}

	for (int i = 0; i < MAGIC_LENGTH; i++) {
		if (tmp_magic[i] != MAGIC[i]) {
			return 0;
		}
	}

	return 1;
}

static unsigned long calculate_crc(FILE *f)
{
	crc_t crc = crc_init();
	/* Get file size. */
	fseek(f, 0L, SEEK_END);
	size_t file_size = ftell(f);
	fseek(f, 0L, SEEK_SET);

	const size_t chunk_size = 1024;
	/* read chunks of 1 kB */
	size_t read_bytes = 0;
	/* Prealocate chunk */
	unsigned char *chunk = malloc(sizeof(unsigned char) * chunk_size);
	CHECK_ALLOC_LOG(chunk, 0);
	while ((file_size - read_bytes) > chunk_size) {
		if (!fread_wrapper(chunk, sizeof(unsigned char), chunk_size, f)) {
			free(chunk);
			return 0;
		}
		crc = crc_update(crc, chunk,
		                 sizeof(unsigned char) * chunk_size);
		read_bytes += chunk_size;
	}

	/* Read the rest of the file */
	if (!fread_wrapper(chunk, sizeof(unsigned char), file_size - read_bytes,
	                f)) {
		free(chunk);
		return 0;
	}

	crc = crc_update(crc, chunk,
	                 sizeof(unsigned char) * (file_size - read_bytes));
	free(chunk);

	fseek(f, 0L, SEEK_SET);
	return (unsigned long)crc_finalize(crc);
}

int knot_zload_open(zloader_t **dst, const char *filename)
{
	if (!dst || !filename) {
		return KNOT_EBADARG;
	}

	*dst = 0;

	fread_wrapper = fread_safe_from_file;

	/* Open file for binary read. */
	FILE *f = fopen(filename, "rb");
	if (unlikely(!f)) {
		dbg_zload("knot_zload_open: failed to open '%s'\n",
				   filename);
		return KNOT_EFEWDATA; // No such file or directory (POSIX.1)
	}

	/* Calculate CRC and compare with filename.crc file */
	unsigned long crc_calculated = calculate_crc(f);

	/* Read CRC from filename.crc file */
	char *crc_path =
		malloc(sizeof(char) * (strlen(filename) + strlen(".crc") + 1));
	if (unlikely(!crc_path)) {
		fclose(f);
		return KNOT_ENOMEM;
	}
	memset(crc_path, 0,
	       sizeof(char) * (strlen(filename) + strlen(".crc") + 1));

	memcpy(crc_path, filename, sizeof(char) * strlen(filename));

	crc_path = strncat(crc_path, ".crc", strlen(".crc"));
	FILE *f_crc = fopen(crc_path, "r");
	if (unlikely(!f_crc)) {
		dbg_zload("knot_zload_open: failed to open '%s'\n",
		                   crc_path);
		fclose(f);
		free(crc_path);
		return KNOT_ECRC;
	}

	unsigned long crc_from_file = 0;
	if (fscanf(f_crc, "%64lu\n", &crc_from_file) != 1) {
		dbg_zload("knot_zload_open: could not read "
		                   "CRC from file '%s'\n",
		                   crc_path);
		fclose(f_crc);
		fclose(f);
		free(crc_path);
		return KNOT_ERROR;
	}
	free(crc_path);
	fclose(f_crc);

	/* Compare calculated and read CRCs. */
	if (crc_from_file != crc_calculated) {
		dbg_zload("knot_zload_open: CRC failed for "
		                   "file '%s'\n",
		                   filename);
		fclose(f);
		return KNOT_ECRC;
	}

	/* Check magic sequence. */
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	if (!knot_check_magic(f, MAGIC, MAGIC_LENGTH)) {
		fclose(f);
		dbg_zload("knot_zload_open: magic bytes "
				   "in don't match '%*s' "
			 "(%s)\n",
			 (int)MAGIC_LENGTH, (const char*)MAGIC, filename);
		return KNOT_EMALF; // Illegal byte sequence (POSIX.1, C99)
	}

	/* Read source file length. */
	uint32_t sflen = 0;
	if (!fread_wrapper(&sflen, 1, sizeof(uint32_t), f)) {
		dbg_zload("knot_zload_open: failed to read "
				   "sfile length\n");
		fclose(f);
		return KNOT_ERROR;
	}

	/* Read source file. */
	char *sfile = malloc(sflen);
	if (!sfile) {
		dbg_zload("knot_zload_open: invalid sfile "
				   "length %u\n", sflen);
		fclose(f);
		return KNOT_ENOMEM;
	}
	if (!fread_wrapper(sfile, 1, sflen, f)) {
		dbg_zload("knot_zload_open: failed to read %uB "
				   "source file\n",
			 sflen);
		free(sfile);
		fclose(f);
		return KNOT_ERROR;
	}

	/* Allocate new loader. */
	zloader_t *zl = malloc(sizeof(zloader_t));
	if (!zl) {
		free(sfile);
		fclose(f);
		return KNOT_ENOMEM;
	}

	dbg_zload("knot_zload_open: opened '%s' as fp %p "
			   "(source is '%s')\n",
		 filename, f, sfile);
	zl->filename = strdup(filename);
	zl->source = sfile;
	zl->fp = f;
	*dst = zl;

	return KNOT_EOK;
}

static void cleanup_id_array(knot_dname_t **id_array,
			     const uint from, const uint to)
{
	for (uint i = from; i < to; i++) {
		knot_dname_release(id_array[i]);
	}

	free(id_array);
}

//static knot_dname_table_t *create_dname_table(FILE *f, uint max_id)
//{
//	if (f == NULL ) {
//		return NULL;
//	}

//	if (!fread_wrapper(&max_id, sizeof(max_id), 1, f)) {
//		return NULL;
//	}

//	knot_dname_table_t *dname_table = knot_dname_table_new();
//	if (dname_table == NULL) {
//		return NULL;
//	}

//	/* Create nodes containing dnames. */
//	for (uint i = 1; i < max_id; i++) {
//		knot_dname_t *loaded_dname = read_dname_with_id(f);
//		if (loaded_dname == NULL) {
//			knot_dname_table_deep_free(&dname_table);
//			return NULL;
//		}
//		if (knot_dname_table_add_dname(dname_table,
//		                                 loaded_dname) != KNOT_EOK) {

//		}
//	}

//	return dname_table;
//}

static knot_dname_table_t *create_dname_table_from_array(
	knot_dname_t **array, uint max_id)
{
	if (array == NULL) {
		/* should I set errno or what ... ? */
		dbg_zload("No array passed\n");
		return NULL;
	}

	assert(array[0] == NULL);

	knot_dname_table_t *ret = knot_dname_table_new();
	CHECK_ALLOC_LOG(ret, NULL);

	/* Table will have max_id entries */
	for (uint i = 1; i < max_id; i++) {
		assert(array[i]);
		if (knot_dname_table_add_dname(ret,
						 array[i]) != KNOT_EOK) {
			dbg_zload("Could not add: %s\n",
			                   knot_dname_to_str(array[i]));
			knot_dname_table_deep_free(&ret);
			return NULL;
		}
	}

	return ret;
}

static knot_dname_t **create_dname_array(FILE *f, uint max_id)
{
	if (f == NULL) {
		return NULL;
	}

	knot_dname_t **array =
		malloc(sizeof(knot_dname_t *) * ( max_id + 1));
	if (array == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	memset(array, 0, sizeof(knot_dname_t *) * (max_id + 1));	

	for (uint i = 0; i < max_id - 1; i++) {
		knot_dname_t *read_dname = read_dname_with_id(f);
		if (read_dname == NULL) {
			cleanup_id_array(array, 0, i);
			return NULL;
		}

		if (read_dname->id < max_id) {

			/* Create new node from dname. */
			read_dname->node = knot_node_new(read_dname, NULL, 0);

			if (read_dname->node == NULL) {
				ERR_ALLOC_FAILED;

				/* Release read dname. */
				knot_dname_release(read_dname);
				cleanup_id_array(array, 0, i);
				return NULL;
			}

			/* Store reference to dname in array. */
			array[read_dname->id] = read_dname;
		} else {
			/* Release read dname. */
			knot_dname_release(read_dname);
			cleanup_id_array(array, 0, i);
			return NULL;
		}

	}

	return array;
}

knot_zone_t *knot_zload_load(zloader_t *loader)
{
	dbg_zload("Loading zone, loader: %p\n", loader);
	if (!loader) {
		dbg_zload("NULL loader!\n");
		return NULL;
	}

	fread_wrapper = fread_safe_from_file;

	FILE *f = loader->fp;

	knot_node_t *tmp_node;

	uint32_t node_count;
	uint32_t nsec3_node_count;
	uint32_t auth_node_count;

	if (!fread_wrapper(&node_count, sizeof(node_count), 1, f)) {
		dbg_zload("wrong read!\n");
		return NULL;
	}

	if (!fread_wrapper(&nsec3_node_count, sizeof(nsec3_node_count), 1, f)) {
		dbg_zload("wrong read!\n");
		return NULL;
	}
	if (!fread_wrapper(&auth_node_count,
	      sizeof(auth_node_count), 1, f)) {
		dbg_zload("wrong read!\n");
		return NULL;
	}
	dbg_zload("authoritative nodes: %u\n", auth_node_count);

	dbg_zload("loading %u nodes\n", node_count);

	uint32_t total_dnames = 0;
	/* First, read number of dnames in dname table. */
	if (!fread_wrapper(&total_dnames, sizeof(total_dnames), 1, f)) {
		return NULL;
	}

	dbg_zload("total dname count: %d\n", total_dnames);

	/* Create id array. */
	knot_dname_t **id_array = create_dname_array(f, total_dnames);
	if (id_array == NULL) {
		return NULL;
	}

	knot_dname_table_t *dname_table =
		create_dname_table_from_array(id_array, total_dnames);
	if (dname_table == NULL) {
		ERR_ALLOC_FAILED;
		cleanup_id_array(id_array, 1, total_dnames);
		free(dname_table);
		return NULL;
	}

	knot_node_t *apex = knot_load_node(f, id_array);

	if (!apex) {
		fprintf(stderr, "zone: Could not load apex node (in %s)\n",
			loader->filename);
		cleanup_id_array(id_array, 1,
				 node_count + nsec3_node_count + 1);
		free(dname_table);
		return NULL;
	}

	dbg_zload("Apex node loaded: %p\n", apex);

	knot_zone_t *zone = knot_zone_new(apex, auth_node_count, 0);
	if (zone == NULL) {
		cleanup_id_array(id_array, 1,
				 node_count + nsec3_node_count + 1);
		dbg_zload("Failed to create new zone from apex!\n");
		knot_node_free(&apex, 0);
		free(dname_table);
		return NULL;
	}

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	assert(contents);

	/* Assign dname table to the new zone. */
	contents->dname_table = dname_table;

	knot_node_set_previous(apex, NULL);

	knot_node_t *last_node = 0;

	last_node = apex;

	for (uint i = 1; i < node_count; i++) {
		tmp_node = knot_load_node(f, id_array);

		if (tmp_node != NULL) {
			if (knot_zone_contents_add_node(contents, tmp_node,
			                                  0, 0, 0) != 0) {
				fprintf(stderr, "!! cannot add node\n");
				continue;
			}
			if (knot_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(contents,
				                            tmp_node, 0);
			}

			knot_node_set_previous(tmp_node, last_node);

			if (tmp_node->rrset_count &&
			    (knot_node_is_deleg_point(tmp_node) ||
			    !knot_node_is_non_auth(tmp_node))) {
				last_node = tmp_node;
			}

		} else {
			fprintf(stderr, "zone: Node error (in %s).\n",
				loader->filename);
		}
	}

	assert(knot_node_previous(knot_zone_contents_apex(contents)) == NULL);

	knot_node_set_previous(knot_zone_contents_get_apex(contents),
	                         last_node);

	dbg_zload("loading %u nsec3 nodes\n", nsec3_node_count);

	knot_node_t *nsec3_first = NULL;

	if (nsec3_node_count > 0) {
		nsec3_first = knot_load_node(f, id_array);

		assert(nsec3_first != NULL);

		if (knot_zone_contents_add_nsec3_node(contents, nsec3_first, 0, 0, 0)
		    != 0) {
			fprintf(stderr, "!! cannot add first nsec3 node, "
				"exiting.\n");
			knot_zone_deep_free(&zone, 0);
			cleanup_id_array(id_array, node_count + 1,
					 nsec3_node_count + 1);
			return NULL;
		}

		knot_node_set_previous(nsec3_first, NULL);
		last_node = nsec3_first;
	}

	for (uint i = 1; i < nsec3_node_count; i++) {
		tmp_node = knot_load_node(f, id_array);

		if (tmp_node != NULL) {
			if (knot_zone_contents_add_nsec3_node(contents,
			    tmp_node, 0, 0, 0) != 0) {
				fprintf(stderr, "!! cannot add nsec3 node\n");
				continue;
			}

			knot_node_set_previous(tmp_node, last_node);

			last_node = tmp_node;
		} else {
			fprintf(stderr, "zone: Node error (in %s).\n",
				loader->filename);
		}
	}

	if (nsec3_node_count) {
		assert(knot_node_previous(nsec3_first) == NULL);
		knot_node_set_previous(nsec3_first, last_node);
	}

	/* ID array is now useless */
	for (uint i = 1; i < total_dnames; i++) {
		/* Added to table, may discard now. */
		knot_dname_release(id_array[i]);
	}
	free(id_array);

	dbg_zload("zone loaded, returning: %p\n", zone);
	
	return zone;
}

int knot_zload_needs_update(zloader_t *loader)
{
	if (!loader) {
		return 1;
	}

	/* Check if the source still exists. */
	struct stat st_src;
	if (stat(loader->source, &st_src) != 0) {
		return 1;
	}

	/* Check if the compiled file still exists. */
	struct stat st_bin;
	if (stat(loader->filename, &st_bin) != 0) {
		return 1;
	}

	/* Compare the mtime of the source and file. */
	/*! \todo Inspect types on Linux. */
	if (timet_cmp(st_bin.st_mtime, st_src.st_mtime) < 0) {
		return 1;
	}

	return 0;
}

void knot_zload_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	free(loader->filename);
	free(loader->source);
	fclose(loader->fp);
	free(loader);
}

int knot_zload_rrset_deserialize(knot_rrset_t **rrset,
                                   uint8_t *stream, size_t *size)
{
	if (stream == NULL || size == 0) {
		return KNOT_EBADARG;
	}

	fread_wrapper = read_from_stream;

	knot_zload_stream = stream;
	knot_zload_stream_remaining = knot_zload_stream_size = *size;

	knot_rrset_t *ret = knot_load_rrset(NULL, NULL, 0);

	if (ret == NULL) {
		knot_zload_stream = NULL;
		knot_zload_stream_remaining = 0;
		knot_zload_stream_size = 0;
		return KNOT_EMALF;
	}

	*size = knot_zload_stream_remaining;
	*rrset = ret;

	knot_zload_stream = NULL;
	knot_zload_stream_remaining = 0;
	knot_zload_stream_size = 0;

	return KNOT_EOK;
}

