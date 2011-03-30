#include <config.h>
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/zone-load.h"
#include "dnslib/zone-dump.h"
#include "dnslib/dnslib.h"
#include "dnslib/debug.h"

static int timespec_cmp(struct timespec *x, struct timespec *y)
{
	/* Calculate difference in the scale of seconds. */
	long diff = x->tv_sec - y->tv_sec;

	/* If it is equal, need to measure nanosecs. */
	if (diff == 0) {
		diff = x->tv_nsec - y->tv_nsec;
	}

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

static inline int fread_safe(void *dst, size_t size, size_t n, FILE *fp)
{
	int rc = fread(dst, size, n, fp);
	if (rc != n) {
		fprintf(stderr, "fread: invalid read %d (expected %zu)\n", rc,
		        n);
	}

	return rc == n;
}

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

	debug_dnslib_zload("Reading %d items\n", desc->length);

	debug_dnslib_zload("current type: %s\n", dnslib_rrtype_to_string(type));

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
				assert(labels != NULL); /* FIXME */
				if(!fread_safe(labels,sizeof(uint8_t),
				               label_count, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					free(labels);
					return 0;
				}

				if(!fread_safe(&has_wildcard, sizeof(uint8_t),
				               1, f)) {
					load_rdata_purge(rdata, items, i, type);
					free(dname_wire);
					free(labels);
					return 0;
				}

				if (has_wildcard) {
					if(!fread_safe(&tmp_id, sizeof(void *),
					               1, f)) {
						load_rdata_purge(rdata, items,
						                 i, type);
						free(dname_wire);
						free(labels);
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

			debug_dnslib_zload("read len: %d\n", raw_data_length);
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
		fprintf(stderr, "zoneload: Could not set items "
		        "when loading rdata.\n");
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
		fprintf(stderr, "!! Error: rrsig has wrong type\n");
		return 0;
	}
	debug_dnslib_zload("rrset type: %d\n", rrset_type);
	if (!fread_safe(&rrset_class, sizeof(rrset_class), 1, f)) {
		return 0;
	}
	debug_dnslib_zload("rrset class %d\n", rrset_class);

	if (!fread_safe(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return 0;
	}
	debug_dnslib_zload("rrset ttl %d\n", rrset_ttl);

	if (!fread_safe(&rdata_count, sizeof(rdata_count), 1, f)) {
		return 0;
	}

	rrsig = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	debug_dnslib_zload("loading %d rdata entries\n", rdata_count);

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

	debug_dnslib_zload("RRSet type: %d\n", rrset->type);

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
	void *dname_id; //ID, technically it's an integer(32 or 64 bits)
	void *parent_id;
	void *nsec3_node_id;

	short label_count = 0;
	uint8_t *labels = NULL;

	if (!fread_safe(&dname_size, sizeof(dname_size), 1, f)) {
		return 0;
	}

	debug_dnslib_zload("%d\n", dname_size);

	if (!fread_safe(dname_wire, sizeof(uint8_t), dname_size, f)) {
		return 0;
	}

	/* refactor */
	if (!fread_safe(&label_count, sizeof(label_count), 1, f)) {
		return 0;
	}

	labels = malloc(sizeof(uint8_t) * label_count);

	assert(labels != NULL);

	if (!fread_safe(labels, sizeof(uint8_t), label_count, f)) {
		free(labels);
		return 0;
	}

	/* refactor */

	if (!fread_safe(&dname_id, sizeof(dname_id), 1, f)) {
		free(labels);
		return 0;
	}

	debug_dnslib_zload("id: %p\n", dname_id);

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

	debug_dnslib_zload("Node owned by: %s\n", dnslib_dname_to_str(owner));
	debug_dnslib_zload("labels: %d\n", owner->label_count);
//	hex_print(owner->labels, owner->label_count);

	debug_dnslib_zload("Number of RRSets in a node: %d\n", rrset_count);

	node = owner->node;

	if (node == NULL) {
		fprintf(stderr, "zone: Could not create node.\n");
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
			fprintf(stderr, "zone: Could not load rrset.\n");
			return NULL;
		}
		tmp_rrset->owner = node->owner;
		if (tmp_rrset->rrsigs != NULL) {
			tmp_rrset->rrsigs->owner = node->owner;
		}
		if (dnslib_node_add_rrset(node, tmp_rrset) != 0) {
			fprintf(stderr, "zone: Could not add rrset.\n");
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

zloader_t *dnslib_zload_open(const char *filename)
{
	if (unlikely(!filename)) {
		errno = ENOENT; // No such file or directory (POSIX.1)
		return 0;
	}

	/* Open file for binary read. */
	FILE *f = fopen(filename, "rb");
	if (unlikely(!f)) {
		debug_dnslib_zload("dnslib_zload_open: failed to open '%s'\n", filename);
		errno = ENOENT; // No such file or directory (POSIX.1)
		return 0;
	}

	/* Check magic sequence. */
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	if (!dnslib_check_magic(f, MAGIC, MAGIC_LENGTH)) {
		fclose(f);
		debug_dnslib_zload("dnslib_zload_open: magic bytes in don't match '%*s' "
		         "(%s)\n",
		         (int)MAGIC_LENGTH, (const char*)MAGIC, filename);
		errno = EILSEQ; // Illegal byte sequence (POSIX.1, C99)
		return 0;
	}

	/* Read source file length. */
	uint32_t sflen = 0;
	if (fread(&sflen, 1, sizeof(uint32_t), f) != sizeof(uint32_t)) {
		debug_dnslib_zload("dnslib_zload_open: failed to read sfile length\n");
		fclose(f);
		errno = EIO; // I/O error.
		return 0;
	}

	/* Read source file. */
	char *sfile = malloc(sflen);
	if (!sfile) {
		debug_dnslib_zload("dnslib_zload_open: invalid sfile length %u\n", sflen);
		fclose(f);
		errno = ENOMEM; // Not enough space.
		return 0;
	}
	if (fread(sfile, 1, sflen, f) < sflen) {
		debug_dnslib_zload("dnslib_zload_open: failed to read %uB source file\n",
		         sflen);
		free(sfile);
		fclose(f);
		errno = EIO; // I/O error.
		return 0;
	}

	/* Allocate new loader. */
	zloader_t *zl = malloc(sizeof(zloader_t));
	if (!zl) {
		errno = ENOMEM; // Not enough space.
		free(sfile);
		fclose(f);
		return 0;
	}

	debug_dnslib_zload("dnslib_zload_open: opened '%s' as fp %p (source is '%s')\n",
	         filename, f, sfile);
	zl->filename = strdup(filename);
	zl->source = sfile;
	zl->fp = f;
	return zl;
}

dnslib_zone_t *dnslib_zload_load(zloader_t *loader)
{
	if (!loader) {
		return 0;
	}

	FILE *f = loader->fp;

	dnslib_node_t *tmp_node;

	uint node_count;

	uint nsec3_node_count;

	uint auth_node_count;

	if (!fread_safe(&node_count, sizeof(node_count), 1, f)) {
		return 0;
	}

	if (!fread_safe(&nsec3_node_count, sizeof(nsec3_node_count), 1, f)) {
		return 0;
	}
	if (!fread_safe(&auth_node_count,
	      sizeof(auth_node_count), 1, f)) {
		return 0;
	}

	debug_dnslib_zload("authorative nodes: %u\n", auth_node_count);

	id_array =
		malloc(sizeof(dnslib_dname_t *) *
		(node_count + nsec3_node_count + 1));

	debug_dnslib_zload("loading %u nodes\n", node_count);

	for (uint i = 1; i < (node_count + nsec3_node_count + 1); i++) {
		id_array[i] = dnslib_dname_new();
		id_array[i]->node = dnslib_node_new(NULL, NULL);
	}

	dnslib_node_t *apex = dnslib_load_node(f);

	if (!apex) {
		fprintf(stderr, "zone: Could not load apex node (in %s)\n",
		        loader->filename);
		return 0;
	}

	dnslib_zone_t *zone = dnslib_zone_new(apex, auth_node_count);

	assert(zone != NULL);

	apex->prev = NULL;

        dnslib_node_t *last_node;

	last_node = apex;

	for (uint i = 1; i < node_count; i++) {
		tmp_node = dnslib_load_node(f);

		if (tmp_node != NULL) {
			if (dnslib_zone_add_node(zone, tmp_node) != 0) {
				fprintf(stderr, "!! cannot add node\n");
				continue;
			}
			if (dnslib_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(zone,
				                            tmp_node,
				                            0);
			}

			tmp_node->prev = last_node;

			if (skip_first(tmp_node->rrsets) != NULL &&
			    (dnslib_node_is_deleg_point(tmp_node) ||
			    !dnslib_node_is_non_auth(tmp_node))) {
                                last_node = tmp_node;
                        }

		} else {
			fprintf(stderr, "zone: Node error (in %s).\n",
			        loader->filename);
		}
	}

	assert(zone->apex->prev == NULL);

	zone->apex->prev = last_node;

	debug_dnslib_zload("loading %u nsec3 nodes\n", nsec3_node_count);

	dnslib_node_t *nsec3_first = NULL;

	if (nsec3_node_count > 0) {
		nsec3_first = dnslib_load_node(f);

		assert(nsec3_first != NULL);

		if (dnslib_zone_add_nsec3_node(zone, nsec3_first) != 0) {
			fprintf(stderr, "!! cannot add first nsec3 node, "
			        "exiting.\n");
			dnslib_zone_deep_free(&zone);
			return NULL;
		}

		nsec3_first->prev = NULL;

		last_node = nsec3_first;
	}

	for (uint i = 1; i < nsec3_node_count; i++) {
		tmp_node = dnslib_load_node(f);

		if (tmp_node != NULL) {
			if (dnslib_zone_add_nsec3_node(zone, tmp_node) != 0) {
				fprintf(stderr, "!! cannot add nsec3 node\n");
				continue;
			}

			tmp_node->prev = last_node;

			last_node = tmp_node;
		} else {
			fprintf(stderr, "zone: Node error (in %s).\n",
			        loader->filename);
		}
	}

	if (nsec3_node_count) {
		assert(nsec3_first->prev == NULL);
		nsec3_first->prev = last_node;
	}

	return zone;
}

int dnslib_zload_needs_update(zloader_t *loader)
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
	if (timespec_cmp(&st_bin.st_mtim, &st_src.st_mtim) < 0) {
		return 1;
	}

	return 0;
}

void dnslib_zload_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	free(loader->filename);
	free(loader->source);
	fclose(loader->fp);
	free(loader);
}

