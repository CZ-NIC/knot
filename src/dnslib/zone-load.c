#include <config.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "common/crc.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/zone-load.h"
#include "dnslib/zone-dump.h"
#include "dnslib/dnslib.h"
#include "dnslib/debug.h"

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

static uint8_t *dnslib_zload_stream = NULL;
static size_t dnslib_zload_stream_remaining = 0;
static size_t dnslib_zload_stream_size = 0;

static inline int read_from_stream(void *dst,
                                   size_t size, size_t n, FILE *fp)
{
	if (dnslib_zload_stream_remaining < (size * n)) {
		return 0;
	}

	memcpy(dst,
	       dnslib_zload_stream +
	       (dnslib_zload_stream_size - dnslib_zload_stream_remaining),
	       size * n);
	dnslib_zload_stream_remaining -= size * n;

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
static void load_rdata_purge(dnslib_rdata_t *rdata,
			     dnslib_rdata_item_t *items,
			     int count,
			     uint16_t type)
{
	dnslib_rdata_set_items(rdata, items, count);
	dnslib_rdata_deep_free(&rdata, type, 0);
	free(items);
}

static dnslib_dname_t *read_dname_with_id(FILE *f)
{
	dnslib_dname_t *ret = dnslib_dname_new();
	CHECK_ALLOC_LOG(ret, NULL);

	/* Read ID. */
	uint32_t dname_id = 0;
	if (!fread_wrapper(&dname_id, sizeof(dname_id), 1, f)) {
		dnslib_dname_free(&ret);
		return NULL;
	}

	ret->id = dname_id;

	/* Read size of dname. */
	uint32_t dname_size = 0;
	if (!fread_wrapper(&dname_size, sizeof(dname_size), 1, f)) {
		dnslib_dname_free(&ret);
		return NULL;
	}
	ret->size = dname_size;

	assert(ret->size <= DNAME_MAX_WIRE_LENGTH);

	/* Read wireformat of dname. */
	ret->name = malloc(sizeof(uint8_t) * ret->size);
	if (ret->name == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&ret);
		return NULL;
	}

	if (!fread_wrapper(ret->name, sizeof(uint8_t), ret->size, f)) {
		dnslib_dname_free(&ret);
		return NULL;
	}

	/* Read labels. */
	uint16_t label_count = 0;
	if (!fread_wrapper(&label_count, sizeof(label_count), 1, f)) {
		dnslib_dname_free(&ret);
		return NULL;
	}

	ret->label_count = label_count;

	ret->labels = malloc(sizeof(uint8_t) * ret->label_count);
	if (ret->labels == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&ret);
		return NULL;
	}

	if (!fread_wrapper(ret->labels, sizeof(uint8_t), ret->label_count, f)) {
		free(ret->name);
		free(ret);
		return NULL;
	}

	debug_dnslib_zload("loaded: %s (id: %d)\n", dnslib_dname_to_str(ret),
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
static dnslib_rdata_t *dnslib_load_rdata(uint16_t type, FILE *f,
                                         dnslib_dname_t **id_array,
                                         int use_ids)
{
	dnslib_rdata_t *rdata = dnslib_rdata_new();

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

			uint32_t dname_id = 0;
			uint8_t has_wildcard = 0;
			uint8_t in_the_zone = 0;

			if (use_ids) {
				if(!fread_wrapper(&dname_id, sizeof(dname_id), 1, f)) {
					load_rdata_purge(rdata, items, i, type);
					return NULL;
				}
				items[i].dname = id_array[dname_id];
			} else {
				items[i].dname = read_dname_with_id(f);
			}

			if(!fread_wrapper(&in_the_zone, sizeof(in_the_zone),
			               1, f)) {
				load_rdata_purge(rdata, items, i, type);
				return NULL;
			}

			if(!fread_wrapper(&has_wildcard, sizeof(uint8_t),
				       1, f)) {
				load_rdata_purge(rdata, items, i, type);
				return NULL;
			}

			if (use_ids && has_wildcard) {
				if(!fread_wrapper(&dname_id, sizeof(dname_id),
					       1, f)) {
					load_rdata_purge(rdata, items,
							 i, type);
					return NULL;
				}
				items[i].dname->node =
						id_array[dname_id]->node;
			} else if (use_ids && !in_the_zone) { /* destroy the node */
				if (id_array[dname_id]->node != NULL) {
					dnslib_node_free(&id_array[dname_id]->
							 node, 0, 0);
				}
				/* Also sets node to NULL! */
			}
			assert(items[i].dname);
		} else {
			if (!fread_wrapper(&raw_data_length,
					sizeof(raw_data_length), 1, f)) {
				load_rdata_purge(rdata, items, i, type);
				return NULL;
			}

			debug_dnslib_zload("read len: %d\n", raw_data_length);
			items[i].raw_data =
				malloc(sizeof(uint8_t) * raw_data_length + 2);
			*(items[i].raw_data) = raw_data_length;

			if (!fread_wrapper(items[i].raw_data + 1, sizeof(uint8_t),
			      raw_data_length, f)) {
				load_rdata_purge(rdata, items, i + 1, type);
				return NULL;
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

/*!
 * \brief Loads RRSIG from binary file.
 *
 * \param f File to read from.
 *
 * \return pointer to created and read RRSIG on success, NULL otherwise.
 */
static dnslib_rrset_t *dnslib_load_rrsig(FILE *f, dnslib_dname_t **id_array,
                                         int use_ids)
{
	dnslib_rrset_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;

	if (!fread_wrapper(&rrset_type, sizeof(rrset_type), 1, f)) {
		return NULL;
	}

	if (rrset_type != DNSLIB_RRTYPE_RRSIG) {
		fprintf(stderr, "!! Error: rrsig has wrong type\n");
		return NULL;
	}
	debug_dnslib_zload("rrset type: %d\n", rrset_type);
	if (!fread_wrapper(&rrset_class, sizeof(rrset_class), 1, f)) {
		return NULL;
	}
	debug_dnslib_zload("rrset class %d\n", rrset_class);

	if (!fread_wrapper(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return NULL;
	}
	debug_dnslib_zload("rrset ttl %d\n", rrset_ttl);

	if (!fread_wrapper(&rdata_count, sizeof(rdata_count), 1, f)) {
		return NULL;
	}

	rrsig = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	debug_dnslib_zload("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(DNSLIB_RRTYPE_RRSIG, f,
					      id_array, use_ids);
		if (tmp_rdata) {
			dnslib_rrset_add_rdata(rrsig, tmp_rdata);
		} else {
			dnslib_rrset_deep_free(&rrsig, 0, 1, 1);
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
static dnslib_rrset_t *dnslib_load_rrset(FILE *f, dnslib_dname_t **id_array,
                                         int use_ids)
{
	dnslib_rrset_t *rrset;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint8_t rdata_count;
	uint8_t rrsig_count;

	dnslib_dname_t *owner = NULL;

	if (!use_ids) {
		owner = read_dname_with_id(f);
	}

	if (!fread_wrapper(&rrset_type, sizeof(rrset_type), 1, f)) {
		return NULL;
	}
	if (!fread_wrapper(&rrset_class, sizeof(rrset_class), 1, f)) {
		return NULL;
	}
	if (!fread_wrapper(&rrset_ttl, sizeof(rrset_ttl), 1, f)) {
		return NULL;
	}
	if (!fread_wrapper(&rdata_count, sizeof(rdata_count), 1, f)) {
		return NULL;
	}
	if (!fread_wrapper(&rrsig_count, sizeof(rrsig_count), 1, f)) {
		return NULL;
	}

	rrset = dnslib_rrset_new(owner, rrset_type, rrset_class, rrset_ttl);

	debug_dnslib_zload("RRSet type: %d\n", rrset->type);

	dnslib_rdata_t *tmp_rdata;

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(rrset->type, f,
					      id_array, use_ids);
		if (tmp_rdata) {
			dnslib_rrset_add_rdata(rrset, tmp_rdata);
		} else {
			dnslib_rrset_deep_free(&rrset, 0, 1, 1);
			return NULL;
		}
	}

	dnslib_rrset_t *tmp_rrsig = NULL;

	if (rrsig_count) {
		tmp_rrsig = dnslib_load_rrsig(f, id_array, use_ids);
		if (!use_ids) {
			tmp_rrsig->owner = rrset->owner;
		}
	}

	rrset->rrsigs = tmp_rrsig;

	return rrset;
}

/*!
 * \brief Loads node from binary file.
 *
 * \param f File to read from.
 *
 * \return Pointer to created and read node on success, NULL otherwise.
 */
static dnslib_node_t *dnslib_load_node(FILE *f, dnslib_dname_t **id_array)
{
	uint8_t flags = 0;
	dnslib_node_t *node = NULL;
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
	dnslib_dname_t *owner = id_array[dname_id];

	debug_dnslib_zload("Node owner id: %d\n", dname_id);
	debug_dnslib_zload("Node owned by: %s\n", dnslib_dname_to_str(owner));
	debug_dnslib_zload("Number of RRSets in a node: %d\n", rrset_count);

	node = owner->node;

	if (node == NULL) {
		fprintf(stderr, "zone: Could not create node.\n");
		return NULL;
	}
	/* XXX can it be 0, ever? I think not. */
	if (nsec3_node_id != 0) {
		dnslib_node_set_nsec3_node(node, id_array[nsec3_node_id]->node);
//		node->nsec3_node = id_array[nsec3_node_id]->node;
	} else {
		dnslib_node_set_nsec3_node(node, NULL);
//		node->nsec3_node = NULL;
	}
	node->owner = owner;
	node->flags = flags;

	//XXX will have to be set already...canonical order should do it

	if (parent_id != 0) {
		dnslib_node_set_parent(node, id_array[parent_id]->node);
		assert(dnslib_node_parent(node) != NULL);
	} else {
		dnslib_node_set_parent(node, NULL);
	}

	dnslib_rrset_t *tmp_rrset;

	for (int i = 0; i < rrset_count; i++) {
		if ((tmp_rrset = dnslib_load_rrset(f, id_array, 1)) == NULL) {
			dnslib_node_free(&node, 1, 0);
			//TODO what else to free?
			fprintf(stderr, "zone: Could not load rrset.\n");
			return NULL;
		}
		tmp_rrset->owner = node->owner;
		if (tmp_rrset->rrsigs != NULL) {
			tmp_rrset->rrsigs->owner = node->owner;
		}
		if (dnslib_node_add_rrset(node, tmp_rrset, 0) < 0) {
			fprintf(stderr, "zone: Could not add rrset.\n");
			return NULL;
		}
	}
	assert(node != NULL);
	return node;
}

/*!
 * \brief Finds and sets wildcard child for given node's owner.
 *
 * \param zone Current zone.
 * \param node Node to be used.
 * \param nsec3 Is NSEC3 node.
 */
static void find_and_set_wildcard_child(dnslib_zone_t *zone,
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

	dnslib_node_set_wildcard_child(wildcard_parent, node);
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
static int dnslib_check_magic(FILE *f, const uint8_t* MAGIC, uint MAGIC_LENGTH)
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

zloader_t *dnslib_zload_open(const char *filename)
{
	if (unlikely(!filename)) {
		errno = ENOENT; // No such file or directory (POSIX.1)
		return NULL;
	}

	fread_wrapper = fread_safe_from_file;

	/* Open file for binary read. */
	FILE *f = fopen(filename, "rb");
	if (unlikely(!f)) {
		debug_dnslib_zload("dnslib_zload_open: failed to open '%s'\n",
				   filename);
		errno = ENOENT; // No such file or directory (POSIX.1)
		return NULL;
	}

	/* Calculate CRC and compare with filename.crc file */
	unsigned long crc_calculated = calculate_crc(f);

	/* Read CRC from filename.crc file */
	char *crc_path =
		malloc(sizeof(char) * (strlen(filename) + strlen(".crc") + 1));
	if (unlikely(!crc_path)) {
		fclose(f);
		errno = ENOMEM;
		return NULL;
	}
	memset(crc_path, 0,
	       sizeof(char) * (strlen(filename) + strlen(".crc") + 1));

	memcpy(crc_path, filename, sizeof(char) * strlen(filename));

	crc_path = strcat(crc_path, ".crc");
	FILE *f_crc = fopen(crc_path, "r");
	if (unlikely(!f_crc)) {
		debug_dnslib_zload("dnslib_zload_open: failed to open '%s'\n",
		                   crc_path);
		fclose(f);
		free(crc_path);
		errno = ENOENT; // No such file or directory (POSIX.1)
		return NULL;
	}

	unsigned long crc_from_file = 0;
	if (fscanf(f_crc, "%lu\n", &crc_from_file) != 1) {
		debug_dnslib_zload("dnslib_zload_open: could not read "
		                   "CRC from file '%s'\n",
		                   crc_path);
		fclose(f_crc);
		fclose(f);
		free(crc_path);
		errno = EIO; // I/O error.
		return NULL;
	}
	free(crc_path);
	fclose(f_crc);

	/* Compare calculated and read CRCs. */
	if (crc_from_file != crc_calculated) {
		debug_dnslib_zload("dnslib_zload_open: CRC failed for "
		                   "file '%s'\n",
		                   filename);
		fclose(f);
		errno = DNSLIB_ECRC;
		return NULL;
	}

	/* Check magic sequence. */
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	if (!dnslib_check_magic(f, MAGIC, MAGIC_LENGTH)) {
		fclose(f);
		debug_dnslib_zload("dnslib_zload_open: magic bytes "
				   "in don't match '%*s' "
			 "(%s)\n",
			 (int)MAGIC_LENGTH, (const char*)MAGIC, filename);
		errno = EILSEQ; // Illegal byte sequence (POSIX.1, C99)
		return NULL;
	}

	/* Read source file length. */
	uint32_t sflen = 0;
	if (!fread_wrapper(&sflen, 1, sizeof(uint32_t), f)) {
		debug_dnslib_zload("dnslib_zload_open: failed to read "
				   "sfile length\n");
		fclose(f);
		errno = EIO; // I/O error.
		return NULL;
	}

	/* Read source file. */
	char *sfile = malloc(sflen);
	if (!sfile) {
		debug_dnslib_zload("dnslib_zload_open: invalid sfile "
				   "length %u\n", sflen);
		fclose(f);
		errno = ENOMEM; // Not enough space.
		return NULL;
	}
	if (!fread_wrapper(sfile, 1, sflen, f)) {
		debug_dnslib_zload("dnslib_zload_open: failed to read %uB "
				   "source file\n",
			 sflen);
		free(sfile);
		fclose(f);
		errno = EIO; // I/O error.
		return NULL;
	}

	/* Allocate new loader. */
	zloader_t *zl = malloc(sizeof(zloader_t));
	if (!zl) {
		errno = ENOMEM; // Not enough space.
		free(sfile);
		fclose(f);
		return NULL;
	}

	debug_dnslib_zload("dnslib_zload_open: opened '%s' as fp %p "
			   "(source is '%s')\n",
		 filename, f, sfile);
	zl->filename = strdup(filename);
	zl->source = sfile;
	zl->fp = f;
	return zl;
}

static void cleanup_id_array(dnslib_dname_t **id_array,
			     const uint from, const uint to)
{
	for (uint i = from; i < to; i++) {
		dnslib_dname_free(&(id_array[i]));
	}

	free(id_array);
}

//static dnslib_dname_table_t *create_dname_table(FILE *f, uint max_id)
//{
//	if (f == NULL ) {
//		return NULL;
//	}

//	if (!fread_wrapper(&max_id, sizeof(max_id), 1, f)) {
//		return NULL;
//	}

//	dnslib_dname_table_t *dname_table = dnslib_dname_table_new();
//	if (dname_table == NULL) {
//		return NULL;
//	}

//	/* Create nodes containing dnames. */
//	for (uint i = 1; i < max_id; i++) {
//		dnslib_dname_t *loaded_dname = read_dname_with_id(f);
//		if (loaded_dname == NULL) {
//			dnslib_dname_table_deep_free(&dname_table);
//			return NULL;
//		}
//		if (dnslib_dname_table_add_dname(dname_table,
//		                                 loaded_dname) != DNSLIB_EOK) {

//		}
//	}

//	return dname_table;
//}

static dnslib_dname_table_t *create_dname_table_from_array(
	dnslib_dname_t **array, uint max_id)
{
	if (array == NULL) {
		/* should I set errno or what ... ? */
		debug_dnslib_zload("No array passed\n");
		return NULL;
	}

	assert(array[0] == NULL);

	dnslib_dname_table_t *ret = dnslib_dname_table_new();
	CHECK_ALLOC_LOG(ret, NULL);

	/* Table will have max_id entries */
	for (uint i = 1; i < max_id; i++) {
		assert(array[i]);
		if (dnslib_dname_table_add_dname(ret,
						 array[i]) != DNSLIB_EOK) {
			debug_dnslib_zload("Could not add: %s\n",
			                   dnslib_dname_to_str(array[i]));
			dnslib_dname_table_deep_free(&ret);
			return NULL;
		}
	}

	return ret;
}

static dnslib_dname_t **create_dname_array(FILE *f, uint max_id)
{
	if (f == NULL) {
		return NULL;
	}

	dnslib_dname_t **array =
		malloc(sizeof(dnslib_dname_t *) * ( max_id + 1));
	memset(array, 0, sizeof(dnslib_dname_t *) * (max_id + 1));
	if (array == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	for (uint i = 0; i < max_id - 1; i++) {
		dnslib_dname_t *read_dname = read_dname_with_id(f);
//		printf("First dname: %s\n", dnslib_dname_to_str(array[i]));
		if (read_dname == NULL) {
			cleanup_id_array(array, 0, i);
			return NULL;
		}
		if (read_dname->id < max_id) {
			read_dname->node = dnslib_node_new(read_dname, NULL, 0);
			if (read_dname->node == NULL) {
				ERR_ALLOC_FAILED;
				cleanup_id_array(array, 0, i);
				dnslib_dname_free(&read_dname);
				return NULL;
			}
			array[read_dname->id] = read_dname;
		} else {
			cleanup_id_array(array, 0, i);
			return NULL;
		}
//		assert(array[i]->id == i);
	}

	return array;
}

dnslib_zone_t *dnslib_zload_load(zloader_t *loader)
{
	if (!loader) {
		return NULL;
	}

	fread_wrapper = fread_safe_from_file;

	FILE *f = loader->fp;

	dnslib_node_t *tmp_node;

	/* Load the dname table. */
//	const dnslib_dname_table_t *dname_table =
//		create_dname_table(f, total_dnames);
//	if (dname_table == NULL) {
//		return NULL;
//	}

	uint32_t node_count;
	uint32_t nsec3_node_count;
	uint32_t auth_node_count;

	if (!fread_wrapper(&node_count, sizeof(node_count), 1, f)) {
		return NULL;
	}

	if (!fread_wrapper(&nsec3_node_count, sizeof(nsec3_node_count), 1, f)) {
		return NULL;
	}
	if (!fread_wrapper(&auth_node_count,
	      sizeof(auth_node_count), 1, f)) {
		return NULL;
	}
	debug_dnslib_zload("authoritative nodes: %u\n", auth_node_count);

	debug_dnslib_zload("loading %u nodes\n", node_count);

	uint32_t total_dnames = 0;
	/* First, read number of dnames in dname table. */
	if (!fread_wrapper(&total_dnames, sizeof(total_dnames), 1, f)) {
		return NULL;
	}

	debug_dnslib_zload("total dname count: %d\n", total_dnames);

	/* Create id array. */
	dnslib_dname_t **id_array = create_dname_array(f, total_dnames);
	if (id_array == NULL) {
		return NULL;
	}

	dnslib_dname_table_t *dname_table =
		create_dname_table_from_array(id_array, total_dnames);
	if (dname_table == NULL) {
		ERR_ALLOC_FAILED;
		cleanup_id_array(id_array, 1, total_dnames);
		return NULL;
	}

	dnslib_node_t *apex = dnslib_load_node(f, id_array);

	if (!apex) {
		fprintf(stderr, "zone: Could not load apex node (in %s)\n",
			loader->filename);
		cleanup_id_array(id_array, 1,
				 node_count + nsec3_node_count + 1);
		return NULL;
	}

	dnslib_zone_t *zone = dnslib_zone_new(apex, auth_node_count, 0);
	if (zone == NULL) {
		cleanup_id_array(id_array, 1,
				 node_count + nsec3_node_count + 1);
		return NULL;
	}
	/* Assign dname table to the new zone. */
	zone->contents->dname_table = dname_table;

//	apex->prev = NULL;
	dnslib_node_set_previous(apex, NULL);

	dnslib_node_t *last_node;

	last_node = apex;

	for (uint i = 1; i < node_count; i++) {
		tmp_node = dnslib_load_node(f, id_array);

		if (tmp_node != NULL) {
			if (dnslib_zone_add_node(zone, tmp_node, 0, 0) != 0) {
				fprintf(stderr, "!! cannot add node\n");
				continue;
			}
			if (dnslib_dname_is_wildcard(tmp_node->owner)) {
				find_and_set_wildcard_child(zone,
							    tmp_node,
							    0);
			}

			dnslib_node_set_previous(tmp_node, last_node);
//			tmp_node->prev = last_node;

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

	assert(dnslib_node_previous(dnslib_zone_apex(zone)) == NULL);

	dnslib_node_set_previous(dnslib_zone_get_apex(zone), last_node);
//	zone->apex->prev = last_node;

	debug_dnslib_zload("loading %u nsec3 nodes\n", nsec3_node_count);

	dnslib_node_t *nsec3_first = NULL;

	if (nsec3_node_count > 0) {
		nsec3_first = dnslib_load_node(f, id_array);

		assert(nsec3_first != NULL);

		if (dnslib_zone_add_nsec3_node(zone, nsec3_first, 0, 0) != 0) {
			fprintf(stderr, "!! cannot add first nsec3 node, "
				"exiting.\n");
			dnslib_zone_deep_free(&zone, 1);
			free(id_array);
			/* TODO this will leak dnames from id_array that were
			 * not assigned. */
			return NULL;
		}

		dnslib_node_set_previous(nsec3_first, NULL);
//		nsec3_first->prev = NULL;

		last_node = nsec3_first;
	}

	for (uint i = 1; i < nsec3_node_count; i++) {
		tmp_node = dnslib_load_node(f, id_array);

		if (tmp_node != NULL) {
			if (dnslib_zone_add_nsec3_node(zone, tmp_node, 0, 0) != 0) {
				fprintf(stderr, "!! cannot add nsec3 node\n");
				continue;
			}

			dnslib_node_set_previous(tmp_node, last_node);
//			tmp_node->prev = last_node;

			last_node = tmp_node;
		} else {
			fprintf(stderr, "zone: Node error (in %s).\n",
				loader->filename);
		}
	}

	if (nsec3_node_count) {
		assert(dnslib_node_previous(nsec3_first) == NULL);
		dnslib_node_set_previous(nsec3_first, last_node);
//		nsec3_first->prev = last_node;
	}

	/* ID array is now useless */
	free(id_array);


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
	/*! \todo Inspect types on Linux. */
	if (timet_cmp(st_bin.st_mtime, st_src.st_mtime) < 0) {
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

int dnslib_zload_rrset_deserialize(dnslib_rrset_t **rrset,
                                   uint8_t *stream, size_t *size)
{
	if (stream == NULL || size == 0 || *rrset != NULL) {
		return DNSLIB_EBADARG;
	}

	fread_wrapper = read_from_stream;

	dnslib_zload_stream = stream;
	dnslib_zload_stream_remaining = dnslib_zload_stream_size = *size;

	dnslib_rrset_t *ret = dnslib_load_rrset(NULL, NULL, 0);

	if (ret == NULL) {
		dnslib_zload_stream = NULL;
		dnslib_zload_stream_remaining = 0;
		dnslib_zload_stream_size = 0;
		return DNSLIB_EMALF;
	}

//	printf("dnslib_zload_stream_size: %d, dnslib_zload_stream_remaning: %d\n",
//	       dnslib_zload_stream_size, dnslib_zload_stream_remaining);

	*size = dnslib_zload_stream_remaining;
	*rrset = ret;

	dnslib_zload_stream = NULL;
	dnslib_zload_stream_remaining = 0;
	dnslib_zload_stream_size = 0;

	return DNSLIB_EOK;
}

