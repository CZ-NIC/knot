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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libknot/common.h"
#include "knot/zone/zone-dump.h"
#include "libknot/libknot.h"
#include "common/crc.h"
#include "knot/other/debug.h"
#include "common/skip-list.h"
#include "libknot/util/error.h"
#include "semantic-check.h"

#define ZONECHECKS_VERBOSE

/*! \note Contents of a dump file:
 * MAGIC(knotxx) db_filename dname_table
 * NUMBER_OF_NORMAL_NODES NUMBER_OF_NSEC3_NODES
 * [normal_nodes] [nsec3_nodes]
 * --------------------------------------------
 * dname_table is dumped as follows:
 * NUMBER_OF_DNAMES [dname_wire_length dname_wire label_count dname_labels ID]
 * node has following format:
 * owner_id
 * node_flags node_rrset_count [node_rrsets]
 * rrset has following format:
 * rrset_type rrset_class rrset_ttl rrset_rdata_count rrset_rrsig_count
 * [rrset_rdata] [rrset_rrsigs]
 * rdata can contain either dname ID,
 * or raw data stored like this: data_len [data]
 */

static inline int write_to_file_crc(const void *src,
                                     size_t size, size_t n, int fd,
                                     crc_t *crc)
{
	ssize_t rc = write(fd, src, size * n);
	if (rc != size * n) {
		fprintf(stderr, "fwrite: invalid write %zu (expected %zu)\n", rc,
			n);
	}

	if (size * n > 0) {
		*crc =
			crc_update(*crc, (unsigned char *)src,
		                   size * n);
	}

	/* 
	 * It was meant differtely, caller function does not 
	 * care how many bytes had been written, it just cares about
	 * success/fail (not that it is checked anyway) (#1684).
 	 */
	return rc == n;

}

static inline int write_to_stream(const void *src,
                                   size_t size, size_t n,
                                   uint8_t **stream,
                                   size_t *stream_size)
{
	/* Resize the stream */
	void *tmp = realloc(*stream,
			    (*stream_size + (size * n)) * sizeof(uint8_t));
	if (tmp != NULL) {
		*stream = tmp;
		memcpy(*stream + *stream_size, src,
		       size * n);
		*stream_size += (size * n) * sizeof(uint8_t);
		return KNOT_EOK;
	} else {
		free(*stream);
		*stream = NULL;
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int write_wrapper(const void *src,
                          size_t size, size_t n, int fd,
                          uint8_t **stream, size_t *stream_size, crc_t *crc)
{
	if (fd < 0) {
		assert(stream && stream_size);
		assert(crc == NULL);
		return write_to_stream(src, size, n, stream, stream_size);
	} else {
		assert(stream == NULL && stream_size == NULL);
		return write_to_file_crc(src, size, n, fd, crc);
	}
}

/*!
 * \brief Dumps dname labels in binary format to given file.
 *
 * \param dname Dname whose labels are to be dumped.
 * \param f Output file.
 */
static void knot_labels_dump_binary(const knot_dname_t *dname, int fd,
                                    uint8_t **stream, size_t *stream_size,
                                    crc_t *crc)
{
	dbg_zdump("label count: %d\n", dname->label_count);
	uint16_t label_count = dname->label_count;
	/*!< \todo #1684 check the return value */
	write_wrapper(&label_count, sizeof(label_count), 1, fd, stream,
	               stream_size, crc);
	/*!< \todo #1684 check the return value */
	write_wrapper(dname->labels, sizeof(uint8_t), dname->label_count, fd,
	               stream, stream_size, crc);
}

/*!
 * \brief Dumps dname in binary format to given file.
 *
 * \param dname Dname to be dumped.
 * \param f Output file.
 */
static void knot_dname_dump_binary(const knot_dname_t *dname, int fd,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	uint32_t dname_size = dname->size;
	/*!< \todo #1684 check the return value */
	write_wrapper(&dname_size, sizeof(dname_size), 1, fd, stream,
	               stream_size, crc);
	/*!< \todo #1684 check the return value */
	write_wrapper(dname->name, sizeof(uint8_t), dname->size, fd,
	               stream, stream_size, crc);
	dbg_zdump("dname size: %d\n", dname->size);
	knot_labels_dump_binary(dname, fd, stream, stream_size, crc);
}

/*!< \todo #1684 some global variable indicating error! */
static void dump_dname_with_id(const knot_dname_t *dname, int fd,
                               uint8_t **stream, size_t *stream_size,
                               crc_t *crc)
{
	uint32_t id = dname->id;
	/*!< \todo #1684 check the return value */
	write_wrapper(&id, sizeof(id), 1, fd, stream, stream_size, crc);
	knot_dname_dump_binary(dname, fd, stream, stream_size, crc);
/*	if (!write_wrapper_safe(&dname->id, sizeof(dname->id), 1, f)) {
		return KNOT_ERROR;
	} */
}

/*!
 * \brief Dumps given rdata in binary format to given file.
 *
 * \param rdata Rdata to be dumped.
 * \param type Type of rdata.
 * \param data Arguments to be propagated.
 */
static void knot_rdata_dump_binary(knot_rdata_t *rdata,
				   uint32_t type, int fd, int use_ids,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dbg_zdump("Dumping type: %d\n", type);

	if (desc->fixed_items) {
		assert(desc->length == rdata->count);
	}

	/* Write rdata count. */
	/*!< \todo #1684 check the return value */
	write_wrapper(&(rdata->count),
	               sizeof(rdata->count), 1, fd, stream, stream_size, crc);

	for (int i = 0; i < rdata->count; i++) {
		if (&(rdata->items[i]) == NULL) {
			dbg_zdump("Item n. %d is not set!\n", i);
			continue;
		}
		dbg_zdump("Item n: %d\n", i);
		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME )	{
			/*  some temp variables - this is way too long */
			assert(rdata->items[i].dname != NULL);
			knot_dname_t *wildcard = NULL;

			if (rdata->items[i].dname->node != NULL &&
				rdata->items[i].dname->node->owner !=
				rdata->items[i].dname) {
				wildcard = rdata->items[i].dname->node->owner;
			}

			if (use_ids) {
				/* Write ID. */
				assert(rdata->items[i].dname->id != 0);

				uint32_t id = rdata->items[i].dname->id;
				/*!< \todo #1684 check the return value */
				write_wrapper(&id,
				       sizeof(id), 1, fd, stream, stream_size,
				               crc);
			} else {
//				assert(rdata->items[i].dname->id != 0);
				dump_dname_with_id(rdata->items[i].dname,
				                   fd, stream,
				                   stream_size, crc);
			}

			/* Write in the zone bit */
			if (rdata->items[i].dname->node != NULL && !wildcard) {
				/*!< \todo #1684 check the return value */
				write_wrapper((uint8_t *)"\1",
				       sizeof(uint8_t), 1, fd, stream,
				               stream_size, crc);
			} else {
				/*!< \todo #1684 check the return value */
				write_wrapper((uint8_t *)"\0", sizeof(uint8_t),
				       1, fd, stream, stream_size, crc);
			}

			if (use_ids && wildcard) {
				/*!< \todo #1684 check the return value */
				write_wrapper((uint8_t *)"\1",
				       sizeof(uint8_t), 1, fd, stream,
				       stream_size, crc);
				uint32_t wildcard_id = wildcard->id;
				/*!< \todo #1684 check the return value */
				write_wrapper(&wildcard_id,
				       sizeof(wildcard_id), 1, fd, stream,
				               stream_size, crc);
			} else {
				/*!< \todo #1684 check the return value */
				write_wrapper((uint8_t *)"\0", sizeof(uint8_t),
				       1, fd, stream,
				       stream_size, crc);
			}

		} else {
			dbg_zdump("Writing raw data. Item nr.: %d\n",
			                 i);
			assert(rdata->items[i].raw_data != NULL);
			/*!< \todo #1684 check the return value */
			write_wrapper(rdata->items[i].raw_data,
			               sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 2, fd,
			               stream, stream_size, crc);

			dbg_zdump("Written %d long raw data\n",
					   rdata->items[i].raw_data[0]);
		}
	}
}

/*!
 * \brief Dumps RRSIG in binary format to given file.
 *
 * \param rrsig RRSIG to be dumped.
 * \param data Arguments to be propagated.
 */
static void knot_rrsig_set_dump_binary(knot_rrset_t *rrsig, int fd,
                                       int use_ids,
                                       uint8_t **stream, size_t *stream_size,
                                       crc_t *crc)
{
dbg_zdump_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(rrsig));
	dbg_zdump("Dumping RRSIG \\w owner: %s\n",
	                   name);
	free(name);
);
	assert(rrsig->type == KNOT_RRTYPE_RRSIG);
	assert(rrsig->rdata);
	/*!< \todo #1684 check the return value */
	write_wrapper(&rrsig->type, sizeof(rrsig->type), 1, fd,
	               stream, stream_size, crc);
	write_wrapper(&rrsig->rclass, sizeof(rrsig->rclass), 1, fd,
	               stream, stream_size, crc);
	write_wrapper(&rrsig->ttl, sizeof(rrsig->ttl), 1, fd,
	               stream, stream_size, crc);

	uint32_t rdata_count = 1;
	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrsig->rdata;
	while(tmp_rdata->next != rrsig->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}

	write_wrapper(&rdata_count, sizeof(rdata_count), 1, fd,
	               stream, stream_size, crc);

	tmp_rdata = rrsig->rdata;
	while (tmp_rdata->next != rrsig->rdata) {
		knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG, fd,
		                         use_ids, stream, stream_size, crc);
		tmp_rdata = tmp_rdata->next;
	}
	knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG, fd, use_ids,
	                       stream, stream_size, crc);
}

/*!
 * \brief Dumps RRSet in binary format to given file.
 *
 * \param rrset RRSSet to be dumped.
 * \param data Arguments to be propagated.
 */
static void knot_rrset_dump_binary(const knot_rrset_t *rrset, int fd,
                                   int use_ids,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	dbg_zdump_detail("zdump: rrset_dump_binary: Dumping rrset to fd=%d\n",
	                 fd);

	if (!use_ids) {
		dump_dname_with_id(rrset->owner, fd, stream, stream_size, crc);
	}

	/*!< \todo #1684 check the return value */
	write_wrapper(&rrset->type, sizeof(rrset->type), 1, fd,
	               stream, stream_size, crc);
	write_wrapper(&rrset->rclass, sizeof(rrset->rclass), 1, fd,
	               stream, stream_size, crc);
	write_wrapper(&rrset->ttl, sizeof(rrset->ttl), 1, fd,
	               stream, stream_size, crc);

	uint32_t rdata_count = 1;
	uint8_t has_rrsig = rrset->rrsigs != NULL;

	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrset->rdata;
	while(tmp_rdata->next != rrset->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}

	write_wrapper(&rdata_count, sizeof(rdata_count), 1, fd,
	               stream, stream_size, crc);
	write_wrapper(&has_rrsig, sizeof(has_rrsig), 1, fd,
	               stream, stream_size, crc);
	
	dbg_zdump_detail("zdump: rrset_dump_binary: Static data dumped.\n");

	tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		knot_rdata_dump_binary(tmp_rdata, rrset->type, fd, use_ids,
		                       stream, stream_size, crc);
		tmp_rdata = tmp_rdata->next;
	}
	knot_rdata_dump_binary(tmp_rdata, rrset->type, fd, use_ids,
	                       stream, stream_size, crc);
	
	dbg_zdump_detail("zdump: rrset_dump_binary: Rdata dumped.\n");

	/* This is now obsolete, although I'd rather not use recursion - that
	 * would probably not work */

	if (rrset->rrsigs != NULL) {
		knot_rrsig_set_dump_binary(rrset->rrsigs, fd, use_ids,
		                           stream, stream_size, crc);
	}
}

/*!
 * \brief Dumps all RRSets in node to file in binary format.
 *
 * \param node Node to dumped.
 * \param data Arguments to be propagated.
 */
static void knot_node_dump_binary(knot_node_t *node, int fd,
                                  uint8_t **stream, size_t *stream_size,
                                  crc_t *crc)
{
	if (node == NULL) {
		return;
	}
	
	/* first write dname */
	assert(node->owner != NULL);

	/* Write owner ID. */
dbg_zdump_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_zdump("Dumping node owned by %s\n",
	                   name);
	free(name);
);
	assert(node->owner->id != 0);
	uint32_t owner_id = node->owner->id;
	/*!< \todo #1684 check the return value */
	write_wrapper(&owner_id, sizeof(owner_id), 1, fd, stream, stream_size,
	               crc);

	if (knot_node_parent(node) != NULL) {
		uint32_t parent_id = knot_dname_id(
				knot_node_owner(knot_node_parent(node)));
		write_wrapper(&parent_id, sizeof(parent_id), 1, fd,
		               stream, stream_size, crc);
	} else {
		uint32_t parent_id = 0;
		write_wrapper(&parent_id, sizeof(parent_id), 1, fd,
		               stream, stream_size, crc);
	}

	write_wrapper(&(node->flags), sizeof(node->flags), 1, fd,
	               stream, stream_size, crc);

	dbg_zdump("Written flags: %u\n", node->flags);

	if (knot_node_nsec3_node(node) != NULL) {
		uint32_t nsec3_id =
			knot_node_owner(knot_node_nsec3_node(node))->id;
		write_wrapper(&nsec3_id, sizeof(nsec3_id), 1, fd,
		               stream, stream_size, crc);
		dbg_zdump("Written nsec3 node id: %u\n",
			 knot_node_owner(knot_node_nsec3_node(node))->id);
	} else {
		uint32_t nsec3_id = 0;
		write_wrapper(&nsec3_id, sizeof(nsec3_id), 1, fd,
		               stream, stream_size, crc);
	}

	/* Now we need (or do we?) count of rrsets to be read
	 * but that number is yet unknown */

	uint16_t rrset_count = node->rrset_count;
	write_wrapper(&rrset_count, sizeof(rrset_count), 1, fd,
	               stream, stream_size, crc);

	const knot_rrset_t **node_rrsets = knot_node_rrsets(node);
	for (int i = 0; i < rrset_count; i++)
	{
		knot_rrset_dump_binary(node_rrsets[i], fd, 1,
		                       stream, stream_size, crc);
	}

	free(node_rrsets);

}

int zone_is_secure(knot_zone_contents_t *zone)
{
	if (knot_node_rrset(knot_zone_contents_apex(zone),
			      KNOT_RRTYPE_DNSKEY) == NULL) {
		return 0;
	} else {
		if (knot_node_rrset(knot_zone_contents_apex(zone),
				      KNOT_RRTYPE_NSEC3PARAM) != NULL) {
			return 2;
		} else {
			return 1;
		}
	}
}

static void dump_dname_from_tree(knot_dname_t *dname,
				 void *data)
{
	arg_t *arg = (arg_t *)data;
	int *fd_pointer = (int *)arg->arg1;
	int fd = -1;
	if (fd_pointer != NULL) {
		fd = *fd_pointer;
	} else {
		dbg_zdump("zdump: dump_dname_from_tree: Bad fd.\n");
		return;
	}
	
	crc_t *crc = (crc_t*)arg->arg2;
	dump_dname_with_id(dname, fd, NULL, NULL, crc);
}

static int knot_dump_dname_table(const knot_dname_table_t *dname_table,
				   int fd, crc_t *crc)
{
	arg_t arg;
	arg.arg1 = &fd;
	arg.arg2 = crc;
	/* Go through the tree and dump each dname along with its ID. */
	knot_dname_table_tree_inorder_apply(dname_table,
					    dump_dname_from_tree, &arg);

	return KNOT_EOK;
}

static void save_node_from_tree(knot_node_t *node, void *data)
{
	arg_t *arg = (arg_t *)data;
	/* Increment node count */
	(*((uint32_t *)(arg->arg1)))++;
	/* Save the first node only */
	if (arg->arg2 == NULL) {
		arg->arg2 = (void *)node;
	}
	arg->arg3 = (void *)node;
}

static void dump_node_to_file(knot_node_t *node, void *data)
{
	arg_t *arg = (arg_t *)data;
	int *fd_pointer = (int *)arg->arg1;
	int fd = -1;
	if (fd_pointer != NULL) {
		fd = *fd_pointer;
	}
	
	knot_node_dump_binary(node, fd, NULL, NULL, (crc_t *)arg->arg7);
}

char *knot_zdump_crc_file(const char* filename)
{
	char *crc_path =
		malloc(sizeof(char) * (strlen(filename) +
		strlen(".crc") + 1));
	CHECK_ALLOC_LOG(crc_path, NULL);
	memset(crc_path, 0,
	       sizeof(char) * (strlen(filename) +
	       strlen(".crc") + 1));
	memcpy(crc_path, filename,
	       sizeof(char) * strlen(filename));
	crc_path = strncat(crc_path, ".crc", strlen(".crc"));
	return crc_path;
}

int knot_zdump_binary(knot_zone_contents_t *zone, int fd,
                      int do_checks, const char *sfilename,
                      crc_t *crc)
{
	if (fd < 0 || sfilename == NULL) {
		return KNOT_EBADARG;
	}

	arg_t arguments;
	/* Memory to be derefenced in the save_node_from_tree function. */
	uint32_t node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of normal nodes. */
	knot_zone_contents_tree_apply_inorder(zone, save_node_from_tree, &arguments);
	/* arg1 is now count of normal nodes */
	uint32_t normal_node_count = *((uint32_t *)arguments.arg1);

	node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of NSEC3 nodes. */
	knot_zone_contents_nsec3_apply_inorder(zone, save_node_from_tree, &arguments);
	uint32_t nsec3_node_count = *((uint32_t *)arguments.arg1);
	/* arg2 is the first NSEC3 node - used in sem checks. */
	/* arg3 is the last NSEC3 node - used in sem checks. */
	const knot_node_t *first_nsec3_node = (knot_node_t *)arguments.arg2;
	const knot_node_t *last_nsec3_node = (knot_node_t *)arguments.arg3;

	if (do_checks && zone_is_secure(zone)) {
		do_checks += zone_is_secure(zone);
	}

	/* FIXME(OS): Really descriptive call 1,1,1,1, some #defines here? */
	err_handler_t *handler = handler_new(1, 1, 1, 1, 1);
	if (handler == NULL) {
		return KNOT_ENOMEM;
	} else { /* Do check for SOA right now */
		if (knot_node_rrset(knot_zone_contents_apex(zone),
				      KNOT_RRTYPE_SOA) == NULL) {
			err_handler_handle_error(handler,
						 knot_zone_contents_apex(zone),
						 ZC_ERR_MISSING_SOA);
		}
	}
	
	knot_node_t *last_node = NULL;
	int ret = zone_do_sem_checks(zone,
	                             do_checks, handler, &last_node);
	log_cyclic_errors_in_zone(handler, zone, last_node,
	                          first_nsec3_node, last_nsec3_node,
	                          do_checks);
	err_handler_log_all(handler);
	free(handler);
		
	if (ret != KNOT_EOK) {
		fprintf(stderr, "Zone will not be dumped because of "
		        "fatal semantic errors.\n");
		/* If remove fails, there is nothing we can do. */
		return KNOT_ERROR;
	}

	*crc = crc_init();

	/* Start writing header - magic bytes. */
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	write_wrapper(&MAGIC, sizeof(uint8_t), MAGIC_LENGTH, fd, NULL, NULL,
	               crc);

	/* Write source file length. */
	uint32_t sflen = strlen(sfilename) + 1;
	write_wrapper(&sflen, sizeof(uint32_t), 1, fd, NULL, NULL, crc);

	/* Write source file. */
	write_wrapper(sfilename, sflen, 1, fd, NULL, NULL, crc);

	/* Notice: End of header,
	 */

	/* Start writing compiled data. */
	write_wrapper(&normal_node_count, sizeof(normal_node_count), 1, fd,
	               NULL, NULL, crc);
	write_wrapper(&nsec3_node_count, sizeof(nsec3_node_count), 1, fd,
	               NULL, NULL, crc);
	uint32_t auth_node_count = zone->node_count;
	write_wrapper(&auth_node_count,
	       sizeof(auth_node_count), 1, fd, NULL, NULL, crc);

	/* Write total number of dnames */
	assert(zone->dname_table);
	uint32_t total_dnames = zone->dname_table->id_counter;
	write_wrapper(&total_dnames,
	       sizeof(total_dnames), 1, fd, NULL, NULL, crc);

	/* Write dname table. */
	if (knot_dump_dname_table(zone->dname_table, fd, crc)
	    != KNOT_EOK) {
		return KNOT_ERROR;
	}
	
	arguments.arg1 = &fd;
	arguments.arg3 = zone;
	arguments.arg7 = crc;

	/*!< \todo #1685 Stop traversal upon error. */
	knot_zone_contents_tree_apply_inorder(zone, dump_node_to_file,
				       (void *)&arguments);

	knot_zone_contents_nsec3_apply_inorder(zone, dump_node_to_file,
					(void *)&arguments);
	*crc = crc_finalize(*crc);
	
	return KNOT_EOK;
}

int knot_zdump_rrset_serialize(const knot_rrset_t *rrset, uint8_t **stream,
                                 size_t *size)
{
	if (stream == NULL || *stream != NULL || rrset == NULL ||
	    size == NULL) {
		dbg_zdump("zdump: rrset_serialize: Bad arguments.\n");
		return KNOT_EBADARG;
	}

	*size = 0;
	arg_t arguments;
	memset(&arguments, 0, sizeof(arg_t));
	
	/* This fd will signal functions to use streams. */
	int fd = -1;

	knot_rrset_dump_binary(rrset, fd, 0, stream, size, NULL);

	return KNOT_EOK;
}

int knot_zdump_dump(knot_zone_contents_t *zone, int fd, const char *sfilename,
                    crc_t *crc)
{
	int rc = knot_zdump_binary(zone, fd, 0, sfilename, crc);
	if (rc != KNOT_EOK) {
		dbg_zdump("Failed to save the zone to binary zone db\n.");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}
