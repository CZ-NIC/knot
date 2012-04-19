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

static const size_t BUFFER_SIZE = 4096;

static inline int write_to_file_crc(const void *src,
                                     size_t size, size_t n, int fd,
                                     crc_t *crc)
{
	if (src == NULL || fd < 0) {
		return KNOT_EBADARG;
	}
	ssize_t rc = write(fd, src, size * n);
	if (rc != size * n) {
		fprintf(stderr, "write: invalid write %zu (expected %zu)\n", rc,
			n);
	}

	if (size * n > 0) {
		*crc =
			crc_update(*crc, (unsigned char *)src,
		                   size * n);
	}

	return rc == size * n;
}

static inline int write_to_stream(const void *src,
                                  size_t size, size_t n,
                                  uint8_t *stream,
                                  size_t max_size,
                                  size_t *written_bytes)
{
	if (src == NULL || stream == NULL || written_bytes == NULL) {
		return KNOT_EBADARG;
	}
	
	/* Check that the stream boundary will not be crossed. */
	if (*written_bytes + (size * n) > max_size) {
		/* Buffer overflown. */
		dbg_zdump("zdump: write_to_stream: Cannot write to stream, no "
		          "space left.\n");
		return KNOT_ERANGE;
	}
	
	/* Do the actual write. */
	memcpy(stream + *written_bytes, src, size * n);
	/* Expand size. */
	*written_bytes += (size * n);
	
	return KNOT_EOK;
}

static int write_wrapper(const void *src,
                         size_t size, size_t n, int fd,
                         uint8_t *stream, size_t max_size,
                         size_t *written_bytes, crc_t *crc)
{
	if (src == NULL) {
		dbg_zdump("zdump: write_wrapper: NULL source.\n");
		return KNOT_EBADARG;
	}
	
	dbg_zdump_detail("zdump: write_wrapper: Writing %d bytes to fd: %d.\n",
	                 size * n, fd);
	
	if (fd < 0) {
		assert(stream && written_bytes);
		assert(crc == NULL);
		/*!< \todo To comply with calling convention of write_wrapper,
		 * we have to lose the error. */
		int ret = write_to_stream(src, size, n, stream, max_size,
		                          written_bytes);
		if (ret != KNOT_EOK) {
			dbg_zdump("zdump: write_wrapper: Could not write to "
			          "stream. Reason: %s.\n", knot_strerror(ret));
			/* Intentional! */
			return 0;
		} else {
			/* Intentional! */
			return 1;
		}
	} else {
		/* Write to buffer first, if possible. */
		if (*written_bytes + (size * n) < BUFFER_SIZE) {
			dbg_zdump_detail("zdump: write_wrapper: Fits to "
			                 "buffer. Remaining=%d.\n",
			                 BUFFER_SIZE - *written_bytes);
			int ret = write_to_stream(src, size, n,
			                          stream,
			                          BUFFER_SIZE, written_bytes);
			if (ret != KNOT_EOK) {
				dbg_zdump("zdump: write_wrapper: "
				          "Could not write to "
				          "stream. Reason: %s.\n",
				          knot_strerror(ret));
				/* Intentional! */
				return 0;
			} else {
				/* Intentional! */
				return 1;
			}
		} else {
			/* Fill remainder of buffer. */
			size_t remainder = BUFFER_SIZE - *written_bytes;
			dbg_zdump_detail("zdump: write_wrapper: "
			                 "Flushing buffer, "
			                 "appending %d bytes.\n", remainder);
			int ret = write_to_stream(src, 1,
			                          remainder,
			                          stream,
			                          BUFFER_SIZE,
			                          written_bytes);
			if (ret != KNOT_EOK) {
				dbg_zdump("zdump: write_wrapper: "
				          "Could not write to stream: %s\n",
				          knot_strerror(ret));
				// failure
				return 0;
			}

			assert(*written_bytes == BUFFER_SIZE);

			/* Buffer is filled, write to the actual file. */
			ret = write_to_file_crc(stream, 1,
			                        *written_bytes, fd, crc);
			if (!ret) {
				dbg_zdump("zdump: write_wrapper: "
				          "Could not write to file.\n");
				// failure
				return 0;
			}
			
			/* Reset counter. */
			*written_bytes = 0;
			
			/* Write remaining data to new buffer. */
			if ((size * n) - remainder > BUFFER_SIZE) {
				/* Write through. */
				dbg_zdump("zdump: Attempting buffer write "
				          "through. Total: %d bytes.\n",
				          (size * n) - remainder);
				ret = write_to_file_crc(src + remainder, 1,
				                        (size * n) - remainder,
				                        fd, crc);
				if (!ret) {
					dbg_zdump("zdump: write_wrapper: "
					          "Could not write rest of buffer to "
					          "file: %s.\n", knot_strerror(ret));
					// failure
					return 0;
				}
			} else {
				/* Normal buffer filling. */
				ret = write_to_stream(src + remainder,
				                      1, (size * n) - remainder,
				                      stream, BUFFER_SIZE,
				                      written_bytes);
				if (ret != KNOT_EOK) {
					dbg_zdump("zdump: write_wrapper: "
					          "Could not write rest of buffer to "
					          "stream: %s.\n", knot_strerror(ret));
					// failure
					return 0;
				}
			}

			// OK
			return 1;
		}
	}
}

/*!
 * \brief Dumps dname labels in binary format to given file.
 *
 * \param dname Dname whose labels are to be dumped.
 * \param f Output file.
 */
static int knot_labels_dump_binary(const knot_dname_t *dname, int fd,
                                   uint8_t *stream, size_t max_size,
                                   size_t *written_bytes, crc_t *crc)
{
	if (dname == NULL) {
		dbg_zdump("zdump: dump_labels: NULL dname.\n");
		return KNOT_EBADARG;
	}
	
	uint16_t label_count = dname->label_count;
	if (!write_wrapper(&label_count, sizeof(label_count), 1, fd, stream,
	                   max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_labels: Could not write label count.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(dname->labels, sizeof(uint8_t), dname->label_count,
	                   fd, stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_labels: Could not write labels.\n");
		return KNOT_ERROR;
	}
	
	dbg_zdump_verb("zdump: dump_labels: Labels dumped successfully.\n");
	return KNOT_EOK;
}

/*!
 * \brief Dumps dname in binary format to given file.
 *
 * \param dname Dname to be dumped.
 * \param f Output file.
 */
static int knot_dname_dump_binary(const knot_dname_t *dname, int fd,
                                  uint8_t *stream, size_t max_size,
                                  size_t *written_bytes,
                                  crc_t *crc)
{
	if (dname == NULL) {
		dbg_zdump("zdump: dump_dname: NULL dname.\n");
		return KNOT_EBADARG;
	}
	
	/*! \todo too big */
	uint32_t dname_size = dname->size;
	if (!write_wrapper(&dname_size, sizeof(dname_size), 1, fd, stream,
	                   max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_dname: Cannot write dname size.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(dname->name, sizeof(uint8_t), dname->size, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_dname: Cannot write dname name.\n");
		return KNOT_ERROR;
	}
	
	dbg_zdump_verb("zdump: dump_dname: Dname dumped successfully.\n");
	return knot_labels_dump_binary(dname, fd, stream, max_size,
	                               written_bytes, crc);
}

/*!< \todo #1684 some global variable indicating error! */
static int dump_dname_with_id(const knot_dname_t *dname, int fd,
                              uint8_t *stream, size_t max_size,
                              size_t *written_bytes, crc_t *crc)
{
	if (dname == NULL) {
		dbg_zdump("zdump: dump_dname: NULL dname.\n");
		return KNOT_EBADARG;
	}
	
	uint32_t id = dname->id;
	if (!write_wrapper(&id, sizeof(id), 1, fd, stream, max_size,
	                   written_bytes, crc)) {
		dbg_zdump("zdump: dump_dname: Cannot write ID.\n");
		return KNOT_ERROR;
	}
	return knot_dname_dump_binary(dname, fd, stream, max_size,
	                              written_bytes, crc);
}

/*!
 * \brief Dumps given rdata in binary format to given file.
 *
 * \param rdata Rdata to be dumped.
 * \param type Type of rdata.
 * \param data Arguments to be propagated.
 */
static int knot_rdata_dump_binary(knot_rdata_t *rdata,
                                  uint32_t type, int fd, int use_ids,
                                  uint8_t *stream, size_t max_size,
                                  size_t *written_bytes,
                                  crc_t *crc)
{
	if (rdata == NULL) {
		dbg_zdump("zdump: dump_rdata: NULL rdata.\n");
		return KNOT_EBADARG;
	}
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	if (desc->fixed_items) {
		assert(desc->length == rdata->count);
	}
	
	/* Write rdata count. */
	if (!write_wrapper(&(rdata->count),
	                   sizeof(rdata->count), 1, fd, stream, max_size,
	                   written_bytes, crc)) {
		dbg_zdump("zdump: dump_rdata: Could not write RDATA count.\n");
		return KNOT_ERROR;
	}

	for (int i = 0; i < rdata->count; i++) {
		if (&(rdata->items[i]) == NULL) {
			dbg_zdump("zdump: dump_rdata: "
			          "Item n. %d is not set!\n", i);
			continue;
		}
		dbg_zdump_detail("zdump: dump_rdata: Dumping item nr: %d\n", i);
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
				if (!write_wrapper(&id,
				                   sizeof(id),
				                   1, fd, stream, max_size,
				                   written_bytes, crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write dname ID.\n");
					return KNOT_ERROR;
				}
			} else {
				int ret = dump_dname_with_id(
				                        rdata->items[i].dname,
				                        fd, stream,
				                        max_size,
				                        written_bytes,
				                        crc);
				if (ret != KNOT_EOK) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "dump dname.\n");
					return ret;
				}
			}

			/* Write in the zone bit */
			/*! \todo Does not have to be so complex.
			 *        Create extra variable. */
			if (rdata->items[i].dname->node != NULL && !wildcard) {
				if (!write_wrapper((uint8_t *)"\1",
				                   sizeof(uint8_t), 1, fd,
				                   stream, max_size,
				                   written_bytes, crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write zone bit.\n");
					return KNOT_ERROR;
				}
			} else {
				if (!write_wrapper((uint8_t *)"\0",
				                   sizeof(uint8_t),
				                   1, fd,
				                   stream, max_size,
				                   written_bytes, crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write zone bit.\n");
					return KNOT_ERROR;
				}
			}

			if (use_ids && wildcard) {
				if (!write_wrapper((uint8_t *)"\1",
				                   sizeof(uint8_t), 1,
				                   fd, stream, max_size,
				                   written_bytes, crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write wildcard bit.\n");
					return KNOT_ERROR;
				}
				
				uint32_t wildcard_id = wildcard->id;
				if (!write_wrapper(&wildcard_id,
				                   sizeof(wildcard_id), 1,
				                   fd, stream, max_size,
				                   written_bytes, crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write wildcard ID.\n");
					return KNOT_ERROR;
				}
			} else {
				if (!write_wrapper((uint8_t *)"\0",
				                   sizeof(uint8_t),
				                   1, fd, stream,
				                   max_size, written_bytes,
				                   crc)) {
					dbg_zdump("zdump: dump_rdata: Cannot "
					          "write wildcard bit.\n");
					return KNOT_ERROR;
				}
			}
		} else {
			dbg_zdump_detail("zdump: dump_rdata: "
			                 "Writing raw data. Item nr.: %d\n",
			                 i);
			assert(rdata->items[i].raw_data != NULL);
			if (!write_wrapper(rdata->items[i].raw_data,
			                   sizeof(uint8_t),
			                   rdata->items[i].raw_data[0] + 2, fd,
			                   stream, max_size,
			                   written_bytes, crc)) {
				dbg_zdump("zdump: dump_rdata: Cannot write raw "
				          "data.\n");
				return KNOT_ERROR;
			}

			dbg_zdump_detail("zdump: dump_rdata: "
			                  "Written %d long raw data.\n",
					  rdata->items[i].raw_data[0]);
		}
	}
	
	dbg_zdump_verb("zdump: dump_rdata: RDATA dumped successfully.\n");
	return KNOT_EOK;
}

/*!
 * \brief Dumps RRSIG in binary format to given file.
 *
 * \param rrsig RRSIG to be dumped.
 * \param data Arguments to be propagated.
 *
 * \todo This whole function is obsolete. Change after 1.0.2 release.
 */
static int knot_rrsig_set_dump_binary(knot_rrset_t *rrsig, int fd,
                                      int use_ids,
                                      uint8_t *stream, size_t max_size,
                                      size_t *written_bytes, crc_t *crc)
{
	if (rrsig == NULL) {
		dbg_zdump("zdump: dump_rrsig: NULL RRSIG.\n");
		return KNOT_EBADARG;
	}
	
dbg_zdump_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(rrsig));
	dbg_zdump_detail("zdump: dump_rrsig: Dumping RRSIG \\w owner: %s.\n",
	                 name);
	free(name);
);
	assert(rrsig->type == KNOT_RRTYPE_RRSIG);
	assert(rrsig->rdata);
	if (!write_wrapper(&rrsig->type, sizeof(rrsig->type), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrsig: Cannot write type.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(&rrsig->rclass, sizeof(rrsig->rclass), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrsig: Cannot write class.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(&rrsig->ttl, sizeof(rrsig->ttl), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrsig: Cannot write TTL.\n");
		return KNOT_ERROR;
	}
	
	uint32_t rdata_count = 1;
	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrsig->rdata;
	while(tmp_rdata->next != rrsig->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	
	if (!write_wrapper(&rdata_count, sizeof(rdata_count), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrsig: Cannot write rdata count.\n");
		return KNOT_ERROR;
	}

	dbg_zdump_verb("zdump: dump_rrsig: Static data dumped.\n");

	tmp_rdata = rrsig->rdata;
	while (tmp_rdata->next != rrsig->rdata) {
		int ret = knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG,
		                                 fd,
		                                 use_ids, stream, max_size,
		                                 written_bytes, crc);
		if (ret != KNOT_EOK) {
			dbg_zdump("zdump: rrsig_to_binary: Could not dump "
			          "rdata. Reason: %s.\n", knot_strerror(ret));
			return ret;
		}
		tmp_rdata = tmp_rdata->next;
	}
	return knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG, fd, use_ids,
	                       stream, max_size, written_bytes, crc);
}

/*!
 * \brief Dumps RRSet in binary format to given file.
 *
 * \param rrset RRSSet to be dumped.
 * \param data Arguments to be propagated.
 */
static int knot_rrset_dump_binary(const knot_rrset_t *rrset, int fd,
                                  int use_ids,
                                  uint8_t *stream, size_t max_size,
                                  size_t *written_bytes,
                                  crc_t *crc)
{
	if (rrset == NULL) {
		dbg_zdump("zdump: dump_rrset: NULL RRSet.\n");
		return KNOT_EBADARG;
	}
	
	dbg_zdump_exec_detail(
		char *name = knot_dname_to_str(knot_rrset_owner(rrset));
		dbg_zdump_detail("zdump: dump_rrset: "
	                         "Dumping RRSet \\w owner: %s.\n",
		                 name);
		free(name);
	);	
	
	if (!use_ids) {
		/*!< \todo IDs in changeset do no good. Change loading too. */
		int ret = dump_dname_with_id(rrset->owner,
		                             fd, stream, max_size,
		                             written_bytes, crc);
		if (ret != KNOT_EOK) {
			dbg_zdump("zdump: rrset_dump_binary: Could not dump "
			          "RRSet's owner.\n");
			return ret;
		}
	}

	if (!write_wrapper(&rrset->type, sizeof(rrset->type), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrset: Cannot write type.\n");
		return KNOT_ERROR;
	}
	if (!write_wrapper(&rrset->rclass, sizeof(rrset->rclass), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrset: Cannot write class.\n");
		return KNOT_ERROR;
	}
	if (!write_wrapper(&rrset->ttl, sizeof(rrset->ttl), 1, fd,
	               stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrset: Cannot write TTL.\n");
		return KNOT_ERROR;
	}

	uint32_t rdata_count = 1;
	uint8_t has_rrsig = rrset->rrsigs != NULL;

	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrset->rdata;
	while(tmp_rdata->next != rrset->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}

	if (!write_wrapper(&rdata_count, sizeof(rdata_count), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_rrset: Cannot write rdata count.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(&has_rrsig, sizeof(has_rrsig), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		return KNOT_ERROR;
	}
	
	dbg_zdump_verb("zdump: rrset_dump_binary: Static data dumped.\n");

	tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		int ret = knot_rdata_dump_binary(tmp_rdata, rrset->type,
		                                 fd, use_ids,
		                                 stream, max_size,
		                                 written_bytes, crc);
		if (ret != KNOT_EOK) {
			dbg_zdump("zdump: rrset_to_binary: Could not dump "
			          "rdata. Reason: %s.\n", knot_strerror(ret));
			return ret;
		}
		tmp_rdata = tmp_rdata->next;
	}
	
	int ret = knot_rdata_dump_binary(tmp_rdata, rrset->type, fd, use_ids,
	                                 stream,
	                                 max_size, written_bytes, crc);
	if (ret != KNOT_EOK) {
		dbg_zdump("zdump: rrset_to_binary: Could not dump "
		          "rdata. Reason: %s.\n", knot_strerror(ret));
		return ret;
	}
	
	dbg_zdump_verb("zdump: rrset_dump_binary: Rdata dumped.\n");

	/* This is now obsolete, although I'd rather not use recursion - that
	 * would probably not work */

	if (rrset->rrsigs != NULL) {
		return knot_rrsig_set_dump_binary(rrset->rrsigs, fd, use_ids,
		                                  stream,
		                                  max_size, written_bytes, crc);
	} else {
		return KNOT_EOK;
	}
}

/*!
 * \brief Dumps all RRSets in node to file in binary format.
 *
 * \param node Node to dumped.
 * \param data Arguments to be propagated.
 */
static int knot_node_dump_binary(knot_node_t *node, int fd,
                                 uint8_t *stream,
                                 size_t max_size,
                                 size_t *written_bytes,
                                 crc_t *crc)
{
	if (node == NULL) {
		dbg_zdump("zdump: dump_node: NULL node.\n");
		return KNOT_EBADARG;
	}
	
	/* first write dname */
	assert(node->owner != NULL);

	/* Write owner ID. */
dbg_zdump_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_zdump_detail("zdump: dump_node: Dumping node owned by %s\n",
	                 name);
	free(name);
);
	assert(node->owner->id != 0);
	uint32_t owner_id = node->owner->id;
	if (!write_wrapper(&owner_id, sizeof(owner_id), 1, fd, stream,
	                   max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_node: Cannot write ID.\n");
		return KNOT_ERROR;
	}

	/*!< \todo Fix after release. */
	if (knot_node_parent(node) != NULL) {
		uint32_t parent_id = knot_dname_id(
				knot_node_owner(knot_node_parent(node)));
		if (!write_wrapper(&parent_id, sizeof(parent_id), 1, fd,
		                   stream, max_size, written_bytes, crc)) {
			dbg_zdump("zdump: dump_node: Cannot write parent "
			          "ID.\n");
			return KNOT_ERROR;
		}
	} else {
		uint32_t parent_id = 0;
		if (!write_wrapper(&parent_id, sizeof(parent_id), 1, fd,
		                   stream, max_size, written_bytes, crc)) {
			dbg_zdump("zdump: dump_node: Cannot write parent "
			          "ID.\n");
			return KNOT_ERROR;
		}
	}

	if (!write_wrapper(&(node->flags), sizeof(node->flags), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_node: Cannot write node flags.\n");
		return KNOT_ERROR;
	}

	if (knot_node_nsec3_node(node) != NULL) {
		uint32_t nsec3_id =
			knot_node_owner(knot_node_nsec3_node(node))->id;
		if (!write_wrapper(&nsec3_id, sizeof(nsec3_id), 1, fd,
		                   stream, max_size, written_bytes, crc)) {
			dbg_zdump("zdump: dump_node: Cannot write NSEC3 ID.\n");
			return KNOT_ERROR;
		}
		
		dbg_zdump_detail("Written nsec3 node id: %u\n",
			         knot_node_owner(
		                         knot_node_nsec3_node(node))->id);
	} else {
		uint32_t nsec3_id = 0;
		if (!write_wrapper(&nsec3_id, sizeof(nsec3_id), 1, fd,
		                   stream, max_size, written_bytes, crc)) {
			dbg_zdump("zdump: dump_node: Cannot write NSEC3 ID.\n");
			return KNOT_ERROR;
		}
	}

	/* Now we need (or do we?) count of rrsets to be read
	 * but that number is yet unknown */

	uint16_t rrset_count = node->rrset_count;
	if (!write_wrapper(&rrset_count, sizeof(rrset_count), 1, fd,
	                   stream, max_size, written_bytes, crc)) {
		dbg_zdump("zdump: dump_node: Cannot write RRSet count.\n");
		return KNOT_ERROR;
	}

	const knot_rrset_t **node_rrsets = knot_node_rrsets(node);
	for (int i = 0; i < rrset_count; i++)
	{
		int ret = knot_rrset_dump_binary(node_rrsets[i], fd, 1,
		                                 stream, max_size,
		                                 written_bytes, crc);
		if (ret != KNOT_EOK) {
			dbg_zdump("zdump: dump_node: Could not dump RRSet. "
			          "Reason: %s.\n", knot_strerror(ret));
			return ret;
		}
	}

	free(node_rrsets);
	
	dbg_zdump_verb("zdump: dump_node: Node dumped successfully.\n");

	return KNOT_EOK;
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
	if (arg->error_code != KNOT_EOK) {
		dbg_zdump("zdump: dump_dname_from_tree: "
		          "Error occured previously.\n");
		return;
	}
	
	int *fd_pointer = (int *)arg->arg1;
	int fd = -1;
	if (fd_pointer != NULL) {
		fd = *fd_pointer;
	} else {
		dbg_zdump("zdump: dump_dname_from_tree: Bad fd.\n");
		arg->error_code = KNOT_EBADARG;
		return;
	}
	
	uint8_t *buffer = (uint8_t *)arg->arg5;
	size_t *written_bytes = (size_t *)arg->arg6;
	crc_t *crc = (crc_t*)arg->arg2;
	
	arg->error_code = dump_dname_with_id(dname, fd, buffer,
	                                     BUFFER_SIZE, written_bytes, crc);
}

static int knot_dump_dname_table(const knot_dname_table_t *dname_table,
				 int fd, crc_t *crc, uint8_t *buffer,
                                 size_t *written_bytes)
{
	arg_t arg;
	arg.arg2 = crc;
	arg.arg5 = buffer;
	arg.arg6 = written_bytes;
	arg.arg1 = &fd;
	assert(arg.arg1 == &fd);
	arg.error_code = KNOT_EOK;
	/* Go through the tree and dump each dname along with its ID. */
	knot_dname_table_tree_inorder_apply(dname_table,
					    dump_dname_from_tree, &arg);

	return arg.error_code;
}

static void save_node_from_tree(knot_node_t *node, void *data)
{
	arg_t *arg = (arg_t *)data;
	if (arg == NULL) {
		return;
	}
	
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
	if (arg == NULL) {
		return;
	}
	
	if (arg->error_code != KNOT_EOK) {
		dbg_zdump("zdump: dump_node_to_file: "
		          "Error occured previously.\n");
		return;
	}
	
	int *fd_pointer = (int *)arg->arg1;
	int fd = -1;
	if (fd_pointer != NULL) {
		fd = *fd_pointer;
	}
	
	uint8_t *buffer = (uint8_t *)arg->arg5;
	size_t *written_bytes = (size_t *)arg->arg6;
	
	arg->error_code =
		knot_node_dump_binary(node,
	                              fd, buffer, BUFFER_SIZE, written_bytes,
	                              (crc_t *)arg->arg7);
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
		dbg_zdump("zdump: Bad arguments.\n");
		return KNOT_EBADARG;
	}
	
	dbg_zdump("zdump: Dumping zone %p.\n", zone);
	
	uint8_t buffer[BUFFER_SIZE];
	size_t written_bytes = 0;

	arg_t arguments;
	/* Memory to be derefenced in the save_node_from_tree function. */
	uint32_t node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of normal nodes. This cannot fail. */
	knot_zone_contents_tree_apply_inorder(zone, save_node_from_tree,
	                                      &arguments);
	/* arg1 is now count of normal nodes */
	uint32_t normal_node_count = *((uint32_t *)arguments.arg1);

	node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of NSEC3 nodes. This cannot fail. */
	knot_zone_contents_nsec3_apply_inorder(zone,
	                                       save_node_from_tree, &arguments);
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
	if (!write_wrapper(&MAGIC, sizeof(uint8_t), MAGIC_LENGTH,
	                   fd, buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write magic bytes.\n");
		return KNOT_ERROR;
	}

	/* Write source file length. */
	uint32_t sflen = strlen(sfilename) + 1;
	if (!write_wrapper(&sflen, sizeof(uint32_t), 1, fd,
	                   buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write source file length.\n");
		return KNOT_ERROR;
	}

	/* Write source file. */
	if (!write_wrapper(sfilename, sflen, 1, fd,  buffer,
	                   BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write source file name.\n");
		return KNOT_ERROR;
	}

	/* Notice: End of header,
	 */

	/* Start writing compiled data. */
	if (!write_wrapper(&normal_node_count, sizeof(normal_node_count), 1, fd,
	                    buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write node count.\n");
		return KNOT_ERROR;
	}
	
	if (!write_wrapper(&nsec3_node_count, sizeof(nsec3_node_count), 1, fd,
	                   buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write NSEC3 node count.\n");
		return KNOT_ERROR;
	}
	uint32_t auth_node_count = zone->node_count;
	if (!write_wrapper(&auth_node_count,
	                   sizeof(auth_node_count),
	                   1, fd,  buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write authoritative node count.\n");
		return KNOT_ERROR;
	}

	/* Write total number of dnames */
	assert(zone->dname_table);
	uint32_t total_dnames = zone->dname_table->id_counter;
	if (!write_wrapper(&total_dnames,
	                   sizeof(total_dnames), 1, fd,
	                   buffer, BUFFER_SIZE, &written_bytes, crc)) {
		dbg_zdump("zdump: Cannot write dname count.\n");
		return KNOT_ERROR;
	}

	/* Write dname table. */
	if (knot_dump_dname_table(zone->dname_table, fd, crc, buffer,
	                          &written_bytes)
	    != KNOT_EOK) {
		dbg_zdump("zdump: Cannot write dname table.\n");
		return KNOT_ERROR;
	}
	
	arguments.arg1 = &fd;
	arguments.arg3 = zone;
	arguments.arg5 = buffer;
	arguments.arg6 = &written_bytes;
	arguments.arg7 = crc;
	
	arguments.error_code = KNOT_EOK;

	/*!< \todo #1685 Stop traversal upon error. */
	knot_zone_contents_tree_apply_inorder(zone, dump_node_to_file,
				       (void *)&arguments);
	
	if (arguments.error_code != KNOT_EOK) {
		dbg_zdump("zdump: Dump of normal tree failed. Reason: %s.\n",
		          knot_strerror(arguments.error_code));
		return arguments.error_code;
	}
	
	arguments.error_code = KNOT_EOK;
	knot_zone_contents_nsec3_apply_inorder(zone, dump_node_to_file,
					(void *)&arguments);
	
	if (arguments.error_code != KNOT_EOK) {
		dbg_zdump("zdump: Dump of NSEC3 tree failed. Reason: %s.\n",
		          knot_strerror(arguments.error_code));
		return arguments.error_code;
	}
	
	/* Finish the dump. */
	if (!write_to_file_crc(buffer, 1, written_bytes, fd, crc)) {
		dbg_zdump("zdump: Failed to finalize dump.\n");
		return KNOT_ERROR;
	}
	
	
	*crc = crc_finalize(*crc);
	dbg_zdump("zdump: Zone %p dumped successfully.\n", zone);
	
	return KNOT_EOK;
}

int knot_zdump_rrset_serialize(const knot_rrset_t *rrset, uint8_t *stream,
                                 size_t max_size, size_t *written_bytes)
{
	if (stream == NULL || rrset == NULL ||
	    written_bytes == NULL) {
		dbg_zdump("zdump: rrset_serialize: Bad arguments.\n");
		return KNOT_EBADARG;
	}
	
	*written_bytes = 0;

	/* This fd will signal functions to use streams. */
	int fd = -1;

	return knot_rrset_dump_binary(rrset, fd, 0, stream, max_size,
	                              written_bytes, NULL);
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
