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

#include "packet/response.h"
#include "util/wire.h"
#include "util/descriptor.h"
#include "common.h"
#include "util/debug.h"
#include "packet/packet.h"
#include "edns.h"

#define COMPRESSION_PEDANTIC

/*----------------------------------------------------------------------------*/
/*!
 * \brief Holds information about compressed domain name.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct knot_compr_owner {
	/*!
	 * \brief Place where the name is stored in the wire format of the
	 * packet.
	 */
	uint8_t *wire;
	short size; /*!< Size of the domain name in bytes. */
	/*! \brief Position of the name relative to the start of the packet. */
	size_t pos;
};

typedef struct knot_compr_owner knot_compr_owner_t;

/*!
 * \brief Holds information about compressed domain names in packet.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct knot_compr {
	knot_compressed_dnames_t *table;  /*!< Compression table. */
	size_t wire_pos;            /*!< Current position in the wire format. */
	knot_compr_owner_t owner; /*!< Information about the current name. */
};

typedef struct knot_compr knot_compr_t;

static const size_t KNOT_RESPONSE_MAX_PTR = 16383;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocates space for compression table.
 *
 * \param table Compression table to reallocate space for.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_realloc_compr(knot_compressed_dnames_t *table)
{
	int free_old = table->max != table->default_count;
	size_t *old_offsets = table->offsets;
	int *old_to_free = table->to_free;
	const knot_dname_t **old_dnames = table->dnames;

	short new_max_count = table->max + STEP_DOMAINS;

	size_t *new_offsets = (size_t *)malloc(new_max_count * sizeof(size_t));
	CHECK_ALLOC_LOG(new_offsets, -1);

	int *new_to_free = (int *)malloc(new_max_count * sizeof(int));
	if (new_to_free == NULL) {
		ERR_ALLOC_FAILED;
		free(new_offsets);
		return KNOT_ENOMEM;
	}

	const knot_dname_t **new_dnames = (const knot_dname_t **)malloc(
		new_max_count * sizeof(knot_dname_t *));
	if (new_dnames == NULL) {
		ERR_ALLOC_FAILED;
		free(new_offsets);
		free(new_to_free);
		return KNOT_ENOMEM;
	}

	memcpy(new_offsets, table->offsets, table->max * sizeof(size_t));
	memcpy(new_to_free, table->to_free, table->max * sizeof(int));
	memcpy(new_dnames, table->dnames,
	       table->max * sizeof(knot_dname_t *));

	table->offsets = new_offsets;
	table->to_free = new_to_free;
	table->dnames = new_dnames;
	table->max = new_max_count;

	if (free_old) {
		free(old_offsets);
		free(old_to_free);
		free(old_dnames);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Stores new mapping between domain name and offset in the compression
 *        table.
 *
 * If the domain name is already present in the table, it is not inserted again.
 *
 * \param table Compression table to save the mapping into.
 * \param dname Domain name to insert.
 * \param pos Position of the domain name in the packet's wire format.
 */
static void knot_response_compr_save(knot_compressed_dnames_t *table,
                                     const knot_dname_t *dname, size_t pos,
                                     int copied_dname)
{
	assert(table->count < table->max);

	for (int i = 0; i < table->count; ++i) {
		if (table->dnames[i] == dname) {
			dbg_response("Already present, skipping..\n");
			return;
		}
	}

	table->dnames[table->count] = dname;
	table->offsets[table->count] = pos;
	table->to_free[table->count] = copied_dname;
	++table->count;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Stores domain name position and positions of its parent domain names
 *        to the compression table.
 *
 * If part of the domain name (\a dname) was not found previously in the
 * compression table, this part and all its parent domains is stored also, to
 * maximize compression potential.
 *
 * \param table Compression table to save the information into.
 * \param dname Domain name to save.
 * \param not_matched Count of labels not matched when previously searching in
 *                    the compression table for \a dname.
 * \param pos Position of the domain name in the wire format of the packet.
 * \param unmatched_offset Position of the unmatched parent domain of \a dname.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_store_dname_pos(knot_compressed_dnames_t *table,
                                           const knot_dname_t *dname,
                                           int not_matched, size_t pos,
                                           size_t unmatched_offset,
                                           int compr_cs)
{
dbg_response_exec(
	char *name = knot_dname_to_str(dname);
	dbg_response_detail("Putting dname %s into compression table."
	                    " Labels not matched: %d, position: %zu,"
	                    ", pointer: %p, unmatched off: %zu\n", name,
	                    not_matched, pos, dname, unmatched_offset);
	free(name);
);
	if (pos > KNOT_RESPONSE_MAX_PTR) {
		dbg_response("Pointer larger than it can be, not saving\n");
		return KNOT_EDNAMEPTR;
	}

	if (table->count == table->max &&
	    knot_response_realloc_compr(table) != 0) {
		return KNOT_ENOMEM;
	}

	/*
	 * Store positions of ancestors if more than 1 label was not matched.
	 *
	 * In case the name is not in the zone, the counting to not_matched
	 * may be limiting, because the search stopped before after the first
	 * label (i.e. not_matched == 1). So we do not store the parents in
	 * this case. However, storing them will require creating those domain
	 * names, as they do not exist.
	 *
	 * The same problem is with domain names synthetized from wildcards.
	 * These also do not have any node to follow.
	 *
	 * We accept this as performance has higher
	 * priority than the best possible compression.
	 */
	const knot_dname_t *to_save = dname;
	size_t parent_pos = pos;
	int i = 0, copied = 0;

	while (to_save != NULL && i < knot_dname_label_count(dname)
	       && parent_pos <= KNOT_RESPONSE_MAX_PTR) {
		if (i == not_matched) {
			parent_pos = unmatched_offset;
		}

dbg_response_exec_detail(
		char *name = knot_dname_to_str(to_save);
		dbg_response_detail("Putting dname %s into compression table."
		                    " Position: %zu, pointer: %p\n",
		                    name, parent_pos, to_save);
		free(name);
);

		if (table->count == table->max &&
		    knot_response_realloc_compr(table) != 0) {
			dbg_response("Unable to realloc.\n");
			return KNOT_ENOMEM;
		}

		knot_response_compr_save(table, to_save, parent_pos, copied);

		/*! \todo Remove '!compr_cs'. */
		// This is a temporary hack to avoid the wrong behaviour
		// when the wrong not_matched count is used to compare with i
		// and resulting in using the 0 offset.
		// If case-sensitive search is in place, we should not save the
		// node's parent's positions.
		
		// Added check to rule out wildcard-covered dnames
		// (in such case the offset is not right)

		/*! \todo The whole compression requires a serious refactoring.
		 *        Or better - a rewrite!
		 */
		const knot_dname_t *to_save_new =
		          (!compr_cs && knot_dname_node(to_save) != NULL
		           && knot_node_owner(knot_dname_node(to_save))
		              !=  to_save
		           && knot_node_parent(knot_dname_node(to_save))
		              != NULL)
		                ? knot_node_owner(knot_node_parent(
		                        knot_dname_node(to_save)))
		                : NULL;

#ifdef COMPRESSION_PEDANTIC
		if (to_save_new == NULL) {
			// copied name - must be freed later
			to_save_new = knot_dname_left_chop(to_save);
			copied = 1;
		} else {
			copied = 0;
		}
#endif

		to_save = to_save_new;

		dbg_response("i: %d\n", i);
		parent_pos += knot_dname_label_size(dname, i) + 1;
		++i;
	}

	if (copied == 1 && to_save != NULL) {
		// The last name was not used, free it
		dbg_response("Freeing last chopped dname.\n");
		knot_dname_release((knot_dname_t *)to_save);
	}

	return KNOT_EOK;
}

/*---------------------------------------------------------------------------*/
/*!
 * \brief Tries to find offset of domain name in the compression table.
 *
 * \param table Compression table to search in.
 * \param dname Domain name to search for.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \return Offset of \a dname stored in the compression table or -1 if the name
 *         was not found in the table.
 */
static size_t knot_response_find_dname_pos(
               const knot_compressed_dnames_t *table,
               const knot_dname_t *dname, int compr_cs)
{
	for (int i = 0; i < table->count; ++i) {
		int ret = (compr_cs)
		           ? knot_dname_compare_cs(table->dnames[i], dname)
		           : knot_dname_compare(table->dnames[i], dname);
		if (ret == 0) {
			dbg_response_detail("Found offset: %zu\n",
			                    table->offsets[i]);
			return table->offsets[i];
		}
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
/*!
 * \brief Put a compressed domain name to the wire format of the packet.
 *
 * Puts the not matched part of the domain name to the wire format and puts
 * a pointer to the rest of the name after that.
 *
 * \param dname Domain name to put to the wire format.
 * \param not_matched Size of the part of domain name that cannot be compressed.
 * \param offset Position of the rest of the domain name in the packet's wire
 *               format.
 * \param wire Place where to put the wire format of the name.
 * \param max Maximum available size of the place for the wire format.
 *
 * \return Size of the compressed domain name put into the wire format or
 *         KNOT_ESPACE if it did not fit.
 */
static int knot_response_put_dname_ptr(const knot_dname_t *dname,
                                         int not_matched, size_t offset,
                                         uint8_t *wire, size_t max)
{
	// put the not matched labels
	short size = knot_dname_size_part(dname, not_matched);
	if (size + 2 > max) {
		return KNOT_ESPACE;
	}

	memcpy(wire, knot_dname_name(dname), size);
	knot_wire_put_pointer(wire + size, offset);

	dbg_response_detail("Size of the dname with ptr: %d\n", size + 2);
	
	return size + 2;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to compress domain name and creates its wire format.
 *
 * \param dname Domain name to convert and compress.
 * \param compr Compression table holding information about offsets of domain
 *              names in the packet.
 * \param dname_wire Place where to put the wire format of the name.
 * \param max Maximum available size of the place for the wire format.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \return Size of the domain name's wire format or KNOT_ESPACE if it did not
 *         fit into the provided space.
 */
static int knot_response_compress_dname(const knot_dname_t *dname,
	knot_compr_t *compr, uint8_t *dname_wire, size_t max, int compr_cs)
{
	int size = 0;
	if (!dname || !compr || !dname_wire) {
		return KNOT_EINVAL;
	}

	// try to find the name or one of its ancestors in the compr. table
#ifdef COMPRESSION_PEDANTIC
	knot_dname_t *to_find = (knot_dname_t *)dname;
	int copied = 0;
#else
	const knot_dname_t *to_find = dname;
#endif
	size_t offset = 0;
	int not_matched = 0;

	while (to_find != NULL && knot_dname_label_count(to_find) != 0) {
dbg_response_exec_detail(
		char *name = knot_dname_to_str(to_find);
		dbg_response_detail("Searching for name %s in the compression"
		                    " table, not matched labels: %d\n", name,
		                    not_matched);
		free(name);
);
		offset = knot_response_find_dname_pos(compr->table, to_find,
		                                        compr_cs);
		if (offset == 0) {
			++not_matched;
		} else {
			break;
		}
#ifdef COMPRESSION_PEDANTIC
		if (compr_cs || to_find->node == NULL
		    || to_find->node->owner != to_find
		    || to_find->node->parent == NULL) {
			if (!copied) {
				to_find = knot_dname_left_chop(to_find);
				copied = 1;
			} else {
				knot_dname_left_chop_no_copy(to_find);
			}
		} else {
			assert(knot_dname_node(to_find) !=
			       knot_node_parent(knot_dname_node(to_find)));
			assert(to_find != knot_node_owner(
			    knot_node_parent(knot_dname_node(to_find))));
			to_find = knot_node_get_owner(
			            knot_node_parent(knot_dname_node(to_find)));
		}
		dbg_response_detail("New to_find: %p\n", to_find);
#else
		// if case-sensitive comparation, we cannot just take the parent
		if (compr_cs || knot_dname_node(to_find) == NULL
		    || knot_node_owner(knot_dname_node(to_find)) != to_find
		    || knot_node_parent(knot_dname_node(to_find))
		       == NULL) {
			dbg_response_detail("compr_cs: %d\n", compr_cs);
			dbg_response_detail("knot_dname_node(to_find, 1) == %p"
			                    "\n", knot_dname_node(to_find));
			
			if (knot_dname_node(to_find) != NULL) {
				dbg_response_detail("knot_node_owner(knot_dname_node("
				             "to_find, 1)) = %p, to_find = %p\n",
				             knot_node_owner(knot_dname_node(to_find)),
				             to_find);
				dbg_response_detail("knot_node_parent(knot_dname_node("
				                    "to_find, 1), 1) = %p\n",
				      knot_node_parent(knot_dname_node(to_find)));
			}
			break;
		} else {
			assert(knot_dname_node(to_find) !=
			     knot_node_parent(knot_dname_node(to_find)));
			assert(to_find != knot_node_owner(
			    knot_node_parent(knot_dname_node(to_find))));
			to_find = knot_node_owner(
			     knot_node_parent(knot_dname_node(to_find)));
			dbg_response_detail("New to_find: %p\n", to_find);
		}
#endif
	}

#ifdef COMPRESSION_PEDANTIC
	if (copied) {
		knot_dname_free(&to_find);
	}
#endif

	dbg_response_detail("Max size available for domain name: %zu\n", max);
	
	if (offset > 0) {
		// found such dname somewhere in the packet
		// the pointer should be legal as no illegal pointers are stored
		assert(offset <= KNOT_RESPONSE_MAX_PTR);
		dbg_response_detail("Found name in the compression table.\n");
		assert(offset >= KNOT_WIRE_HEADER_SIZE);
		size = knot_response_put_dname_ptr(dname, not_matched, offset,
		                                     dname_wire, max);
		if (size <= 0) {
			return KNOT_ESPACE;
		}
	} else {
		dbg_response_detail("Not found, putting whole name.\n");
		// now just copy the dname without compressing
		if (dname->size > max) {
			return KNOT_ESPACE;
		}

		memcpy(dname_wire, dname->name, dname->size);
		size = dname->size;
	}

	// in either way, put info into the compression table
	/*! \todo This is useless if the name was already in the table. 
	 *        It is meaningful only if the found name is the one from QNAME
	 *        and thus its parents are not stored yet.
	 */
	// only put legal pointers (#2131)
	if (knot_response_store_dname_pos(compr->table, dname, not_matched,
	                                     compr->wire_pos, offset, compr_cs)
	    != 0) {
		dbg_response_detail("Compression info could not be stored.\n");
	}

	return size;
}

/*---------------------------------------------------------------------------*/
/*!
 * \brief Convert one RR into wire format.
 *
 * \param[in] rrset RRSet to which the RR belongs.
 * \param[in] rdata The actual RDATA of this RR.
 * \param[in] compr Information about compressed domain names in the packet.
 * \param[out] rrset_wire Place to put the wire format of the RR into.
 * \param[in] max_size Size of space available for the wire format.
 * \param[in] compr_cs Set to <> 0 if dname compression should use case
 *                     sensitive comparation. Set to 0 otherwise.
 *
 * \return Size of the RR's wire format or KNOT_ESPACE if it did not fit into
 *         the provided space.
 */
static int knot_response_rr_to_wire(const knot_rrset_t *rrset,
                                      const knot_rdata_t *rdata,
                                      knot_compr_t *compr,
                                      uint8_t **rrset_wire, size_t max_size,
                                      int compr_cs)
{
	int size = 0;
	
	dbg_response_detail("Max size: %zu, owner pos: %zu, owner size: %d\n",
	                    max_size, compr->owner.pos, compr->owner.size);

	if (size + ((compr->owner.pos == 0
	             || compr->owner.pos > KNOT_RESPONSE_MAX_PTR) 
		? compr->owner.size : 2) + 10
	    > max_size) {
		return KNOT_ESPACE;
	}

	dbg_response_detail("Owner position: %zu\n", compr->owner.pos);

	// put owner if needed (already compressed)
	if (compr->owner.pos == 0 || compr->owner.pos > KNOT_RESPONSE_MAX_PTR) {
		memcpy(*rrset_wire, compr->owner.wire, compr->owner.size);
		compr->owner.pos = compr->wire_pos;
		*rrset_wire += compr->owner.size;
		size += compr->owner.size;
	} else {
		dbg_response_detail("Putting pointer: %zu\n",
		                    compr->owner.pos);
		knot_wire_put_pointer(*rrset_wire, compr->owner.pos);
		*rrset_wire += 2;
		size += 2;
	}
	
	dbg_response_detail("Max size: %zu, size: %d\n", max_size, size);

	dbg_response_detail("Wire format:\n");

	// put rest of RR 'header'
	knot_wire_write_u16(*rrset_wire, rrset->type);
	dbg_response_detail("  Type: %u\n", rrset->type);
	*rrset_wire += 2;

	knot_wire_write_u16(*rrset_wire, rrset->rclass);
	dbg_response_detail("  Class: %u\n", rrset->rclass);
	*rrset_wire += 2;

	knot_wire_write_u32(*rrset_wire, rrset->ttl);
	dbg_response_detail("  TTL: %u\n", rrset->ttl);
	*rrset_wire += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *rrset_wire;
	*rrset_wire += 2;

	size += 10;
	compr->wire_pos += size;
	
	dbg_response_detail("Max size: %zu, size: %d\n", max_size, size);

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(rrset->type);

	uint16_t rdlength = 0;

	for (int i = 0; i < rdata->count; ++i) {
		if (max_size < size + rdlength) {
			return KNOT_ESPACE;
		}
		
		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME: {
			int ret = knot_response_compress_dname(
				knot_rdata_item(rdata, i)->dname,
				compr, *rrset_wire, max_size - size - rdlength, 
				compr_cs);

			if (ret < 0) {
				return KNOT_ESPACE;
			}

			dbg_response_detail("Compressed dname size: %d\n", ret);
			*rrset_wire += ret;
			rdlength += ret;
			compr->wire_pos += ret;
			// TODO: compress domain name
			break;
		}
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME: {
			knot_dname_t *dname =
				knot_rdata_item(rdata, i)->dname;
			if (size + rdlength + dname->size > max_size) {
				return KNOT_ESPACE;
			}

			// save whole domain name
			memcpy(*rrset_wire, dname->name, dname->size);
			dbg_response_detail("Uncompressed dname size: %d\n",
			                    dname->size);
			*rrset_wire += dname->size;
			rdlength += dname->size;
			compr->wire_pos += dname->size;
			break;
		}
		default: {
			uint16_t *raw_data =
				knot_rdata_item(rdata, i)->raw_data;

			if (size + rdlength + raw_data[0] > max_size) {
				return KNOT_ESPACE;
			}

			// copy just the rdata item data (without size)
			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
			dbg_response_detail("Raw data size: %d\n",
			                    raw_data[0]);
			*rrset_wire += raw_data[0];
			rdlength += raw_data[0];
			compr->wire_pos += raw_data[0];
			break;
		}
		}
	}
	
	dbg_response_detail("Max size: %zu, size: %d\n", max_size, size);

	assert(size + rdlength <= max_size);
	size += rdlength;
	knot_wire_write_u16(rdlength_pos, rdlength);

	return size;
}

/*---------------------------------------------------------------------------*/
/*!
 * \brief Convert whole RRSet into wire format.
 *
 * \param[in] rrset RRSet to convert
 * \param[out] pos Place where to put the wire format.
 * \param[out] size Size of the converted wire format.
 * \param[in] max_size Maximum available space for the wire format.
 * \param wire_pos Current position in the wire format of the whole packet.
 * \param owner_tmp Wire format of the RRSet's owner, possibly compressed.
 * \param compr Information about compressed domain names in the packet.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \return Size of the RRSet's wire format or KNOT_ESPACE if it did not fit
 *         into the provided space.
 */
static int knot_response_rrset_to_wire(const knot_rrset_t *rrset,
                                         uint8_t **pos, size_t *size,
                                         size_t max_size, size_t wire_pos,
                                         uint8_t *owner_tmp,
                                         knot_compressed_dnames_t *compr,
                                         int compr_cs)
{
dbg_response_exec_verb(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_response_verb("Converting RRSet with owner %s, type %s\n",
	                  name, knot_rrtype_to_string(rrset->type));
	free(name);
	dbg_response_verb("  Size before: %zu\n", *size);
);

	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		return KNOT_EOK;
	}

	/*
	 * We may pass the current position to the compression function
	 * because if the owner will be put somewhere, it will be on the
	 * current position (first item of a RR). If it will not be put into
	 * the wireformat, we may remove the dname (and possibly its parents)
	 * from the compression table.
	 */

	knot_compr_t compr_info;
	compr_info.table = compr;
	compr_info.wire_pos = wire_pos;
	compr_info.owner.pos = 0;
	compr_info.owner.wire = owner_tmp;
	compr_info.owner.size =
		knot_response_compress_dname(rrset->owner, &compr_info,
		                               owner_tmp, max_size, compr_cs);

	dbg_response_detail("    Owner size: %d, position: %zu\n",
	                    compr_info.owner.size, compr_info.owner.pos);
	if (compr_info.owner.size < 0) {
		return KNOT_ESPACE;
	}

	int rrs = 0;
	short rrset_size = 0;

	const knot_rdata_t *rdata = rrset->rdata;
	do {
		int ret = knot_response_rr_to_wire(rrset, rdata, &compr_info,
		                                     pos, max_size - rrset_size,
		                                     compr_cs);

		assert(ret != 0);

		if (ret < 0) {
			// some RR didn't fit in, so no RRs should be used
			// TODO: remove last entries from compression table
			dbg_response("Some RR didn't fit in.\n");
			return KNOT_ESPACE;
		}

		dbg_response_verb("RR of size %d added.\n", ret);
		rrset_size += ret;
		++rrs;
	} while ((rdata = knot_rrset_rdata_next(rrset, rdata)) != NULL);


	// the whole RRSet did fit in
	assert (rrset_size <= max_size);
	*size += rrset_size;

	dbg_response_verb("  Size after: %zu\n", *size);

	return rrs;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to add RRSet to the response.
 *
 * This function tries to convert the RRSet to wire format and add it to the
 * wire format of the response and if successful, adds the RRSet to the given
 * list (and updates its size). If the RRSet did not fit into the available
 * space (\a max_size), it is omitted as a whole and the TC bit may be set
 * (according to \a tc).
 *
 * \param rrsets Lists of RRSets to which this RRSet should be added.
 * \param rrset_count Number of RRSets in the list.
 * \param resp Response structure where the RRSet should be added.
 * \param max_size Maximum available space in wire format of the response.
 * \param rrset RRSet to add.
 * \param tc Set to <> 0 if omitting the RRSet should cause the TC bit to be
 *           set in the response.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \return Count of RRs added to the response or KNOT_ESPACE if the RRSet did
 *         not fit in the available space.
 */
static int knot_response_try_add_rrset(const knot_rrset_t **rrsets,
                                        short *rrset_count,
                                        knot_packet_t *resp,
                                        size_t max_size,
                                        const knot_rrset_t *rrset, int tc,
                                        int compr_cs)
{
	//short size = knot_response_rrset_size(rrset, &resp->compression);

dbg_response_exec(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_response_verb("\nAdding RRSet with owner %s and type %s: \n",
	                  name, knot_rrtype_to_string(rrset->type));
	free(name);
);

	uint8_t *pos = resp->wireformat + resp->size;
	size_t size = 0;
	int rrs = knot_response_rrset_to_wire(rrset, &pos, &size, max_size,
	                                        resp->size, resp->owner_tmp,
	                                        &resp->compression, compr_cs);

	if (rrs >= 0) {
		rrsets[(*rrset_count)++] = rrset;
		resp->size += size;
		dbg_response_verb("RRset added, size: %zu, RRs: %d, total "
		                  "size of response: %zu\n\n", size, rrs,
		                  resp->size);
	} else if (tc) {
		dbg_response_verb("Setting TC bit.\n");
		knot_wire_flags_set_tc(&resp->header.flags1);
		knot_wire_set_tc(resp->wireformat);
	}

	return rrs;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocate space for RRSets.
 *
 * \param rrsets Space for RRSets.
 * \param max_count Size of the space available for the RRSets.
 * \param default_max_count Size of the space pre-allocated for the RRSets when
 *        the response structure was initialized.
 * \param step How much the space should be increased.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_realloc_rrsets(const knot_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step)
{
	int free_old = (*max_count) != default_max_count;
	const knot_rrset_t **old = *rrsets;

	short new_max_count = *max_count + step;
	const knot_rrset_t **new_rrsets = (const knot_rrset_t **)malloc(
		new_max_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, KNOT_ENOMEM);

	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(knot_rrset_t *));

	*rrsets = new_rrsets;
	*max_count = new_max_count;

	if (free_old) {
		free(old);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocate space for Wildcard nodes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_realloc_wc_nodes(const knot_node_t ***nodes,
                                          const knot_dname_t ***snames,
                                          short *max_count,
                                          short default_max_count, short step)
{
	dbg_packet_detail("Max count: %d, default max count: %d\n",
	                  *max_count, default_max_count);
	int free_old = (*max_count) != default_max_count;

	const knot_node_t **old_nodes = *nodes;
	const knot_dname_t **old_snames = *snames;

	short new_max_count = *max_count + step;

	const knot_node_t **new_nodes = (const knot_node_t **)malloc(
		new_max_count * sizeof(knot_node_t *));
	CHECK_ALLOC_LOG(new_nodes, KNOT_ENOMEM);

	const knot_dname_t **new_snames = (const knot_dname_t **)malloc(
	                        new_max_count * sizeof(knot_dname_t *));
	if (new_snames == NULL) {
		free(new_nodes);
		return KNOT_ENOMEM;
	}

	memcpy(new_nodes, *nodes, (*max_count) * sizeof(knot_node_t *));
	memcpy(new_snames, *snames, (*max_count) * sizeof(knot_dname_t *));

	*nodes = new_nodes;
	*snames = new_snames;
	*max_count = new_max_count;

	if (free_old) {
		free(old_nodes);
		free(old_snames);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int knot_response_init(knot_packet_t *response)
{
	if (response == NULL) {
		return KNOT_EINVAL;
	}

	if (response->max_size < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_ESPACE;
	}

	// set the qr bit to 1
	knot_wire_flags_set_qr(&response->header.flags1);

	uint8_t *pos = response->wireformat;
	knot_packet_header_to_wire(&response->header, &pos,
	                                &response->size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_init_from_query(knot_packet_t *response,
                                  knot_packet_t *query,
                                  int copy_question)
{

	if (response == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	// copy the header from the query
	memcpy(&response->header, &query->header, sizeof(knot_header_t));

	int err = 0;
	/*! \todo Constant. */
	size_t to_copy = 12;

	if (copy_question) {
		// copy the Question section (but do not copy the QNAME)
		memcpy(&response->question, &query->question,
		       sizeof(knot_question_t));

		// put the qname into the compression table
		// TODO: get rid of the numeric constants
		if ((err = knot_response_store_dname_pos(&response->compression,
			      response->question.qname, 0, 12, 12, 0))
		                != KNOT_EOK) {
			return err;
		}

		/*! \todo Constant. */
		to_copy += 4 + knot_dname_size(response->question.qname);
	} else {
		response->header.qdcount = 0;
		knot_wire_set_qdcount(response->wireformat, 0);
	}

	assert(response->max_size >= to_copy);
	memcpy(response->wireformat, query->wireformat, to_copy);
	response->size = to_copy;

	// set the qr bit to 1
	knot_wire_flags_set_qr(&response->header.flags1);
	knot_wire_set_qr(response->wireformat);

	// clear TC flag
	knot_wire_flags_clear_tc(&response->header.flags1);
	knot_wire_clear_tc(response->wireformat);
	
	// clear AD flag
	knot_wire_flags_clear_ad(&response->header.flags2);
	knot_wire_clear_ad(response->wireformat);
	
	// clear RA flag
	knot_wire_flags_clear_ra(&response->header.flags2);
	knot_wire_clear_ad(response->wireformat);

	// set counts to 0
	response->header.ancount = 0;
	knot_wire_set_ancount(response->wireformat, 0);
	response->header.nscount = 0;
	knot_wire_set_nscount(response->wireformat, 0);
	response->header.arcount = 0;
	knot_wire_set_arcount(response->wireformat, 0);

	response->query = query;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_response_clear(knot_packet_t *resp, int clear_question)
{
	if (resp == NULL) {
		return;
	}

	resp->size = (clear_question) ? KNOT_WIRE_HEADER_SIZE
	              : KNOT_WIRE_HEADER_SIZE + 4
	                + knot_dname_size(resp->question.qname);
	resp->an_rrsets = 0;
	resp->ns_rrsets = 0;
	resp->ar_rrsets = 0;

	// free copied names for compression
	for (int i = 0; i < resp->compression.count; ++i) {
		if (resp->compression.to_free[i]) {
			knot_dname_release(
			           (knot_dname_t *)resp->compression.dnames[i]);
		}
	}
	resp->compression.count = 0;

	/*! \todo Temporary RRSets are not deallocated, which may potentially
	 *        lead to memory leaks should this function be used in other
	 *        cases than with XFR-out.
	 */
	knot_packet_free_tmp_rrsets(resp);
	resp->tmp_rrsets_count = 0;

	/*! \todo If this function is used in other cases than with XFR-out,
	 *        the list of wildcard nodes should be cleared here.
	 */

	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_opt(knot_packet_t *resp,
                          const knot_opt_rr_t *opt_rr,
                          int override_max_size,
                          int add_nsid)
{
	if (resp == NULL || opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	// copy the OPT RR

	/*! \todo Change the way OPT RR is handled in response.
	 *        Pointer to nameserver->opt_rr should be enough.
	 */

	resp->opt_rr.version = opt_rr->version;
	resp->opt_rr.ext_rcode = opt_rr->ext_rcode;
	resp->opt_rr.payload = opt_rr->payload;

	/*
	 * Add options only if NSID is requested.
	 *
	 * This is a bit hack and should be resolved in other way before some
	 * other options are supported.
	 */

	if (add_nsid) {
		resp->opt_rr.option_count = opt_rr->option_count;
		assert(resp->opt_rr.options == NULL);
		resp->opt_rr.options = (knot_opt_option_t *)malloc(
				 resp->opt_rr.option_count * sizeof(knot_opt_option_t));
		CHECK_ALLOC_LOG(resp->opt_rr.options, KNOT_ENOMEM);

		memcpy(resp->opt_rr.options, opt_rr->options,
		       resp->opt_rr.option_count * sizeof(knot_opt_option_t));

		// copy all data
		for (int i = 0; i < opt_rr->option_count; i++) {
			resp->opt_rr.options[i].data = (uint8_t *)malloc(
						resp->opt_rr.options[i].length);
			CHECK_ALLOC_LOG(resp->opt_rr.options[i].data, KNOT_ENOMEM);

			memcpy(resp->opt_rr.options[i].data,
			       opt_rr->options[i].data,
			       resp->opt_rr.options[i].length);
		}
		resp->opt_rr.size = opt_rr->size;
	} else {
		resp->opt_rr.size = KNOT_EDNS_MIN_SIZE;
	}

	// if max size is set, it means there is some reason to be that way,
	// so we can't just set it to higher value

	if (override_max_size && resp->max_size > 0
	    && resp->max_size < opt_rr->payload) {
		return KNOT_EOK;
	}

	// set max size (less is OK)
	if (override_max_size) {
		dbg_response("Overriding max size to: %u\n",
		             resp->opt_rr.payload);
		return knot_packet_set_max_size(resp, resp->opt_rr.payload);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_answer(knot_packet_t *response,
                                   knot_rrset_t *rrset, int tc,
                                   int check_duplicates, int compr_cs,
                                   int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	dbg_response_verb("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && knot_response_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
	       != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
	                                            KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Answer section.\n");
	dbg_response_detail("RRset: %p\n", rrset);
	dbg_response_detail("Owner: %p\n", rrset->owner);

	int rrs = knot_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size
	                                        - response->tsig_size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.ancount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_authority(knot_packet_t *response,
                                      knot_rrset_t *rrset, int tc,
                                      int check_duplicates, int compr_cs,
                                      int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && knot_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
	                                           KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Authority section.\n");

	int rrs = knot_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size
	                                        - response->tsig_size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.nscount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_additional(knot_packet_t *response,
                                       knot_rrset_t *rrset, int tc,
                                       int check_duplicates, int compr_cs,
                                       int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->opt_rr.version != EDNS_NOT_SUPPORTED
	    && (ret = knot_packet_edns_to_wire(response)) != KNOT_EOK) {
		return ret;
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && knot_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
	                                            KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Additional section.\n");

	int rrs = knot_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->tsig_size, rrset, 
	                                        tc, compr_cs);

	if (rrs >= 0) {
		response->header.arcount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

void knot_response_set_rcode(knot_packet_t *response, short rcode)
{
	if (response == NULL) {
		return;
	}

	knot_wire_flags_set_rcode(&response->header.flags2, rcode);
	knot_wire_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_aa(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_flags_set_aa(&response->header.flags1);
	knot_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_tc(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_flags_set_tc(&response->header.flags1);
	knot_wire_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_nsid(knot_packet_t *response, const uint8_t *data,
                             uint16_t length)
{
	if (response == NULL) {
		return KNOT_EINVAL;
	}

	return knot_edns_add_option(&response->opt_rr,
	                              EDNS_OPTION_NSID, length, data);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_wildcard_node(knot_packet_t *response,
                                    const knot_node_t *node,
                                    const knot_dname_t *sname)
{
	if (response == NULL || node == NULL || sname == NULL) {
		return KNOT_EINVAL;
	}

	if (response->wildcard_nodes.count == response->wildcard_nodes.max
	    && knot_response_realloc_wc_nodes(&response->wildcard_nodes.nodes,
	                                      &response->wildcard_nodes.snames,
	                                      &response->wildcard_nodes.max,
	                                      DEFAULT_WILDCARD_NODES,
	                                     STEP_WILDCARD_NODES) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	response->wildcard_nodes.nodes[response->wildcard_nodes.count] = node;
	response->wildcard_nodes.snames[response->wildcard_nodes.count] = sname;
	++response->wildcard_nodes.count;

	dbg_response_verb("Current wildcard nodes count: %d, max count: %d\n",
	             response->wildcard_nodes.count,
	             response->wildcard_nodes.max);

	return KNOT_EOK;
}
