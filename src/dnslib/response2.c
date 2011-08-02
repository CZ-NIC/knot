#include <stdlib.h>

#include "dnslib/response2.h"
#include "dnslib/wire.h"
#include "dnslib/descriptor.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/error.h"
#include "dnslib/debug.h"
#include "dnslib/packet.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Holds information about compressed domain name.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct dnslib_compr_owner {
	/*!
	 * \brief Place where the name is stored in the wire format of the
	 * packet.
	 */
	uint8_t *wire;
	short size; /*!< Size of the domain name in bytes. */
	/*! \brief Position of the name relative to the start of the packet. */
	size_t pos;
};

typedef struct dnslib_compr_owner dnslib_compr_owner_t;

/*!
 * \brief Holds information about compressed domain names in packet.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct dnslib_compr {
	dnslib_compressed_dnames_t *table;  /*!< Compression table. */
	size_t wire_pos;            /*!< Current position in the wire format. */
	dnslib_compr_owner_t owner; /*!< Information about the current name. */
};

typedef struct dnslib_compr dnslib_compr_t;

static const size_t DNSLIB_RESPONSE_MAX_PTR = 16383;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocates space for compression table.
 *
 * \param table Compression table to reallocate space for.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
static int dnslib_response_realloc_compr(dnslib_compressed_dnames_t *table)
{
	int free_old = table->max != DEFAULT_DOMAINS_IN_RESPONSE;
	size_t *old_offsets = table->offsets;
	const dnslib_dname_t **old_dnames = table->dnames;

	short new_max_count = table->max + STEP_DOMAINS;

	size_t *new_offsets = (size_t *)malloc(new_max_count * sizeof(size_t));
	CHECK_ALLOC_LOG(new_offsets, -1);

	const dnslib_dname_t **new_dnames = (const dnslib_dname_t **)malloc(
		new_max_count * sizeof(dnslib_dname_t *));
	if (new_dnames == NULL) {
		ERR_ALLOC_FAILED;
		free(new_offsets);
		return DNSLIB_ENOMEM;
	}

	memcpy(new_offsets, table->offsets, table->max * sizeof(size_t));
	memcpy(new_dnames, table->dnames,
	       table->max * sizeof(dnslib_dname_t *));

	table->offsets = new_offsets;
	table->dnames = new_dnames;
	table->max = new_max_count;

	if (free_old) {
		free(old_offsets);
		free(old_dnames);
	}

	return DNSLIB_EOK;
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
static void dnslib_response_compr_save(dnslib_compressed_dnames_t *table,
                                       const dnslib_dname_t *dname, size_t pos)
{
	assert(table->count < table->max);

	for (int i = 0; i < table->count; ++i) {
		if (table->dnames[i] == dname) {
			debug_dnslib_response("Already present, skipping..\n");
			return;
		}
	}

	table->dnames[table->count] = dname;
	table->offsets[table->count] = pos;
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
static int dnslib_response_store_dname_pos(dnslib_compressed_dnames_t *table,
                                           const dnslib_dname_t *dname,
                                           int not_matched, size_t pos,
                                           size_t unmatched_offset)
{
DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(dname);
	debug_dnslib_response("Putting dname %s into compression table."
	                      " Labels not matched: %d, position: %d,"
	                      ", pointer: %p\n", name, not_matched, pos, dname);
	free(name);
);
	if (pos > DNSLIB_RESPONSE_MAX_PTR) {
		debug_dnslib_response("Pointer larger than it can be, not"
		                      " saving\n");
		return DNSLIB_EDNAMEPTR;
	}

	if (table->count == table->max &&
	    dnslib_response_realloc_compr(table) != 0) {
		return DNSLIB_ENOMEM;
	}

	// store the position of the name
//	table->dnames[table->count] = dname;
//	table->offsets[table->count] = pos;
//	++table->count;

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
	const dnslib_dname_t *to_save = dname;
	size_t parent_pos = pos;
	int i = 0;

	while (to_save != NULL && i < dnslib_dname_label_count(dname)) {
		if (i == not_matched) {
			parent_pos = unmatched_offset;
		}

DEBUG_DNSLIB_RESPONSE(
		char *name = dnslib_dname_to_str(to_save);
		debug_dnslib_response("Putting dname %s into compression table."
		                      " Position: %d, pointer: %p\n",
		                      name, parent_pos, to_save);
		free(name);
);

		if (table->count == table->max &&
		    dnslib_response_realloc_compr(table) != 0) {
			debug_dnslib_response("Unable to realloc.\n");
			return DNSLIB_ENOMEM;
		}

//		debug_dnslib_response("Saving..\n");
		dnslib_response_compr_save(table, to_save, parent_pos);

		to_save = (dnslib_dname_node(to_save, 1) != NULL
		      && dnslib_node_parent(dnslib_dname_node(to_save, 1), 1)
		          != NULL) ? dnslib_node_owner(dnslib_node_parent(
		                        dnslib_dname_node(to_save, 1), 1))
		                   : NULL;

		debug_dnslib_response("i: %d\n", i);
		parent_pos += dnslib_dname_label_size(dname, i) + 1;
//		parent_pos += (i > 0)
//			      ? dnslib_dname_label_size(dname, i - 1) + 1 : 0;
		++i;
	}

	return DNSLIB_EOK;
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
static size_t dnslib_response_find_dname_pos(
               const dnslib_compressed_dnames_t *table,
               const dnslib_dname_t *dname, int compr_cs)
{
	for (int i = 0; i < table->count; ++i) {
		debug_dnslib_response("Comparing dnames %p and %p\n",
		                      dname, table->dnames[i]);
DEBUG_DNSLIB_RESPONSE(
		char *name = dnslib_dname_to_str(dname);
		debug_dnslib_response("(%s and ", name);
		name = dnslib_dname_to_str(table->dnames[i]);
		debug_dnslib_response("%s)\n", name);
		free(name);
);
		//if (table->dnames[i] == dname) {
		int ret = (compr_cs)
		           ? dnslib_dname_compare_cs(table->dnames[i], dname)
		           : dnslib_dname_compare(table->dnames[i], dname);
		if (ret == 0) {
			debug_dnslib_response("Found offset: %d\n",
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
 *         DNSLIB_ESPACE if it did not fit.
 */
static int dnslib_response_put_dname_ptr(const dnslib_dname_t *dname,
                                         int not_matched, size_t offset,
                                         uint8_t *wire, size_t max)
{
	// put the not matched labels
	short size = dnslib_dname_size_part(dname, not_matched);
	if (size + 2 > max) {
		return DNSLIB_ESPACE;
	}

	memcpy(wire, dnslib_dname_name(dname), size);
	dnslib_wire_put_pointer(wire + size, offset);

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
 * \return Size of the domain name's wire format or DNSLIB_ESPACE if it did not
 *         fit into the provided space.
 */
static int dnslib_response_compress_dname(const dnslib_dname_t *dname,
	dnslib_compr_t *compr, uint8_t *dname_wire, size_t max, int compr_cs)
{
	int size = 0;
	/*!
	 * \todo Compress!!
	 *
	 * if pos == 0, do not store the position!
	 */

	// try to find the name or one of its ancestors in the compr. table
#ifdef COMPRESSION_PEDANTIC
	//dnslib_dname_t *to_find = dnslib_dname_copy(dname);
	dnslib_dname_t *to_find = (dnslib_dname_t *)dname;
	int copied = 0;
#else
	const dnslib_dname_t *to_find = dname;
#endif
	size_t offset = 0;
	int not_matched = 0;

	while (to_find != NULL && dnslib_dname_label_count(to_find) != 0) {
DEBUG_DNSLIB_RESPONSE(
		char *name = dnslib_dname_to_str(to_find);
		debug_dnslib_response("Searching for name %s in the compression"
		                      " table, not matched labels: %d\n", name,
		                      not_matched);
		free(name);
);
		offset = dnslib_response_find_dname_pos(compr->table, to_find,
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
				to_find = dnslib_dname_left_chop(to_find);
				copied = 1;
			} else {
				dnslib_dname_left_chop_no_copy(to_find);
			}
		} else {
			assert(to_find->node != to_find->node->parent);
			assert(to_find != to_find->node->parent->owner);
			to_find = to_find->node->parent->owner;
		}
#else
		// if case-sensitive comparation, we cannot just take the parent
		if (compr_cs || dnslib_dname_node(to_find, 1) == NULL
		    || dnslib_node_owner(dnslib_dname_node(to_find, 1))
		       != to_find
		    || dnslib_node_parent(dnslib_dname_node(to_find, 1), 1)
		       == NULL) {
			break;
		} else {
			assert(dnslib_dname_node(to_find, 1) !=
			     dnslib_node_parent(dnslib_dname_node(to_find, 1),
			                        1));
			assert(to_find != dnslib_node_owner(
			    dnslib_node_parent(dnslib_dname_node(to_find, 1),
			                       1)));
			to_find = dnslib_node_owner(
			     dnslib_node_parent(dnslib_dname_node(to_find, 1),
			                        1));
		}
#endif
	}

#ifdef COMPRESSION_PEDANTIC
	if (copied) {
		dnslib_dname_free(&to_find);
	}
#endif

	if (offset > 0) {  // found such dname somewhere in the packet
		debug_dnslib_response("Found name in the compression table.\n");
		assert(offset >= DNSLIB_WIRE_HEADER_SIZE);
		size = dnslib_response_put_dname_ptr(dname, not_matched, offset,
		                                     dname_wire, max);
		if (size <= 0) {
			return DNSLIB_ESPACE;
		}
	} else {
		debug_dnslib_response("Not found, putting whole name.\n");
		// now just copy the dname without compressing
		if (dname->size > max) {
			return DNSLIB_ESPACE;
		}

		memcpy(dname_wire, dname->name, dname->size);
		size = dname->size;
	}

	// in either way, put info into the compression table
	assert(compr->wire_pos >= 0);
	if (dnslib_response_store_dname_pos(compr->table, dname, not_matched,
	                                    compr->wire_pos, offset) != 0) {
		debug_dnslib_response("Compression info could not be stored."
		                      "\n");
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
 * \return Size of the RR's wire format or DNSLIB_ESPACE if it did not fit into
 *         the provided space.
 */
static int dnslib_response_rr_to_wire(const dnslib_rrset_t *rrset,
                                      const dnslib_rdata_t *rdata,
                                      dnslib_compr_t *compr,
                                      uint8_t **rrset_wire, size_t max_size,
                                      int compr_cs)
{
	int size = 0;

	if (size + ((compr->owner.pos == 0) ? compr->owner.size : 2) + 10
	    > max_size) {
		return DNSLIB_ESPACE;
	}

	debug_dnslib_response("Owner position: %zu\n", compr->owner.pos);

	// put owner if needed (already compressed)
	if (compr->owner.pos == 0) {
		memcpy(*rrset_wire, compr->owner.wire, compr->owner.size);
		compr->owner.pos = compr->wire_pos;
		*rrset_wire += compr->owner.size;
		size += compr->owner.size;
	} else {
		debug_dnslib_response("Putting pointer: %zu\n",
		                      compr->owner.pos);
		dnslib_wire_put_pointer(*rrset_wire, compr->owner.pos);
		*rrset_wire += 2;
		size += 2;
	}

	debug_dnslib_response("Wire format:\n");

	// put rest of RR 'header'
	dnslib_wire_write_u16(*rrset_wire, rrset->type);
	debug_dnslib_response("  Type: %u\n", rrset->type);
	debug_dnslib_response("  Type in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	dnslib_wire_write_u16(*rrset_wire, rrset->rclass);
	debug_dnslib_response("  Class: %u\n", rrset->rclass);
	debug_dnslib_response("  Class in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	dnslib_wire_write_u32(*rrset_wire, rrset->ttl);
	debug_dnslib_response("  TTL: %u\n", rrset->ttl);
	debug_dnslib_response("  TTL in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 4);
	*rrset_wire += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *rrset_wire;
	*rrset_wire += 2;

	size += 10;
	compr->wire_pos += size;

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(rrset->type);

	uint16_t rdlength = 0;

	for (int i = 0; i < rdata->count; ++i) {
		switch (desc->wireformat[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME: {
			int ret = dnslib_response_compress_dname(
				dnslib_rdata_item(rdata, i)->dname,
				compr, *rrset_wire, max_size - size, compr_cs);

			if (ret < 0) {
				return DNSLIB_ESPACE;
			}

			debug_dnslib_response("Compressed dname size: %d\n",
			                      ret);
			*rrset_wire += ret;
			rdlength += ret;
			compr->wire_pos += ret;
			// TODO: compress domain name
			break;
		}
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME: {
			dnslib_dname_t *dname =
				dnslib_rdata_item(rdata, i)->dname;
			if (size + dname->size > max_size) {
				return DNSLIB_ESPACE;
			}

			// save whole domain name
			memcpy(*rrset_wire, dname->name, dname->size);
			debug_dnslib_response("Uncompressed dname size: %d\n",
			                      dname->size);
			*rrset_wire += dname->size;
			rdlength += dname->size;
			compr->wire_pos += dname->size;
			break;
		}
//		case DNSLIB_RDATA_WF_BINARYWITHLENGTH: {
//			uint16_t *raw_data =
//				dnslib_rdata_item(rdata, i)->raw_data;

//			if (size + raw_data[0] + 1 > max_size) {
//				return DNSLIB_ESPACE;
//			}

//			// copy also the rdata item size
//			assert(raw_data[0] < 256);
//			**rrset_wire = raw_data[0];
//			*rrset_wire += 1;
//			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
//			debug_dnslib_response("Raw data size: %d\n",
//			                      raw_data[0] + 1);
//			*rrset_wire += raw_data[0];
//			rdlength += raw_data[0] + 1;
//			compr->wire_pos += raw_data[0] + 1;
//			break;
//		}
		default: {
			uint16_t *raw_data =
				dnslib_rdata_item(rdata, i)->raw_data;

			if (size + raw_data[0] > max_size) {
				return DNSLIB_ESPACE;
			}

			// copy just the rdata item data (without size)
			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
			debug_dnslib_response("Raw data size: %d\n",
			                      raw_data[0]);
			*rrset_wire += raw_data[0];
			rdlength += raw_data[0];
			compr->wire_pos += raw_data[0];
			break;
		}
		}
	}

	assert(size + rdlength <= max_size);
	size += rdlength;
	dnslib_wire_write_u16(rdlength_pos, rdlength);

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
 * \return Size of the RRSet's wire format or DNSLIB_ESPACE if it did not fit
 *         into the provided space.
 */
static int dnslib_response_rrset_to_wire(const dnslib_rrset_t *rrset,
                                         uint8_t **pos, size_t *size,
                                         size_t max_size, size_t wire_pos,
                                         uint8_t *owner_tmp,
                                         dnslib_compressed_dnames_t *compr,
                                         int compr_cs)
{
DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(rrset->owner);
	debug_dnslib_response("Converting RRSet with owner %s, type %s\n",
	                      name, dnslib_rrtype_to_string(rrset->type));
	free(name);
	debug_dnslib_response("  Size before: %d\n", *size);
);

	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		return DNSLIB_EOK;
	}

	//uint8_t *rrset_wire = (uint8_t *)malloc(PREALLOC_RRSET_WIRE);
	//short rrset_size = 0;

	//uint8_t *owner_wire = (uint8_t *)malloc(rrset->owner->size);
	/*
	 * We may pass the current position to the compression function
	 * because if the owner will be put somewhere, it will be on the
	 * current position (first item of a RR). If it will not be put into
	 * the wireformat, we may remove the dname (and possibly its parents)
	 * from the compression table.
	 */

	dnslib_compr_t compr_info;
	//compr_info.new_entries = 0;
	compr_info.table = compr;
	compr_info.wire_pos = wire_pos;
	compr_info.owner.pos = 0;
	compr_info.owner.wire = owner_tmp;
	compr_info.owner.size =
		dnslib_response_compress_dname(rrset->owner, &compr_info,
		                               owner_tmp, max_size, compr_cs);

	debug_dnslib_response("    Owner size: %d, position: %zu\n",
	                      compr_info.owner.size, compr_info.owner.pos);
	if (compr_info.owner.size < 0) {
		return DNSLIB_ESPACE;
	}

	int rrs = 0;
	short rrset_size = 0;

	const dnslib_rdata_t *rdata = rrset->rdata;
	do {
		int ret = dnslib_response_rr_to_wire(rrset, rdata, &compr_info,
		                                     pos, max_size - rrset_size,
		                                     compr_cs);

		assert(ret != 0);

		if (ret < 0) {
			// some RR didn't fit in, so no RRs should be used
			// TODO: remove last entries from compression table
			debug_dnslib_response("Some RR didn't fit in.\n");
			return DNSLIB_ESPACE;
		}

		debug_dnslib_response("RR of size %d added.\n", ret);
		rrset_size += ret;
		++rrs;
	} while ((rdata = dnslib_rrset_rdata_next(rrset, rdata)) != NULL);

	//memcpy(*pos, rrset_wire, rrset_size);
	//*size += rrset_size;
	//*pos += rrset_size;

	// the whole RRSet did fit in
	assert (rrset_size <= max_size);
	*size += rrset_size;

	debug_dnslib_response("  Size after: %d\n", *size);

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
 * \return Count of RRs added to the response or DNSLIB_ESPACE if the RRSet did
 *         not fit in the available space.
 */
static int dnslib_response_try_add_rrset(const dnslib_rrset_t **rrsets,
                                        short *rrset_count,
                                        dnslib_packet_t *resp,
                                        size_t max_size,
                                        const dnslib_rrset_t *rrset, int tc,
                                        int compr_cs)
{
	//short size = dnslib_response_rrset_size(rrset, &resp->compression);

DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(rrset->owner);
	debug_dnslib_response("\nAdding RRSet with owner %s and type %s: \n",
	                      name, dnslib_rrtype_to_string(rrset->type));
	free(name);
);

	uint8_t *pos = resp->wireformat + resp->size;
	size_t size = 0;
	int rrs = dnslib_response_rrset_to_wire(rrset, &pos, &size, max_size,
	                                        resp->size, resp->owner_tmp,
	                                        &resp->compression, compr_cs);

	if (rrs >= 0) {
		rrsets[(*rrset_count)++] = rrset;
		resp->size += size;
		debug_dnslib_response("RRset added, size: %d, RRs: %d, total "
		                      "size of response: %d\n\n", size, rrs,
		                      resp->size);
	} else if (tc) {
		dnslib_wire_flags_set_tc(&resp->header.flags1);
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
static int dnslib_response_realloc_rrsets(const dnslib_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step)
{
	int free_old = (*max_count) != default_max_count;
	const dnslib_rrset_t **old = *rrsets;

	short new_max_count = *max_count + step;
	const dnslib_rrset_t **new_rrsets = (const dnslib_rrset_t **)malloc(
		new_max_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, DNSLIB_ENOMEM);

	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(dnslib_rrset_t *));

	*rrsets = new_rrsets;
	*max_count = new_max_count;

	if (free_old) {
		free(old);
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int dnslib_response2_init(dnslib_packet_t *response)
{
	if (response == NULL) {
		return DNSLIB_EBADARG;
	}

	if (response->max_size < DNSLIB_WIRE_HEADER_SIZE) {
		return DNSLIB_ESPACE;
	}

	// set the qr bit to 1
	dnslib_wire_flags_set_qr(&response->header.flags1);

	uint8_t *pos = response->wireformat;
	dnslib_packet_header_to_wire(&response->header, &pos,
	                                &response->size);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_init_from_query(dnslib_packet_t *response,
                                    dnslib_packet_t *query)
{
	if (response == NULL || query == NULL) {
		return DNSLIB_EBADARG;
	}

	// copy the header from the query
	memcpy(&response->header, &query->header, sizeof(dnslib_header_t));

	// copy the Question section (but do not copy the QNAME)
	memcpy(&response->question, &query->question,
	       sizeof(dnslib_question_t));

	int err = 0;
	// put the qname into the compression table
	// TODO: get rid of the numeric constants
	if ((err = dnslib_response_store_dname_pos(&response->compression,
	              response->question.qname, 0, 12, 12)) != DNSLIB_EOK) {
		return err;
	}

	// copy the wireformat of Header and Question from the query
	// TODO: get rid of the numeric constants
	size_t to_copy = 12 + 4 + dnslib_dname_size(response->question.qname);
	assert(response->max_size >= to_copy);
	memcpy(response->wireformat, query->wireformat, to_copy);

	response->size = to_copy;

	// set the qr bit to 1
	dnslib_wire_flags_set_qr(&response->header.flags1);
	dnslib_wire_set_qr(response->wireformat);

	// set counts to 0
	response->header.ancount = 0;
	response->header.nscount = 0;
	response->header.arcount = 0;

	response->query = query;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

void dnslib_response2_clear(dnslib_packet_t *resp, int clear_question)
{
	if (resp == NULL) {
		return;
	}

	resp->size = (clear_question) ? DNSLIB_WIRE_HEADER_SIZE
	              : DNSLIB_WIRE_HEADER_SIZE + 4
	                + dnslib_dname_size(resp->question.qname);
	resp->an_rrsets = 0;
	resp->ns_rrsets = 0;
	resp->ar_rrsets = 0;
	resp->compression.count = 0;
	dnslib_packet_free_tmp_rrsets(resp);
	resp->tmp_rrsets_count = 0;
	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_add_opt(dnslib_packet_t *resp,
                            const dnslib_opt_rr_t *opt_rr,
                            int override_max_size)
{
	if (resp == NULL || opt_rr == NULL) {
		return DNSLIB_EBADARG;
	}

	// copy the OPT RR
	resp->opt_rr.version = opt_rr->version;
	resp->opt_rr.ext_rcode = opt_rr->ext_rcode;
	resp->opt_rr.payload = opt_rr->payload;
	resp->opt_rr.size = opt_rr->size;

	// if max size is set, it means there is some reason to be that way,
	// so we can't just set it to higher value

	if (override_max_size && resp->max_size > 0
	    && resp->max_size < opt_rr->payload) {
		return DNSLIB_EPAYLOAD;
	}

	// set max size (less is OK)
	if (override_max_size) {
		return dnslib_packet_set_max_size(resp, resp->opt_rr.payload);
		//resp->max_size = resp->opt_rr.payload;
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_add_rrset_answer(dnslib_packet_t *response,
                                     const dnslib_rrset_t *rrset, int tc,
                                     int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	debug_dnslib_response("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && dnslib_response_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
	       != DNSLIB_EOK) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_packet_contains(response, rrset,
	                                            DNSLIB_RRSET_COMPARE_PTR)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Answer section.\n");
	debug_dnslib_response("RRset: %p\n", rrset);
	debug_dnslib_response("Owner: %p\n", rrset->owner);

	int rrs = dnslib_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.ancount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_add_rrset_authority(dnslib_packet_t *response,
                                        const dnslib_rrset_t *rrset, int tc,
                                        int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && dnslib_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_packet_contains(response, rrset,
	                                           DNSLIB_RRSET_COMPARE_PTR)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Authority section.\n");

	int rrs = dnslib_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.nscount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_add_rrset_additional(dnslib_packet_t *response,
                                         const dnslib_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	int ret;

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->opt_rr.version != EDNS_NOT_SUPPORTED
	    && (ret = dnslib_packet_edns_to_wire(response)) != DNSLIB_EOK) {
		return ret;
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && dnslib_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_packet_contains(response, rrset,
	                                            DNSLIB_RRSET_COMPARE_PTR)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Additional section.\n");

	int rrs = dnslib_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size, rrset, tc,
	                                        compr_cs);

	if (rrs >= 0) {
		response->header.arcount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

void dnslib_response2_set_rcode(dnslib_packet_t *response, short rcode)
{
	if (response == NULL) {
		return;
	}

	dnslib_wire_flags_set_rcode(&response->header.flags2, rcode);
	dnslib_wire_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void dnslib_response2_set_aa(dnslib_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	dnslib_wire_flags_set_aa(&response->header.flags1);
	dnslib_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void dnslib_response2_set_tc(dnslib_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	dnslib_wire_flags_set_tc(&response->header.flags1);
	dnslib_wire_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int dnslib_response2_add_nsid(dnslib_packet_t *response, const uint8_t *data,
                             uint16_t length)
{
	if (response == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_edns_add_option(&response->opt_rr,
	                              EDNS_OPTION_NSID, length, data);
}
