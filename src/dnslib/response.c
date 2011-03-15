#include <config.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "dnslib-common.h"
#include "dnslib/response.h"
#include "dnslib/rrset.h"
#include "dnslib/packet.h"
#include "dnslib/descriptor.h"
#include "dnslib/edns.h"
#include "dnslib/utils.h"
#include "dnslib/node.h"
#include "dnslib/debug.h"

enum {
	DEFAULT_ANCOUNT = 6,
	DEFAULT_NSCOUNT = 8,
	DEFAULT_ARCOUNT = 28,
	DEFAULT_DOMAINS_IN_RESPONSE = 22,
	DEFAULT_TMP_RRSETS = 5,
	STEP_ANCOUNT = 6,
	STEP_NSCOUNT = 8,
	STEP_ARCOUNT = 8,
	STEP_DOMAINS = 10,
	STEP_TMP_RRSETS = 5
};

enum {
	PREALLOC_RESPONSE = sizeof(dnslib_response_t),
	PREALLOC_QNAME_DNAME = sizeof(dnslib_dname_t),
	PREALLOC_QNAME_NAME = 256,
	PREALLOC_QNAME_LABELS = 127,
	PREALLOC_QNAME = PREALLOC_QNAME_DNAME
	                 + PREALLOC_QNAME_NAME
	                 + PREALLOC_QNAME_LABELS,

	PREALLOC_RR_OWNER = 256,

	PREALLOC_ANSWER = DEFAULT_ANCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_AUTHORITY = DEFAULT_NSCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_ADDITIONAL = DEFAULT_ARCOUNT * sizeof(dnslib_dname_t *),

	PREALLOC_RRSETS = PREALLOC_ANSWER
	                  + PREALLOC_AUTHORITY
	                  + PREALLOC_ADDITIONAL,
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(dnslib_dname_t *),
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(short),
	PREALLOC_TMP_RRSETS =
		DEFAULT_TMP_RRSETS * sizeof(dnslib_dname_t *),

	PREALLOC_TOTAL = PREALLOC_RESPONSE
	                 + PREALLOC_QNAME
	                 + PREALLOC_RR_OWNER
	                 + PREALLOC_RRSETS
	                 + PREALLOC_DOMAINS
	                 + PREALLOC_OFFSETS
	                 + PREALLOC_TMP_RRSETS,

	PREALLOC_RESPONSE_WIRE = 65535,
	PREALLOC_RRSET_WIRE = 65535
};

static const short QUESTION_OFFSET = DNSLIB_PACKET_HEADER_SIZE;

struct dnslib_compr_owner {
	uint8_t *wire;
	short size;
	short pos;
};

typedef struct dnslib_compr_owner dnslib_compr_owner_t;

struct dnslib_compr {
	dnslib_compressed_dnames_t *table;
	short new_entries;
	short wire_pos;
	dnslib_compr_owner_t owner;
};

typedef struct dnslib_compr dnslib_compr_t;

//static int COMPRESS_DNAMES = 1;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void dnslib_response_init_pointers(dnslib_response_t *resp)
{
	debug_dnslib_response("Response pointer: %p\n", resp);
	// put QNAME directly after the structure
	resp->question.qname =
		(dnslib_dname_t *)((char *)resp + PREALLOC_RESPONSE);

	debug_dnslib_response("QNAME: %p (%zd after start of response)\n",
		resp->question.qname,
		(void *)resp->question.qname - (void *)resp);

	resp->question.qname->name = (uint8_t *)((char *)resp->question.qname
	                                         + PREALLOC_QNAME_DNAME);
	resp->question.qname->labels = (uint8_t *)((char *)
	                                           resp->question.qname->name
	                                           + PREALLOC_QNAME_NAME);

	resp->owner_tmp = (uint8_t *)((char *)resp->question.qname->labels
	                              + PREALLOC_QNAME_LABELS);

	// then answer, authority and additional sections
	resp->answer = (const dnslib_rrset_t **)
	                   ((char *)resp->owner_tmp + PREALLOC_RR_OWNER);
	resp->authority = resp->answer + DEFAULT_ANCOUNT;
	resp->additional = resp->authority + DEFAULT_NSCOUNT;

	debug_dnslib_response("Answer section: %p (%zd after QNAME)\n",
		resp->answer,
		(void *)resp->answer - (void *)resp->question.qname);
	debug_dnslib_response("Authority section: %p (%zd after Answer)\n",
		resp->authority,
		(void *)resp->authority - (void *)resp->answer);
	debug_dnslib_response("Additional section: %p (%zd after Authority)\n",
		resp->additional,
		(void *)resp->additional - (void *)resp->authority);

	resp->max_an_rrsets = DEFAULT_ANCOUNT;
	resp->max_ns_rrsets = DEFAULT_NSCOUNT;
	resp->max_ar_rrsets = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	resp->compression.dnames = (const dnslib_dname_t **)
	                               (resp->additional + DEFAULT_ARCOUNT);
	resp->compression.offsets = (short *)
		(resp->compression.dnames + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_response("Compression dnames: %p (%zd after Additional)\n",
		resp->compression.dnames,
		(void *)resp->compression.dnames - (void *)resp->additional);
	debug_dnslib_response("Compression offsets: %p (%zd after c. dnames)\n",
		resp->compression.offsets,
		(void *)resp->compression.offsets
		  - (void *)resp->compression.dnames);

	resp->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;

	resp->tmp_rrsets = (const dnslib_rrset_t **)
		(resp->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_response("Tmp rrsets: %p (%zd after compression offsets)"
		"\n", resp->tmp_rrsets,
		(void *)resp->tmp_rrsets - (void *)resp->compression.offsets);

	resp->tmp_rrsets_max = DEFAULT_TMP_RRSETS;

	debug_dnslib_response("End of data: %p (%zd after start of response)\n",
		resp->tmp_rrsets + DEFAULT_TMP_RRSETS,
		(void *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
		  - (void *)resp);
	debug_dnslib_response("Allocated total: %u\n", PREALLOC_TOTAL);

	assert((char *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
	       == (char *)resp + PREALLOC_TOTAL);
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_init(dnslib_response_t *resp,
                                const dnslib_opt_rr_t *opt_rr)
{
	memset(resp, 0, PREALLOC_TOTAL);

	if (opt_rr == NULL) {
		resp->edns_response.version = EDNS_NOT_SUPPORTED;
		// set default max size of the response
		resp->max_size = DNSLIB_MAX_RESPONSE_SIZE;
	} else {
		// copy the OPT RR
		resp->edns_response.version = opt_rr->version;
		resp->edns_response.ext_rcode = opt_rr->ext_rcode;
		resp->edns_response.payload = opt_rr->payload;
		resp->edns_response.size = opt_rr->size;

		resp->max_size = resp->edns_response.payload;
	}

	// pre-allocate space for wire format of the packet
	resp->wireformat = (uint8_t *)malloc(resp->max_size);
	if (resp->wireformat == NULL) {
		return -1;
	}

	// save default pointers to the space after the structure
	dnslib_response_init_pointers(resp);

	// set header to all 0s
	memset(resp->wireformat, 0, DNSLIB_PACKET_HEADER_SIZE);
	// set the QR bit
	dnslib_packet_set_qr(resp->wireformat);
	// set the size to the size of header
	resp->size = DNSLIB_PACKET_HEADER_SIZE;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_header(const uint8_t **pos, size_t *remaining,
                                        dnslib_header_t *header)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || header == NULL) {
		debug_dnslib_response("Missing inputs to header parsing.\n");
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_HEADER_SIZE) {
		debug_dnslib_response("Not enough data to parse header.\n");
		return -2;
	}

	header->id = dnslib_packet_get_id(*pos);
	// copy some of the flags: OPCODE and RD
	// do this by copying flags1 and setting QR to 1, AA to 0 and TC to 0
	header->flags1 = dnslib_packet_get_flags1(*pos);
	dnslib_packet_flags_set_qr(&header->flags1);
	dnslib_packet_flags_clear_aa(&header->flags1);
	dnslib_packet_flags_clear_tc(&header->flags1);
	// do not copy flags2 (all set by server)
	header->qdcount = dnslib_packet_get_qdcount(*pos);
	header->ancount = dnslib_packet_get_ancount(*pos);
	header->nscount = dnslib_packet_get_nscount(*pos);
	header->arcount = dnslib_packet_get_arcount(*pos);

	*pos += DNSLIB_PACKET_HEADER_SIZE;
	*remaining -= DNSLIB_PACKET_HEADER_SIZE;

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_header_to_wire(const dnslib_header_t *header,
                                           uint8_t **pos, short *size)
{
	dnslib_packet_set_id(*pos, header->id);
	dnslib_packet_set_flags1(*pos, header->flags1);
	dnslib_packet_set_flags2(*pos, header->flags2);
	dnslib_packet_set_qdcount(*pos, header->qdcount);
	dnslib_packet_set_ancount(*pos, header->ancount);
	dnslib_packet_set_nscount(*pos, header->nscount);
	dnslib_packet_set_arcount(*pos, header->arcount);

	*pos += DNSLIB_PACKET_HEADER_SIZE;
	*size += DNSLIB_PACKET_HEADER_SIZE;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_question(const uint8_t **pos,
                                          size_t *remaining,
                                          dnslib_question_t *question)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || question == NULL) {
		debug_dnslib_response("Missing inputs to question parsing\n");
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_QUESTION_MIN_SIZE) {
		debug_dnslib_response("Not enough data to parse question.\n");
		return -2;  // malformed
	}

	// domain name must end with 0, so just search for 0
	int i = 0;
	while (i < *remaining && (*pos)[i] != 0) {
		++i;
	}

	if (i == *remaining || *remaining - i - 1 < 4) {
		debug_dnslib_response("Not enough data to parse question.\n");
		return -2;  // no 0 found or not enough data left
	}

	//question->qname = dnslib_dname_new_from_wire(*pos, i + 1, NULL);
//	if (question->qname == NULL) {
//		return -3;  // allocation failed
//	}
	if (dnslib_dname_from_wire(*pos, i + 1, NULL, question->qname) != 0) {
		return -3;
	}

	*pos += i + 1;
	question->qtype = dnslib_wire_read_u16(*pos);
	*pos += 2;
	question->qclass = dnslib_wire_read_u16(*pos);
	*pos += 2;

	*remaining -= (i + 5);

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_question_to_wire(dnslib_question_t *question,
                                            uint8_t **pos, short *size)
{
	debug_dnslib_response("Copying QNAME, size %d\n",
	                      question->qname->size);
	memcpy(*pos, question->qname->name, question->qname->size);
	*size += question->qname->size;
	*pos += question->qname->size;

	dnslib_wire_write_u16(*pos, question->qtype);
	*pos += 2;
	dnslib_wire_write_u16(*pos, question->qclass);
	*pos += 2;
	*size += 4;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_client_edns(const uint8_t **pos,
                                             size_t *remaining,
                                             dnslib_opt_rr_t *client_opt)
{
	debug_dnslib_response("Parsing client EDNS OPT RR.\n");
	int parsed = dnslib_edns_new_from_wire(client_opt, *pos, *remaining);
	if (parsed < 0) {
		debug_dnslib_response("Error parsing EDNS OPT RR.\n");
		return -1;
	}

	assert(*remaining >= parsed);
	*remaining -= parsed;
	*pos += parsed;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_realloc_compr(dnslib_compressed_dnames_t *table)
{
	int free_old = table->max != DEFAULT_DOMAINS_IN_RESPONSE;
	short *old_offsets = table->offsets;
	const dnslib_dname_t **old_dnames = table->dnames;

	short new_max_count = table->max + STEP_DOMAINS;

	short *new_offsets = (short *)malloc(new_max_count * sizeof(short));
	CHECK_ALLOC_LOG(new_offsets, -1);

	const dnslib_dname_t **new_dnames = (const dnslib_dname_t **)malloc(
		new_max_count * sizeof(dnslib_dname_t *));
	if (new_dnames == NULL) {
		ERR_ALLOC_FAILED;
		free(new_offsets);
		return -1;
	}

	memcpy(new_offsets, table->offsets, table->max * sizeof(short));
	memcpy(new_dnames, table->dnames,
	       table->max * sizeof(dnslib_dname_t *));

	table->offsets = new_offsets;
	table->dnames = new_dnames;
	table->max = new_max_count;

	if (free_old) {
		free(old_offsets);
		free(old_dnames);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_compr_save(dnslib_compressed_dnames_t *table,
                                       const dnslib_dname_t *dname, short pos)
{
	assert(table->count < table->max);

	for (int i = 0; i < table->count; ++i) {
		if (table->dnames[i] == dname) {
			return;
		}
	}

	table->dnames[table->count] = dname;
	table->offsets[table->count] = pos;
	++table->count;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_store_dname_pos(dnslib_compressed_dnames_t *table,
                                           const dnslib_dname_t *dname,
                                           int not_matched, short pos,
                                           short matched_offset)
{
DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(dname);
	debug_dnslib_response("Putting dname %s into compression table."
	                      " Labels not matched: %d, position: %d,"
	                      ", pointer: %p\n", name, not_matched, pos, dname);
	free(name);
);
	if (table->count == table->max &&
	    dnslib_response_realloc_compr(table) != 0) {
		return -1;
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
	short parent_pos = pos;
	int i = 0;

	while (to_save != NULL) {
		if (i == not_matched) {
			parent_pos = matched_offset;
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
			return -1;
		}

		dnslib_response_compr_save(table, to_save, parent_pos);

		to_save = (to_save->node != NULL
		           && to_save->node->parent != NULL)
		          ? to_save->node->parent->owner : NULL;

		debug_dnslib_response("i: %d\n", i);
		parent_pos += dnslib_dname_label_size(dname, i) + 1;
//		parent_pos += (i > 0)
//			      ? dnslib_dname_label_size(dname, i - 1) + 1 : 0;
		++i;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/

static short dnslib_response_find_dname_pos(
               const dnslib_compressed_dnames_t *table,
               const dnslib_dname_t *dname)
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
		if (dnslib_dname_compare(table->dnames[i], dname) == 0) {
			debug_dnslib_response("Found offset: %d\n",
			                      table->offsets[i]);
			return table->offsets[i];
		}
	}
	return -1;
}

/*---------------------------------------------------------------------------*/

static int dnslib_response_put_dname_ptr(const dnslib_dname_t *dname,
                                         int not_matched, short offset,
                                         uint8_t *wire, short max)
{
	// put the not matched labels
	short size = dnslib_dname_size_part(dname, not_matched);
	if (size + 2 > max) {
		return -1;
	}

	memcpy(wire, dnslib_dname_name(dname), size);
	dnslib_packet_put_pointer(wire + size, offset);

	return size + 2;
}

/*---------------------------------------------------------------------------*/

static int dnslib_response_compress_dname(const dnslib_dname_t *dname,
	dnslib_compr_t *compr, uint8_t *dname_wire, short max)
{
	int size = 0;
	/*!
	 * \todo Compress!!
	 *
	 * if pos < 0, do not store the position!
	 */

	// try to find the name or one of its ancestors in the compr. table
#ifdef COMPRESSION_PEDANTIC
	//dnslib_dname_t *to_find = dnslib_dname_copy(dname);
	dnslib_dname_t *to_find = (dnslib_dname_t *)dname;
	int copied = 0;
#else
	const dnslib_dname_t *to_find = dname;
#endif
	short offset = -1;
	int not_matched = 0;

	while (to_find != NULL && dnslib_dname_label_count(to_find) != 0) {
DEBUG_DNSLIB_RESPONSE(
		char *name = dnslib_dname_to_str(to_find);
		debug_dnslib_response("Searching for name %s in the compression"
		                      " table, not matched labels: %d\n", name,
		                      not_matched);
		free(name);
);
		offset = dnslib_response_find_dname_pos(compr->table, to_find);
		if (offset < 0) {
			++not_matched;
		} else {
			break;
		}
#ifdef COMPRESSION_PEDANTIC
		if (to_find->node == NULL
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
		if (to_find->node == NULL
		    || to_find->node->owner != to_find
		    || to_find->node->parent == NULL) {
			break;
		} else {
			assert(to_find->node != to_find->node->parent);
			assert(to_find != to_find->node->parent->owner);
			to_find = to_find->node->parent->owner;
		}
#endif
	}

#ifdef COMPRESSION_PEDANTIC
	if (copied) {
		dnslib_dname_free(&to_find);
	}
#endif

	if (offset >= 0) {  // found such dname somewhere in the packet
		debug_dnslib_response("Found name in the compression table.\n");
		assert(offset >= DNSLIB_PACKET_HEADER_SIZE);
		size = dnslib_response_put_dname_ptr(dname, not_matched, offset,
		                                     dname_wire, max);
		if (size <= 0) {
			return -1;
		}
	} else {
		debug_dnslib_response("Not found, putting whole name.\n");
		// now just copy the dname without compressing
		if (dname->size > max) {
			return -1;
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

static int dnslib_response_rr_to_wire(const dnslib_rrset_t *rrset,
                                      const dnslib_rdata_t *rdata,
                                      dnslib_compr_t *compr,
                                      uint8_t **rrset_wire, short max_size)
{
	int size = 0;

	if (size + ((compr->owner.pos < 0) ? compr->owner.size : 2) + 10
	    > max_size) {
		return -1;
	}

	// put owner if needed (already compressed)
	if (compr->owner.pos < 0) {
		memcpy(*rrset_wire, compr->owner.wire, compr->owner.size);
		compr->owner.pos = compr->wire_pos;
		*rrset_wire += compr->owner.size;
		size += compr->owner.size;
	} else {
		dnslib_packet_put_pointer(*rrset_wire, compr->owner.pos);
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
				compr, *rrset_wire, max_size - size);

			if (ret == -1) {
				return -1;
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
				return -1;
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
//				return -1;
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
				return -1;
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

static int dnslib_response_rrset_to_wire(const dnslib_rrset_t *rrset,
                                         uint8_t **pos, short *size,
                                         short max_size, short wire_pos,
                                         uint8_t *owner_tmp,
                                         dnslib_compressed_dnames_t *compr)
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
		return 0;
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
	compr_info.new_entries = 0;
	compr_info.table = compr;
	compr_info.wire_pos = wire_pos;
	compr_info.owner.pos = -1;
	compr_info.owner.wire = owner_tmp;
	compr_info.owner.size =
		dnslib_response_compress_dname(rrset->owner, &compr_info,
		                               owner_tmp, max_size);

	debug_dnslib_response("    Owner size: %d\n", compr_info.owner.size);
	if (compr_info.owner.size < 0) {
		return -1;
	}

	int rrs = 0;
	short rrset_size = 0;

	const dnslib_rdata_t *rdata = rrset->rdata;
	do {
		int ret = dnslib_response_rr_to_wire(rrset, rdata, &compr_info,
		                                    pos, max_size - rrset_size);

		assert(ret != 0);

		if (ret == -1) {
			// some RR didn't fit in, so no RRs should be used

			// TODO: remove last entries from compression table

			debug_dnslib_response("Some RR didn't fit in.\n");
			return -1;
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

static void dnslib_response_free_tmp_rrsets(dnslib_response_t *resp)
{
	for (int i = 0; i < resp->tmp_rrsets_count; ++i) {
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		dnslib_rrset_deep_free(
			&(((dnslib_rrset_t **)(resp->tmp_rrsets))[i]), 1, 1);
	}
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_allocated_space(dnslib_response_t *resp)
{
	if (resp->max_an_rrsets > DEFAULT_ANCOUNT) {
		free(resp->answer);
	}
	if (resp->max_ns_rrsets > DEFAULT_NSCOUNT) {
		free(resp->authority);
	}
	if (resp->max_ar_rrsets > DEFAULT_ARCOUNT) {
		free(resp->additional);
	}

	if (resp->compression.max > DEFAULT_DOMAINS_IN_RESPONSE) {
		free(resp->compression.dnames);
		free(resp->compression.offsets);
	}

	if (resp->tmp_rrsets_max > DEFAULT_TMP_RRSETS) {
		free(resp->tmp_rrsets);
	}
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_realloc_rrsets(const dnslib_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step)
{
	int free_old = (*max_count) != default_max_count;
	const dnslib_rrset_t **old = *rrsets;

	short new_max_count = *max_count + step;
	const dnslib_rrset_t **new_rrsets = (const dnslib_rrset_t **)malloc(
		new_max_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, -1);

	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(dnslib_rrset_t *));

	*rrsets = new_rrsets;
	*max_count = new_max_count;

	if (free_old) {
		free(old);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_rrset_size(const dnslib_rrset_t *rrset,
                                 const dnslib_compressed_dnames_t *compr)
{
	// TODO: count in possible compression
	short size = 0;

	dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);

	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		size += 10;  // 2 type, 2 class, 4 ttl, 2 rdlength
		size += rrset->owner->size;   // owner

		for (int i = 0; i < rdata->count; ++i) {
			switch (desc->wireformat[i]) {
			case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
			case DNSLIB_RDATA_WF_LITERAL_DNAME:
			case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
				debug_dnslib_response("dname size: %d\n",
					rdata->items[i].dname->size);
				size += rdata->items[i].dname->size;
				break;
			case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
				debug_dnslib_response("raw data size: %d\n",
					rdata->items[i].raw_data[0] + 1);
				size += rdata->items[i].raw_data[0] + 1;
				break;
			default:
				debug_dnslib_response("raw data size: %d\n",
					rdata->items[i].raw_data[0]);
				size += rdata->items[i].raw_data[0];
				break;
			}
		}

		rdata = dnslib_rrset_rdata_next(rrset, rdata);
	}

	return size;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_try_add_rrset(const dnslib_rrset_t **rrsets,
                                   short *rrset_count,
                                   dnslib_response_t *resp, short max_size,
                                   const dnslib_rrset_t *rrset, int tc)
{
	//short size = dnslib_response_rrset_size(rrset, &resp->compression);

DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(rrset->owner);
	debug_dnslib_response("\nAdding RRSet with owner %s and type %s: \n",
	                      name, dnslib_rrtype_to_string(rrset->type));
	free(name);
);

	uint8_t *pos = resp->wireformat + resp->size;
	short size = 0;
	int rrs = dnslib_response_rrset_to_wire(rrset, &pos, &size, max_size,
	                                        resp->size, resp->owner_tmp,
	                                        &resp->compression);

	if (rrs >= 0) {
		rrsets[(*rrset_count)++] = rrset;
		resp->size += size;
		debug_dnslib_response("RRset added, size: %d, RRs: %d, total "
		                      "size of response: %d\n\n", size, rrs,
		                      resp->size);
	} else if (tc) {
		dnslib_packet_flags_set_tc(&resp->header.flags1);
	}

	return rrs;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_contains(const dnslib_response_t *resp,
                             const dnslib_rrset_t *rrset)
{
	for (int i = 0; i < resp->header.ancount; ++i) {
		if (resp->answer[i] == rrset) {
			return 1;
		}
	}

	for (int i = 0; i < resp->header.nscount; ++i) {
		if (resp->authority[i] == rrset) {
			return 1;
		}
	}

	for (int i = 0; i < resp->header.arcount; ++i) {
		if (resp->additional[i] == rrset) {
			return 1;
		}
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_edns_to_wire(dnslib_response_t *resp)
{
	resp->size += dnslib_edns_to_wire(&resp->edns_response,
	                                  resp->wireformat + resp->size,
	                                  resp->max_size - resp->size);

	resp->header.arcount += 1;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_response_t *dnslib_response_new_empty(const dnslib_opt_rr_t *opt_rr)
{
	dnslib_response_t *resp = (dnslib_response_t *)malloc(PREALLOC_TOTAL);
	CHECK_ALLOC_LOG(resp, NULL);

	if (dnslib_response_init(resp, opt_rr) != 0) {
		free(resp);
		return NULL;
	}

	return resp;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_parse_query(dnslib_response_t *resp,
                                const uint8_t *query_wire, size_t query_size)
{
	assert(resp != NULL);
	assert(query_wire != NULL);

	int err = 0;

	const uint8_t *pos = query_wire;
	size_t remaining = query_size;

	uint8_t *resp_pos = resp->wireformat;
	short size = 0;

	// header parsing is maybe useless, we may just copy the wire format
	if ((err = dnslib_response_parse_header(
	               &pos, &remaining, &resp->header))) {
		return err;
	}

	dnslib_response_header_to_wire(&resp->header, &resp_pos, &size);
	debug_dnslib_response("Converted header, size so far: %d\n", size);

	if ((err = dnslib_response_parse_question(
	               &pos, &remaining, &resp->question))) {
		return err;
	}
	resp->header.qdcount = 1;

	// put the qname into the compression table
	dnslib_response_store_dname_pos(&resp->compression,
	                                resp->question.qname, 0, size, size);

	dnslib_response_question_to_wire(&resp->question, &resp_pos, &size);
	debug_dnslib_response("Converted Question, size so far: %d\n", size);
	//resp->size += resp->question.qname->size + 4;

	resp->size = size;

	if (resp->header.arcount > 0) {  // expecting EDNS OPT RR
		if ((err = dnslib_response_parse_client_edns(
			       &pos, &remaining, &resp->edns_query))) {
			return err;
		}
		if (dnslib_edns_get_payload(&resp->edns_query)
		    && dnslib_edns_get_payload(&resp->edns_query)
			< resp->max_size) {
			resp->max_size = resp->edns_query.payload;
		}
		// copy the DO bit into response
		if (dnslib_edns_do(&resp->edns_query)) {
			dnslib_edns_set_do(&resp->edns_response);
		}
	} else {
		// set client EDNS version to EDNS_NOT_SUPPORTED
		resp->edns_query.version = EDNS_NOT_SUPPORTED;
	}

	// set ANCOUNT, NSCOUNT and ARCOUNT to 0 (response)
	// parsing of ANCOUNT and NSCOUNT is unnecessary then
	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;

	// TODO: should we also set the flags, or leave it to the application?

	if (remaining > 0) {
		// some trailing garbage; ignore, but log
		log_answer_info("response: %zu bytes of trailing garbage "
		                "in query.\n",
		                remaining);
	}
#ifdef DNSLIB_RESPONSE_DEBUG
	dnslib_response_dump(resp);
#endif /* DNSLIB_RESPONSE_DEBUG */
	return 0;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_response_qname(const dnslib_response_t *response)
{
	return response->question.qname;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_response_qtype(const dnslib_response_t *response)
{
	return response->question.qtype;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_response_qclass(const dnslib_response_t *response)
{
	return response->question.qclass;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_answer(dnslib_response_t *response,
                                     const dnslib_rrset_t *rrset, int tc,
                                     int check_duplicates)
{
	debug_dnslib_response("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && dnslib_response_realloc_rrsets(&response->answer,
			&response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
		!= 0) {
		return -1;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return 1;
	}

	debug_dnslib_response("Trying to add RRSet to Answer section.\n");

	int rrs = dnslib_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc);

	if (rrs >= 0) {
		response->header.ancount += rrs;
		return 0;
	}

	return -1;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_authority(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc,
                                        int check_duplicates)
{
	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && dnslib_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return -1;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return 1;
	}

	debug_dnslib_response("Trying to add RRSet to Authority section.\n");

	int rrs = dnslib_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc);

	if (rrs >= 0) {
		response->header.nscount += rrs;
		return 0;
	}

	return -1;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_additional(dnslib_response_t *response,
                                         const dnslib_rrset_t *rrset, int tc,
                                         int check_duplicates)
{
	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->edns_response.version != EDNS_NOT_SUPPORTED) {
		dnslib_response_edns_to_wire(response);
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && dnslib_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return -1;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return 1;
	}

	debug_dnslib_response("Trying to add RRSet to Additional section.\n");

	int rrs = dnslib_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                         - response->size, rrset, tc);

	if (rrs >= 0) {
		response->header.arcount += rrs;
		return 0;
	}

	return -1;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_rcode(dnslib_response_t *response, short rcode)
{
	dnslib_packet_flags_set_rcode(&response->header.flags2, rcode);
	dnslib_packet_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_aa(dnslib_response_t *response)
{
	dnslib_packet_flags_set_aa(&response->header.flags1);
	dnslib_packet_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_tc(dnslib_response_t *response)
{
	dnslib_packet_flags_set_tc(&response->header.flags1);
	dnslib_packet_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_tmp_rrset(dnslib_response_t *response,
                                  dnslib_rrset_t *tmp_rrset)
{
	if (response->tmp_rrsets_count == response->tmp_rrsets_max
	    && dnslib_response_realloc_rrsets(&response->tmp_rrsets,
			&response->tmp_rrsets_max, DEFAULT_TMP_RRSETS,
			STEP_TMP_RRSETS)
		!= 0) {
		return -1;
	}

	response->tmp_rrsets[response->tmp_rrsets_count++] = tmp_rrset;

	return 0;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_answer_rrset_count(const dnslib_response_t *response)
{
	return response->an_rrsets;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_authority_rrset_count(const dnslib_response_t *response)
{
	return response->ns_rrsets;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_additional_rrset_count(const dnslib_response_t *response)
{
	return response->ar_rrsets;
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_answer_rrset(
	const dnslib_response_t *response, short pos)
{
	if (pos > response->an_rrsets) {
		return NULL;
	}

	return response->answer[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_authority_rrset(
	dnslib_response_t *response, short pos)
{
	if (pos > response->ns_rrsets) {
		return NULL;
	}

	return response->authority[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_additional_rrset(
	dnslib_response_t *response, short pos)
{
	if (pos > response->ar_rrsets) {
		return NULL;
	}

	return response->additional[pos];
}

/*----------------------------------------------------------------------------*/

int dnslib_response_dnssec_requested(const dnslib_response_t *response)
{
	return dnslib_edns_do(&response->edns_query);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_nsid_requested(const dnslib_response_t *response)
{
	return dnslib_edns_has_option(&response->edns_query, EDNS_OPTION_NSID);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_nsid(dnslib_response_t *response, const uint8_t *data,
                             uint16_t length)
{
	return dnslib_edns_add_option(&response->edns_response,
	                              EDNS_OPTION_NSID, length, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_to_wire(dnslib_response_t *resp,
                            uint8_t **resp_wire, size_t *resp_size)
{
	if (*resp_wire != NULL) {
		return -2;
	}

	assert(resp->size <= resp->max_size);

	// if there are no additional RRSets, add EDNS OPT RR
	if (resp->header.arcount == 0
	    && resp->edns_response.version != EDNS_NOT_SUPPORTED) {
	    dnslib_response_edns_to_wire(resp);
	}

	// set ANCOUNT to the packet
	dnslib_packet_set_ancount(resp->wireformat, resp->header.ancount);
	// set NSCOUNT to the packet
	dnslib_packet_set_nscount(resp->wireformat, resp->header.nscount);
	// set ARCOUNT to the packet
	dnslib_packet_set_arcount(resp->wireformat, resp->header.arcount);

	//assert(response->size == size);
	*resp_wire = resp->wireformat;
	*resp_size = resp->size;

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free(dnslib_response_t **response)
{
	if (response == NULL || *response == NULL) {
		return;
	}

	// free temporary domain names
	debug_dnslib_response("Freeing tmp domains...\n");
	dnslib_response_free_tmp_rrsets(*response);

	// check if some additional space was allocated for the response
	debug_dnslib_response("Freeing additional allocated space...\n");
	dnslib_response_free_allocated_space(*response);

	// free the space for wireformat
	assert((*response)->wireformat != NULL);
	free((*response)->wireformat);

	debug_dnslib_response("Freeing response structure\n");
	free(*response);
	*response = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef DNSLIB_RESPONSE_DEBUG
static void dnslib_response_dump_rrsets(const dnslib_rrset_t **rrsets,
                                        int count)
{
	for (int i = 0; i < count; ++i) {
		debug_dnslib_response("  RRSet %d:\n", i + 1);
		char *name = dnslib_dname_to_str(rrsets[i]->owner);
		debug_dnslib_response("    Owner: %s\n", name);
		free(name);
		debug_dnslib_response("    Type: %s\n",
		                      dnslib_rrtype_to_string(rrsets[i]->type));
		debug_dnslib_response("    Class: %s\n",
		                   dnslib_rrclass_to_string(rrsets[i]->rclass));
		debug_dnslib_response("    TTL: %d\n", rrsets[i]->ttl);
		debug_dnslib_response("    RDATA: ");

		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrsets[i]->type);

		const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrsets[i]);
		while (rdata != NULL) {
			for (int j = 0; j < rdata->count; ++j) {
				switch (desc->wireformat[j]) {
				case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
				case DNSLIB_RDATA_WF_LITERAL_DNAME:
				case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
					name = dnslib_dname_to_str(
						rdata->items[j].dname);
					debug_dnslib_response("%s \n",name);
					free(name);
					break;
				case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
					debug_dnslib_response_hex(
					    (char *)rdata->items[j].raw_data,
					    rdata->items[j].raw_data[0]);
					break;
				default:
					debug_dnslib_response_hex(
					   (char *)&rdata->items[j].raw_data[1],
					   rdata->items[j].raw_data[0]);
					break;
				}
			}
			rdata = dnslib_rrset_rdata_next(rrsets[i], rdata);
		}
	}
}
#endif
/*----------------------------------------------------------------------------*/

void dnslib_response_dump(const dnslib_response_t *resp)
{
#ifdef DNSLIB_RESPONSE_DEBUG
	debug_dnslib_response("DNS response:\n-----------------------------\n");

	debug_dnslib_response("\nHeader:\n");
	debug_dnslib_response("  ID: %u", resp->header.id);
	debug_dnslib_response("  FLAGS: %s %s %s %s %s %s %s\n",
	       dnslib_packet_flags_get_qr(resp->header.flags1) ? "qr" : "",
	       dnslib_packet_flags_get_aa(resp->header.flags1) ? "aa" : "",
	       dnslib_packet_flags_get_tc(resp->header.flags1) ? "tc" : "",
	       dnslib_packet_flags_get_rd(resp->header.flags1) ? "rd" : "",
	       dnslib_packet_flags_get_ra(resp->header.flags2) ? "ra" : "",
	       dnslib_packet_flags_get_ad(resp->header.flags2) ? "ad" : "",
	       dnslib_packet_flags_get_cd(resp->header.flags2) ? "cd" : "");
	debug_dnslib_response("  QDCOUNT: %u\n", resp->header.qdcount);
	debug_dnslib_response("  ANCOUNT: %u\n", resp->header.ancount);
	debug_dnslib_response("  NSCOUNT: %u\n", resp->header.nscount);
	debug_dnslib_response("  ARCOUNT: %u\n", resp->header.arcount);

	debug_dnslib_response("\nQuestion:\n");
	char *qname = dnslib_dname_to_str(resp->question.qname);
	debug_dnslib_response("  QNAME: %s\n", qname);
	free(qname);
	debug_dnslib_response("  QTYPE: %u (%s)\n", resp->question.qtype,
	       dnslib_rrtype_to_string(resp->question.qtype));
	debug_dnslib_response("  QCLASS: %u (%s)\n", resp->question.qclass,
	       dnslib_rrclass_to_string(resp->question.qclass));

	debug_dnslib_response("\nAnswer RRSets:\n");
	dnslib_response_dump_rrsets(resp->answer, resp->an_rrsets);
	debug_dnslib_response("\nAuthority RRSets:\n");
	dnslib_response_dump_rrsets(resp->authority, resp->ns_rrsets);
	debug_dnslib_response("\nAdditional RRSets:\n");
	dnslib_response_dump_rrsets(resp->additional, resp->ar_rrsets);

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	debug_dnslib_response("\nEDNS - client:\n");
	debug_dnslib_response("  Version: %u\n", resp->edns_query.version);
	debug_dnslib_response("  Payload: %u\n", resp->edns_query.payload);
	debug_dnslib_response("  Extended RCODE: %u\n",
	                      resp->edns_query.ext_rcode);

	debug_dnslib_response("\nResponse size: %d\n", resp->size);
	debug_dnslib_response("\n-----------------------------\n");
#endif
}
