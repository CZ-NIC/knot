#include <config.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "common.h"
#include "response.h"
#include "rrset.h"
#include "wire.h"
#include "descriptor.h"
#include "edns.h"
#include "utils.h"
#include "node.h"
#include "error.h"
#include "debug.h"

/*!
 * \brief Default maximum DNS response size
 *
 * This size must be supported by all servers and clients.
 */
static const short KNOT_MAX_RESPONSE_SIZE = 512;

/*!
 * \brief Default sizes for response structure parts and steps for increasing
 *        them.
 */
enum {
	DEFAULT_ANCOUNT = 6,         /*!< Default count of Answer RRSets. */
	DEFAULT_NSCOUNT = 8,         /*!< Default count of Authority RRSets. */
	DEFAULT_ARCOUNT = 28,        /*!< Default count of Additional RRSets. */
	/*!
	 * \brief Default count of all domain names in response.
	 *
	 * Used for compression table.
	 */
	DEFAULT_DOMAINS_IN_RESPONSE = 22,

	/*! \brief Default count of temporary RRSets stored in response. */
	DEFAULT_TMP_RRSETS = 5,
	STEP_ANCOUNT = 6, /*!< Step for increasing space for Answer RRSets. */
	STEP_NSCOUNT = 8, /*!< Step for increasing space for Authority RRSets.*/
	STEP_ARCOUNT = 8,/*!< Step for increasing space for Additional RRSets.*/
	STEP_DOMAINS = 10,   /*!< Step for resizing compression table. */
	STEP_TMP_RRSETS = 5  /*!< Step for increasing temorary RRSets count. */
};

/*! \brief Sizes for preallocated space in the response structure. */
enum {
	/*! \brief Size of the response structure itself. */
	PREALLOC_RESPONSE = sizeof(knot_response_t),
	/*! \brief Space for QNAME dname structure. */
	PREALLOC_QNAME_DNAME = sizeof(knot_dname_t),
	/*! \brief Space for QNAME name (maximum domain name size). */
	PREALLOC_QNAME_NAME = 256,
	/*! \brief Space for QNAME labels (maximum label count). */
	PREALLOC_QNAME_LABELS = 127,
	/*! \brief Total space for QNAME. */
	PREALLOC_QNAME = PREALLOC_QNAME_DNAME
	                 + PREALLOC_QNAME_NAME
	                 + PREALLOC_QNAME_LABELS,
	/*!
	 * \brief Space for RR owner wire format.
	 *
	 * Temporary buffer, used when putting RRSets to the response.
	 */
	PREALLOC_RR_OWNER = 256,

	/*! \brief Space for Answer RRSets. */
	PREALLOC_ANSWER = DEFAULT_ANCOUNT * sizeof(knot_dname_t *),
	/*! \brief Space for Authority RRSets. */
	PREALLOC_AUTHORITY = DEFAULT_NSCOUNT * sizeof(knot_dname_t *),
	/*! \brief Space for Additional RRSets. */
	PREALLOC_ADDITIONAL = DEFAULT_ARCOUNT * sizeof(knot_dname_t *),
	/*! \brief Total size for Answer, Authority and Additional RRSets. */
	PREALLOC_RRSETS = PREALLOC_ANSWER
	                  + PREALLOC_AUTHORITY
	                  + PREALLOC_ADDITIONAL,
	/*! \brief Space for one part of the compression table (domain names).*/
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(knot_dname_t *),
	/*! \brief Space for other part of the compression table (offsets). */
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(size_t),
	/*! \brief Space for temporary RRSets. */
	PREALLOC_TMP_RRSETS =
		DEFAULT_TMP_RRSETS * sizeof(knot_dname_t *),

	/*! \brief Total preallocated size for the response. */
	PREALLOC_TOTAL = PREALLOC_RESPONSE
	                 + PREALLOC_QNAME
	                 + PREALLOC_RR_OWNER
	                 + PREALLOC_RRSETS
	                 + PREALLOC_DOMAINS
	                 + PREALLOC_OFFSETS
	                 + PREALLOC_TMP_RRSETS,
};

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

//static int COMPRESS_DNAMES = 1;

static const size_t KNOT_RESPONSE_MAX_PTR = 16383;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets all the pointers in the response structure to the respective
 *        parts of the pre-allocated space.
 */
static void knot_response_init_pointers(knot_response_t *resp)
{
	debug_knot_response("Response pointer: %p\n", resp);
	// put QNAME directly after the structure
	resp->question.qname =
		(knot_dname_t *)((char *)resp + PREALLOC_RESPONSE);

	debug_knot_response("QNAME: %p (%zu after start of response)\n",
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
	resp->answer = (const knot_rrset_t **)
	                   ((char *)resp->owner_tmp + PREALLOC_RR_OWNER);
	resp->authority = resp->answer + DEFAULT_ANCOUNT;
	resp->additional = resp->authority + DEFAULT_NSCOUNT;

	debug_knot_response("Answer section: %p (%zu after QNAME)\n",
		resp->answer,
		(void *)resp->answer - (void *)resp->question.qname);
	debug_knot_response("Authority section: %p (%zu after Answer)\n",
		resp->authority,
		(void *)resp->authority - (void *)resp->answer);
	debug_knot_response("Additional section: %p (%zu after Authority)\n",
		resp->additional,
		(void *)resp->additional - (void *)resp->authority);

	resp->max_an_rrsets = DEFAULT_ANCOUNT;
	resp->max_ns_rrsets = DEFAULT_NSCOUNT;
	resp->max_ar_rrsets = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	resp->compression.dnames = (const knot_dname_t **)
	                               (resp->additional + DEFAULT_ARCOUNT);
	resp->compression.offsets = (size_t *)
		(resp->compression.dnames + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_knot_response("Compression dnames: %p (%zu after Additional)\n",
		resp->compression.dnames,
		(void *)resp->compression.dnames - (void *)resp->additional);
	debug_knot_response("Compression offsets: %p (%zu after c. dnames)\n",
		resp->compression.offsets,
		(void *)resp->compression.offsets
		  - (void *)resp->compression.dnames);

	resp->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;

	resp->tmp_rrsets = (const knot_rrset_t **)
		(resp->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_knot_response("Tmp rrsets: %p (%zu after compression offsets)"
		"\n", resp->tmp_rrsets,
		(void *)resp->tmp_rrsets - (void *)resp->compression.offsets);

	resp->tmp_rrsets_max = DEFAULT_TMP_RRSETS;

	debug_knot_response("End of data: %p (%zu after start of response)\n",
		resp->tmp_rrsets + DEFAULT_TMP_RRSETS,
		(void *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
		  - (void *)resp);
	debug_knot_response("Allocated total: %u\n", PREALLOC_TOTAL);

	assert((char *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
	       == (char *)resp + PREALLOC_TOTAL);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Initializes the response structure.
 *
 * Saves information from the given OPT RR, preallocates space for the
 * wire format of the response (maximum possible space) and initializes pointers
 * (see knot_response_init_pointers()).
 *
 * After initialization, the current size of the response will be set to the
 * size of the header (as the header is always present) and the QR bit will be
 * set.
 *
 * \param resp Response structure to initialize.
 * \param opt_rr OPT RR to be put to the response.
 * \param max_size Maximum size of the wire format of the response.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_init(knot_response_t *resp,
                                const knot_opt_rr_t *opt_rr,
                                size_t max_size)
{
	memset(resp, 0, PREALLOC_TOTAL);

	if (opt_rr == NULL) {
		resp->edns_response.version = EDNS_NOT_SUPPORTED;
		// set default max size of the response
		resp->max_size = max_size;
	} else {
		// copy the OPT RR
		resp->edns_response.version = opt_rr->version;
		resp->edns_response.ext_rcode = opt_rr->ext_rcode;
		resp->edns_response.payload = opt_rr->payload;
		resp->edns_response.size = opt_rr->size;

		if (max_size > 0 && max_size < opt_rr->payload) {
			return KNOT_EPAYLOAD;
		}

		resp->max_size = resp->edns_response.payload;
	}

	debug_knot_response("Response max size: %zu\n", resp->max_size);

	// pre-allocate space for wire format of the packet
	resp->wireformat = (uint8_t *)malloc(resp->max_size);
	if (resp->wireformat == NULL) {
		return KNOT_ENOMEM;
	}

	// save default pointers to the space after the structure
	knot_response_init_pointers(resp);

	// set header to all 0s
	memset(resp->wireformat, 0, KNOT_WIRE_HEADER_SIZE);
	// set the QR bit
	knot_wire_set_qr(resp->wireformat);
	// set the size to the size of header
	resp->size = KNOT_WIRE_HEADER_SIZE;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Parses DNS header from the wire format.
 *
 * \note This function also adjusts the position (\a pos) and size of remaining
 *       bytes in the wire format (\a remaining) according to what was parsed
 *       (though it actually always parses the 12 bytes of the header).
 *
 * \param[in,out] pos Wire format to parse the header from.
 * \param[in,out] remaining Remaining size of the wire format.
 * \param[out] header Header structure to fill in.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EFEWDATA
 */
static int knot_response_parse_header(const uint8_t **pos, size_t *remaining,
                                        knot_header_t *header)
{
	assert(pos != NULL);
	assert(*pos != NULL);
	assert(remaining != NULL);
	assert(header != NULL);

	if (*remaining < KNOT_WIRE_HEADER_SIZE) {
		debug_knot_response("Not enough data to parse header.\n");
		return KNOT_EFEWDATA;
	}

	header->id = knot_wire_get_id(*pos);
	// copy some of the flags: OPCODE and RD
	// do this by copying flags1 and setting QR to 1, AA to 0 and TC to 0
	header->flags1 = knot_wire_get_flags1(*pos);
	knot_wire_flags_set_qr(&header->flags1);
	knot_wire_flags_clear_aa(&header->flags1);
	knot_wire_flags_clear_tc(&header->flags1);
	// do not copy flags2 (all set by server)
	header->qdcount = knot_wire_get_qdcount(*pos);
	header->ancount = knot_wire_get_ancount(*pos);
	header->nscount = knot_wire_get_nscount(*pos);
	header->arcount = knot_wire_get_arcount(*pos);

	*pos += KNOT_WIRE_HEADER_SIZE;
	*remaining -= KNOT_WIRE_HEADER_SIZE;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts the header structure to wire format.
 *
 * \note This function also adjusts the position (\a pos) according to
 *       the size of the converted wire format.
 *
 * \param[in] header DNS header structure to convert.
 * \param[out] pos Position where to put the converted header.
 * \param[out] size Size of the wire format of the header in bytes.
 */
static void knot_response_header_to_wire(const knot_header_t *header,
                                           uint8_t **pos, size_t *size)
{
	knot_wire_set_id(*pos, header->id);
	knot_wire_set_flags1(*pos, header->flags1);
	knot_wire_set_flags2(*pos, header->flags2);
	knot_wire_set_qdcount(*pos, header->qdcount);
	knot_wire_set_ancount(*pos, header->ancount);
	knot_wire_set_nscount(*pos, header->nscount);
	knot_wire_set_arcount(*pos, header->arcount);

	*pos += KNOT_WIRE_HEADER_SIZE;
	*size += KNOT_WIRE_HEADER_SIZE;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Parses DNS Question entry from the wire format.
 *
 * \note This function also adjusts the position (\a pos) and size of remaining
 *       bytes in the wire format (\a remaining) according to what was parsed.
 *
 * \param[in,out] pos Wire format to parse the Question from.
 * \param[in,out] remaining Remaining size of the wire format.
 * \param[out] question DNS Question structure to be filled.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EFEWDATA
 * \retval KNOT_ENOMEM
 */
static int knot_response_parse_question(const uint8_t **pos,
                                          size_t *remaining,
                                          knot_question_t *question)
{
	assert(pos != NULL);
	assert(*pos != NULL);
	assert(remaining != NULL);
	assert(question != NULL);
	assert(question->qname != NULL);

	if (*remaining < KNOT_WIRE_QUESTION_MIN_SIZE) {
		debug_knot_response("Not enough data to parse question.\n");
		return KNOT_EFEWDATA;  // malformed
	}

	// domain name must end with 0, so just search for 0
	int i = 0;
	while (i < *remaining && (*pos)[i] != 0) {
		++i;
	}

	if (i == *remaining || *remaining - i - 1 < 4) {
		debug_knot_response("Not enough data to parse question.\n");
		return KNOT_EFEWDATA;  // no 0 found or not enough data left
	}

	int res = knot_dname_from_wire(*pos, i + 1, NULL, question->qname);
	if (res != KNOT_EOK) {
		assert(res != KNOT_EBADARG);
		return res;
	}

	*pos += i + 1;
	question->qtype = knot_wire_read_u16(*pos);
	*pos += 2;
	question->qclass = knot_wire_read_u16(*pos);
	*pos += 2;

	*remaining -= (i + 5);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts the Question structure to wire format.
 *
 * \note This function also adjusts the position (\a pos) according to
 *       the size of the converted wire format.
 *
 * \param[in] question DNS Question structure to convert.
 * \param[out] pos Position where to put the converted header.
 * \param[out] size Size of the wire format of the header in bytes.
 */
static void knot_response_question_to_wire(knot_question_t *question,
                                            uint8_t **pos, size_t *size)
{
	debug_knot_response("Copying QNAME, size %d\n",
	                      question->qname->size);
	memcpy(*pos, question->qname->name, question->qname->size);
	*size += question->qname->size;
	*pos += question->qname->size;

	knot_wire_write_u16(*pos, question->qtype);
	*pos += 2;
	knot_wire_write_u16(*pos, question->qclass);
	*pos += 2;
	*size += 4;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Parses OPT RR from the query.
 *
 * \note This function also adjusts the position (\a pos) and size of remaining
 *       bytes in the wire format (\a remaining) according to what was parsed.
 *
 * \param pos Position of the OPT RR in the wire format of the query.
 * \param remaining Remaining size of the wire format.
 * \param client_opt OPT RR structure to fill in.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 * \retval KNOT_EFEWDATA
 * \retval KNOT_EMALF
 */
static int knot_response_parse_client_edns(const uint8_t **pos,
                                             size_t *remaining,
                                             knot_opt_rr_t *client_opt)
{
	assert(pos != NULL);

	debug_knot_response("Parsing client EDNS OPT RR.\n");
	int parsed = knot_edns_new_from_wire(client_opt, *pos, *remaining);
	if (parsed < 0) {
		debug_knot_response("Error parsing EDNS OPT RR.\n");
		return parsed;
	}

	assert(*remaining >= parsed);
	*remaining -= parsed;
	*pos += parsed;

	return KNOT_EOK;
}

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
	int free_old = table->max != DEFAULT_DOMAINS_IN_RESPONSE;
	size_t *old_offsets = table->offsets;
	const knot_dname_t **old_dnames = table->dnames;

	short new_max_count = table->max + STEP_DOMAINS;

	size_t *new_offsets = (size_t *)malloc(new_max_count * sizeof(size_t));
	CHECK_ALLOC_LOG(new_offsets, -1);

	const knot_dname_t **new_dnames = (const knot_dname_t **)malloc(
		new_max_count * sizeof(knot_dname_t *));
	if (new_dnames == NULL) {
		ERR_ALLOC_FAILED;
		free(new_offsets);
		return KNOT_ENOMEM;
	}

	memcpy(new_offsets, table->offsets, table->max * sizeof(size_t));
	memcpy(new_dnames, table->dnames,
	       table->max * sizeof(knot_dname_t *));

	table->offsets = new_offsets;
	table->dnames = new_dnames;
	table->max = new_max_count;

	if (free_old) {
		free(old_offsets);
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
                                       const knot_dname_t *dname, size_t pos)
{
	assert(table->count < table->max);

	for (int i = 0; i < table->count; ++i) {
		if (table->dnames[i] == dname) {
			debug_knot_response("Already present, skipping..\n");
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
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_store_dname_pos(knot_compressed_dnames_t *table,
                                           const knot_dname_t *dname,
                                           int not_matched, size_t pos,
                                           size_t unmatched_offset)
{
DEBUG_KNOT_RESPONSE(
	char *name = knot_dname_to_str(dname);
	debug_knot_response("Putting dname %s into compression table."
	                      " Labels not matched: %d, position: %d,"
	                      ", pointer: %p\n", name, not_matched, pos, dname);
	free(name);
);
	if (pos > KNOT_RESPONSE_MAX_PTR) {
		debug_knot_response("Pointer larger than it can be, not"
		                      " saving\n");
		return KNOT_EDNAMEPTR;
	}

	if (table->count == table->max &&
	    knot_response_realloc_compr(table) != 0) {
		return KNOT_ENOMEM;
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
	const knot_dname_t *to_save = dname;
	size_t parent_pos = pos;
	int i = 0;

	while (to_save != NULL) {
		if (i == not_matched) {
			parent_pos = unmatched_offset;
		}

DEBUG_KNOT_RESPONSE(
		char *name = knot_dname_to_str(to_save);
		debug_knot_response("Putting dname %s into compression table."
		                      " Position: %d, pointer: %p\n",
		                      name, parent_pos, to_save);
		free(name);
);

		if (table->count == table->max &&
		    knot_response_realloc_compr(table) != 0) {
			debug_knot_response("Unable to realloc.\n");
			return KNOT_ENOMEM;
		}

//		debug_knot_response("Saving..\n");
		knot_response_compr_save(table, to_save, parent_pos);

		to_save = (knot_dname_node(to_save, 1) != NULL
		      && knot_node_parent(knot_dname_node(to_save, 1), 1)
		         != NULL) ? knot_node_owner(knot_node_parent(
		                      knot_dname_node(to_save, 1), 1))
		                  : NULL;

		debug_knot_response("i: %d\n", i);
		parent_pos += knot_dname_label_size(dname, i) + 1;
//		parent_pos += (i > 0)
//			      ? knot_dname_label_size(dname, i - 1) + 1 : 0;
		++i;
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
		debug_knot_response("Comparing dnames %p and %p\n",
		                      dname, table->dnames[i]);
DEBUG_KNOT_RESPONSE(
		char *name = knot_dname_to_str(dname);
		debug_knot_response("(%s and ", name);
		name = knot_dname_to_str(table->dnames[i]);
		debug_knot_response("%s)\n", name);
		free(name);
);
		//if (table->dnames[i] == dname) {
		int ret = (compr_cs)
		           ? knot_dname_compare_cs(table->dnames[i], dname)
		           : knot_dname_compare(table->dnames[i], dname);
		if (ret == 0) {
			debug_knot_response("Found offset: %d\n",
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

	return size + 2;
}

/*---------------------------------------------------------------------------*/
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
	/*!
	 * \todo Compress!!
	 *
	 * if pos == 0, do not store the position!
	 */

	// try to find the name or one of its ancestors in the compr. table
#ifdef COMPRESSION_PEDANTIC
	//knot_dname_t *to_find = knot_dname_copy(dname);
	knot_dname_t *to_find = (knot_dname_t *)dname;
	int copied = 0;
#else
	const knot_dname_t *to_find = dname;
#endif
	size_t offset = 0;
	int not_matched = 0;

	while (to_find != NULL && knot_dname_label_count(to_find) != 0) {
DEBUG_KNOT_RESPONSE(
		char *name = knot_dname_to_str(to_find);
		debug_knot_response("Searching for name %s in the compression"
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
			assert(to_find->node != to_find->node->parent);
			assert(to_find != to_find->node->parent->owner);
			to_find = to_find->node->parent->owner;
		}
#else
		// if case-sensitive comparation, we cannot just take the parent
		if (compr_cs || knot_dname_node(to_find, 1) == NULL
		    || knot_node_owner(knot_dname_node(to_find, 1))
		       != to_find
		    || knot_node_parent(knot_dname_node(to_find, 1), 1)
		       == NULL) {
			break;
		} else {
			assert(knot_dname_node(to_find, 1) !=
			       knot_node_parent(knot_dname_node(to_find, 1),
			                          1));
			assert(to_find != knot_node_owner(
			       knot_node_parent(knot_dname_node(to_find, 1),
			                          1)));
			to_find = knot_node_owner(
				knot_node_parent(knot_dname_node(to_find,
				                   1), 1));
		}
#endif
	}

#ifdef COMPRESSION_PEDANTIC
	if (copied) {
		knot_dname_free(&to_find);
	}
#endif

	if (offset > 0) {  // found such dname somewhere in the packet
		debug_knot_response("Found name in the compression table.\n");
		assert(offset >= KNOT_WIRE_HEADER_SIZE);
		size = knot_response_put_dname_ptr(dname, not_matched, offset,
		                                     dname_wire, max);
		if (size <= 0) {
			return KNOT_ESPACE;
		}
	} else {
		debug_knot_response("Not found, putting whole name.\n");
		// now just copy the dname without compressing
		if (dname->size > max) {
			return KNOT_ESPACE;
		}

		memcpy(dname_wire, dname->name, dname->size);
		size = dname->size;
	}

	// in either way, put info into the compression table
	assert(compr->wire_pos >= 0);
	if (knot_response_store_dname_pos(compr->table, dname, not_matched,
	                                    compr->wire_pos, offset) != 0) {
		debug_knot_response("Compression info could not be stored."
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

	if (size + ((compr->owner.pos == 0) ? compr->owner.size : 2) + 10
	    > max_size) {
		return KNOT_ESPACE;
	}

	debug_knot_response("Owner position: %zu\n", compr->owner.pos);

	// put owner if needed (already compressed)
	if (compr->owner.pos == 0) {
		memcpy(*rrset_wire, compr->owner.wire, compr->owner.size);
		compr->owner.pos = compr->wire_pos;
		*rrset_wire += compr->owner.size;
		size += compr->owner.size;
	} else {
		debug_knot_response("Putting pointer: %zu\n",
		                      compr->owner.pos);
		knot_wire_put_pointer(*rrset_wire, compr->owner.pos);
		*rrset_wire += 2;
		size += 2;
	}

	debug_knot_response("Wire format:\n");

	// put rest of RR 'header'
	knot_wire_write_u16(*rrset_wire, rrset->type);
	debug_knot_response("  Type: %u\n", rrset->type);
	debug_knot_response("  Type in wire: ");
	debug_knot_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	knot_wire_write_u16(*rrset_wire, rrset->rclass);
	debug_knot_response("  Class: %u\n", rrset->rclass);
	debug_knot_response("  Class in wire: ");
	debug_knot_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	knot_wire_write_u32(*rrset_wire, rrset->ttl);
	debug_knot_response("  TTL: %u\n", rrset->ttl);
	debug_knot_response("  TTL in wire: ");
	debug_knot_response_hex((char *)*rrset_wire, 4);
	*rrset_wire += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *rrset_wire;
	*rrset_wire += 2;

	size += 10;
	compr->wire_pos += size;

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(rrset->type);

	uint16_t rdlength = 0;

	for (int i = 0; i < rdata->count; ++i) {
		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME: {
			int ret = knot_response_compress_dname(
				knot_rdata_item(rdata, i)->dname,
				compr, *rrset_wire, max_size - size, compr_cs);

			if (ret < 0) {
				return KNOT_ESPACE;
			}

			debug_knot_response("Compressed dname size: %d\n",
			                      ret);
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
			if (size + dname->size > max_size) {
				return KNOT_ESPACE;
			}

			// save whole domain name
			memcpy(*rrset_wire, dname->name, dname->size);
			debug_knot_response("Uncompressed dname size: %d\n",
			                      dname->size);
			*rrset_wire += dname->size;
			rdlength += dname->size;
			compr->wire_pos += dname->size;
			break;
		}
//		case KNOT_RDATA_WF_BINARYWITHLENGTH: {
//			uint16_t *raw_data =
//				knot_rdata_item(rdata, i)->raw_data;

//			if (size + raw_data[0] + 1 > max_size) {
//				return KNOT_ESPACE;
//			}

//			// copy also the rdata item size
//			assert(raw_data[0] < 256);
//			**rrset_wire = raw_data[0];
//			*rrset_wire += 1;
//			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
//			debug_knot_response("Raw data size: %d\n",
//			                      raw_data[0] + 1);
//			*rrset_wire += raw_data[0];
//			rdlength += raw_data[0] + 1;
//			compr->wire_pos += raw_data[0] + 1;
//			break;
//		}
		default: {
			uint16_t *raw_data =
				knot_rdata_item(rdata, i)->raw_data;

			if (size + raw_data[0] > max_size) {
				return KNOT_ESPACE;
			}

			// copy just the rdata item data (without size)
			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
			debug_knot_response("Raw data size: %d\n",
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
DEBUG_KNOT_RESPONSE(
	char *name = knot_dname_to_str(rrset->owner);
	debug_knot_response("Converting RRSet with owner %s, type %s\n",
	                      name, knot_rrtype_to_string(rrset->type));
	free(name);
	debug_knot_response("  Size before: %d\n", *size);
);

	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		return KNOT_EOK;
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

	knot_compr_t compr_info;
	//compr_info.new_entries = 0;
	compr_info.table = compr;
	compr_info.wire_pos = wire_pos;
	compr_info.owner.pos = 0;
	compr_info.owner.wire = owner_tmp;
	compr_info.owner.size =
		knot_response_compress_dname(rrset->owner, &compr_info,
		                               owner_tmp, max_size, compr_cs);

	debug_knot_response("    Owner size: %d, position: %zu\n",
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
			debug_knot_response("Some RR didn't fit in.\n");
			return KNOT_ESPACE;
		}

		debug_knot_response("RR of size %d added.\n", ret);
		rrset_size += ret;
		++rrs;
	} while ((rdata = knot_rrset_rdata_next(rrset, rdata)) != NULL);

	//memcpy(*pos, rrset_wire, rrset_size);
	//*size += rrset_size;
	//*pos += rrset_size;

	// the whole RRSet did fit in
	assert (rrset_size <= max_size);
	*size += rrset_size;

	debug_knot_response("  Size after: %d\n", *size);

	return rrs;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Frees all temporary RRSets stored in the response structure.
 *
 * \param resp Response structure to free the temporary RRSets from.
 */
static void knot_response_free_tmp_rrsets(knot_response_t *resp)
{
	for (int i = 0; i < resp->tmp_rrsets_count; ++i) {
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		knot_rrset_deep_free(
			&(((knot_rrset_t **)(resp->tmp_rrsets))[i]), 1, 1, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Deallocates all space which was allocated additionally to the
 *        pre-allocated space of the response structure.
 *
 * \param resp Response structure that holds pointers to the allocated space.
 */
static void knot_response_free_allocated_space(knot_response_t *resp)
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
 * \brief
 */
//static short knot_response_rrset_size(const knot_rrset_t *rrset,
//                                        const knot_compressed_dnames_t *compr)
//{
//	// TODO: count in possible compression
//	short size = 0;

//	knot_rrtype_descriptor_t *desc =
//			knot_rrtype_descriptor_by_type(rrset->type);

//	const knot_rdata_t *rdata = knot_rrset_rdata(rrset);
//	while (rdata != NULL) {
//		size += 10;  // 2 type, 2 class, 4 ttl, 2 rdlength
//		size += rrset->owner->size;   // owner

//		for (int i = 0; i < rdata->count; ++i) {
//			switch (desc->wireformat[i]) {
//			case KNOT_RDATA_WF_COMPRESSED_DNAME:
//			case KNOT_RDATA_WF_LITERAL_DNAME:
//			case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
//				debug_knot_response("dname size: %d\n",
//					rdata->items[i].dname->size);
//				size += rdata->items[i].dname->size;
//				break;
//			case KNOT_RDATA_WF_BINARYWITHLENGTH:
//				debug_knot_response("raw data size: %d\n",
//					rdata->items[i].raw_data[0] + 1);
//				size += rdata->items[i].raw_data[0] + 1;
//				break;
//			default:
//				debug_knot_response("raw data size: %d\n",
//					rdata->items[i].raw_data[0]);
//				size += rdata->items[i].raw_data[0];
//				break;
//			}
//		}

//		rdata = knot_rrset_rdata_next(rrset, rdata);
//	}

//	return size;
//}

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
                                        knot_response_t *resp,
                                        size_t max_size,
                                        const knot_rrset_t *rrset, int tc,
                                        int compr_cs)
{
	//short size = knot_response_rrset_size(rrset, &resp->compression);

DEBUG_KNOT_RESPONSE(
	char *name = knot_dname_to_str(rrset->owner);
	debug_knot_response("\nAdding RRSet with owner %s and type %s: \n",
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
		debug_knot_response("RRset added, size: %d, RRs: %d, total "
		                      "size of response: %d\n\n", size, rrs,
		                      resp->size);
	} else if (tc) {
		knot_wire_flags_set_tc(&resp->header.flags1);
	}

	return rrs;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the response already contains the given RRSet.
 *
 * It searches for the RRSet in the three lists of RRSets corresponding to
 * Answer, Authority and Additional sections of the response.
 *
 * \note Only pointers are compared, i.e. two instances of knot_rrset_t with
 * the same data will be considered different.
 *
 * \param resp Response to look for the RRSet in.
 * \param rrset RRSet to look for.
 *
 * \retval 0 if \a resp does not contain \a rrset.
 * \retval <> 0 if \a resp does contain \a rrset.
 */
static int knot_response_contains(const knot_response_t *resp,
                                    const knot_rrset_t *rrset)
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
/*!
 * \brief Converts the stored response OPT RR to wire format and adds it to
 *        the response wire format.
 *
 * \param resp Response structure.
 */
static void knot_response_edns_to_wire(knot_response_t *resp)
{
	resp->size += knot_edns_to_wire(&resp->edns_response,
	                                  resp->wireformat + resp->size,
	                                  resp->max_size - resp->size);

	resp->header.arcount += 1;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_response_t *knot_response_new_empty(const knot_opt_rr_t *opt_rr)
{
	knot_response_t *resp = (knot_response_t *)malloc(PREALLOC_TOTAL);
	CHECK_ALLOC_LOG(resp, NULL);

	if (knot_response_init(resp, opt_rr, KNOT_MAX_RESPONSE_SIZE) != 0) {
		free(resp);
		return NULL;
	}

	return resp;
}

/*----------------------------------------------------------------------------*/

knot_response_t *knot_response_new(size_t max_wire_size)
{
	knot_response_t *resp = (knot_response_t *)malloc(PREALLOC_TOTAL);
	CHECK_ALLOC_LOG(resp, NULL);

	if (knot_response_init(resp, NULL, max_wire_size) != 0) {
		free(resp);
		return NULL;
	}

	return resp;
}

/*----------------------------------------------------------------------------*/

void knot_response_clear(knot_response_t *resp, int clear_question)
{
	resp->size = (clear_question) ? KNOT_WIRE_HEADER_SIZE
	              : KNOT_WIRE_HEADER_SIZE + 4
	                + knot_dname_size(resp->question.qname);
	resp->an_rrsets = 0;
	resp->ns_rrsets = 0;
	resp->ar_rrsets = 0;
	resp->compression.count = 0;
	knot_response_free_tmp_rrsets(resp);
	resp->tmp_rrsets_count = 0;
	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_opt(knot_response_t *resp,
                            const knot_opt_rr_t *opt_rr,
                            int override_max_size)
{
	if (resp == NULL || opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	// copy the OPT RR
	resp->edns_response.version = opt_rr->version;
	resp->edns_response.ext_rcode = opt_rr->ext_rcode;
	resp->edns_response.payload = opt_rr->payload;
	resp->edns_response.size = opt_rr->size;

	// if max size is set, it means there is some reason to be that way,
	// so we can't just set it to higher value

	if (override_max_size && resp->max_size > 0
	    && resp->max_size < opt_rr->payload) {
		return KNOT_EPAYLOAD;
	}

//	if (resp->max_size < resp->edns_response.payload) {
//		// reallocate space for the wire format (and copy anything
//		// that might have been there before
//		uint8_t *wire_new = (uint8_t *)malloc(
//		                      resp->edns_response.payload);
//		if (wire_new == NULL) {
//			return KNOT_ENOMEM;
//		}

//		memcpy(wire_new, resp->wireformat, resp->max_size);
//		resp->wireformat = wire_new;
//	}

	// set max size (less is OK)
	if (override_max_size) {
		resp->max_size = resp->edns_response.payload;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_set_max_size(knot_response_t *resp, int max_size)
{
	if (resp == NULL || max_size <= 0) {
		return KNOT_EBADARG;
	}

	if (resp->max_size < max_size) {
		// reallocate space for the wire format (and copy anything
		// that might have been there before
		uint8_t *wire_new = (uint8_t *)malloc(max_size);
		if (wire_new == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(wire_new, resp->wireformat, resp->max_size);
		resp->wireformat = wire_new;
	}

	// set max size
	resp->max_size = max_size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_parse_query(knot_response_t *resp,
                                const uint8_t *query_wire, size_t query_size)
{
	if (resp == NULL || query_wire == NULL
	    || resp->question.qname == NULL) {
		return KNOT_EBADARG;
	}

	int err = 0;

	const uint8_t *pos = query_wire;
	size_t remaining = query_size;

	uint8_t *resp_pos = resp->wireformat;
	size_t size = 0;

	// header parsing is maybe useless, we may just copy the wire format
	if ((err = knot_response_parse_header(
	               &pos, &remaining, &resp->header)) != KNOT_EOK) {
		return err;
	}

	knot_response_header_to_wire(&resp->header, &resp_pos, &size);
	debug_knot_response("Converted header, size so far: %d\n", size);

	if (pos == NULL) {
		return KNOT_EMALF;
	}
	if ((err = knot_response_parse_question(
	               &pos, &remaining, &resp->question)) != KNOT_EOK) {
		return err;
	}
	resp->header.qdcount = 1;

	// put the qname into the compression table
	if ((err = knot_response_store_dname_pos(&resp->compression,
	              resp->question.qname, 0, size, size)) != KNOT_EOK) {
		return err;
	}

	knot_response_question_to_wire(&resp->question, &resp_pos, &size);
	debug_knot_response("Converted Question, size so far: %d\n", size);
	//resp->size += resp->question.qname->size + 4;

	resp->size = size;

	if (resp->header.arcount > 0) {  // expecting EDNS OPT RR
		if ((err = knot_response_parse_client_edns(
			       &pos, &remaining, &resp->edns_query))) {
			return KNOT_EMALF;
		}
		if (knot_edns_get_payload(&resp->edns_query)
		    && knot_edns_get_payload(&resp->edns_query)
			< resp->max_size) {
			resp->max_size = resp->edns_query.payload;
		}
		// copy the DO bit into response
		if (knot_edns_do(&resp->edns_query)) {
			knot_edns_set_do(&resp->edns_response);
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
		debug_knot_response("response: %zu bytes of trailing garbage "
		                      "in query.\n", remaining);
	}
#ifdef KNOT_RESPONSE_DEBUG
	knot_response_dump(resp);
#endif /* KNOT_RESPONSE_DEBUG */
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_response_opcode(const knot_response_t *response)
{
	return knot_wire_flags_get_opcode(response->header.flags1);
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_response_qname(const knot_response_t *response)
{
	return response->question.qname;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_response_qtype(const knot_response_t *response)
{
	return response->question.qtype;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_response_qclass(const knot_response_t *response)
{
	return response->question.qclass;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_answer(knot_response_t *response,
                                     const knot_rrset_t *rrset, int tc,
                                     int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EBADARG;
	}

	debug_knot_response("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && knot_response_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
	       != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_response_contains(response, rrset)) {
		return KNOT_EOK;
	}

	debug_knot_response("Trying to add RRSet to Answer section.\n");
	debug_knot_response("RRset: %p\n", rrset);
	debug_knot_response("Owner: %p\n", rrset->owner);

	int rrs = knot_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.ancount += rrs;
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_authority(knot_response_t *response,
                                        const knot_rrset_t *rrset, int tc,
                                        int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EBADARG;
	}

	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && knot_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_response_contains(response, rrset)) {
		return KNOT_EOK;
	}

	debug_knot_response("Trying to add RRSet to Authority section.\n");

	int rrs = knot_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.nscount += rrs;
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_additional(knot_response_t *response,
                                         const knot_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EBADARG;
	}

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->edns_query.version != EDNS_NOT_SUPPORTED
	    && response->edns_response.version != EDNS_NOT_SUPPORTED) {
		knot_response_edns_to_wire(response);
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && knot_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_response_contains(response, rrset)) {
		return KNOT_EOK;
	}

	debug_knot_response("Trying to add RRSet to Additional section.\n");

	int rrs = knot_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size, rrset, tc,
	                                        compr_cs);

	if (rrs >= 0) {
		response->header.arcount += rrs;
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

void knot_response_set_rcode(knot_response_t *response, short rcode)
{
	knot_wire_flags_set_rcode(&response->header.flags2, rcode);
	knot_wire_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_aa(knot_response_t *response)
{
	knot_wire_flags_set_aa(&response->header.flags1);
	knot_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_tc(knot_response_t *response)
{
	knot_wire_flags_set_tc(&response->header.flags1);
	knot_wire_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_tmp_rrset(knot_response_t *response,
                                  knot_rrset_t *tmp_rrset)
{
	if (response->tmp_rrsets_count == response->tmp_rrsets_max
	    && knot_response_realloc_rrsets(&response->tmp_rrsets,
			&response->tmp_rrsets_max, DEFAULT_TMP_RRSETS,
			STEP_TMP_RRSETS) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	response->tmp_rrsets[response->tmp_rrsets_count++] = tmp_rrset;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

short knot_response_answer_rrset_count(const knot_response_t *response)
{
	return response->an_rrsets;
}

/*----------------------------------------------------------------------------*/

short knot_response_authority_rrset_count(const knot_response_t *response)
{
	return response->ns_rrsets;
}

/*----------------------------------------------------------------------------*/

short knot_response_additional_rrset_count(const knot_response_t *response)
{
	return response->ar_rrsets;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_response_answer_rrset(
	const knot_response_t *response, short pos)
{
	if (pos > response->an_rrsets) {
		return NULL;
	}

	return response->answer[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_response_authority_rrset(
	knot_response_t *response, short pos)
{
	if (pos > response->ns_rrsets) {
		return NULL;
	}

	return response->authority[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_response_additional_rrset(
	knot_response_t *response, short pos)
{
	if (pos > response->ar_rrsets) {
		return NULL;
	}

	return response->additional[pos];
}

/*----------------------------------------------------------------------------*/

int knot_response_dnssec_requested(const knot_response_t *response)
{
	return knot_edns_do(&response->edns_query);
}

/*----------------------------------------------------------------------------*/

int knot_response_nsid_requested(const knot_response_t *response)
{
	return knot_edns_has_option(&response->edns_query, EDNS_OPTION_NSID);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_nsid(knot_response_t *response, const uint8_t *data,
                             uint16_t length)
{
	return knot_edns_add_option(&response->edns_response,
	                              EDNS_OPTION_NSID, length, data);
}

/*----------------------------------------------------------------------------*/

int knot_response_to_wire(knot_response_t *resp,
                            uint8_t **resp_wire, size_t *resp_size)
{
	if (resp == NULL || resp_wire == NULL || resp_size == NULL
	    || *resp_wire != NULL) {
		return KNOT_EBADARG;
	}

	assert(resp->size <= resp->max_size);

	// if there are no additional RRSets, add EDNS OPT RR
	if (resp->header.arcount == 0
	    && resp->edns_query.version != EDNS_NOT_SUPPORTED
	    && resp->edns_response.version != EDNS_NOT_SUPPORTED) {
	    knot_response_edns_to_wire(resp);
	}

	// set ANCOUNT to the packet
	knot_wire_set_ancount(resp->wireformat, resp->header.ancount);
	// set NSCOUNT to the packet
	knot_wire_set_nscount(resp->wireformat, resp->header.nscount);
	// set ARCOUNT to the packet
	knot_wire_set_arcount(resp->wireformat, resp->header.arcount);

	//assert(response->size == size);
	*resp_wire = resp->wireformat;
	*resp_size = resp->size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_response_free(knot_response_t **response)
{
	if (response == NULL || *response == NULL) {
		return;
	}

	// free temporary domain names
	debug_knot_response("Freeing tmp domains...\n");
	knot_response_free_tmp_rrsets(*response);

	// check if some additional space was allocated for the response
	debug_knot_response("Freeing additional allocated space...\n");
	knot_response_free_allocated_space(*response);

	// free the space for wireformat
	assert((*response)->wireformat != NULL);
	free((*response)->wireformat);

	debug_knot_response("Freeing response structure\n");
	free(*response);
	*response = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef KNOT_RESPONSE_DEBUG
static void knot_response_dump_rrsets(const knot_rrset_t **rrsets,
                                        int count)
{
	for (int i = 0; i < count; ++i) {
		debug_knot_response("  RRSet %d:\n", i + 1);
		char *name = knot_dname_to_str(rrsets[i]->owner);
		debug_knot_response("    Owner: %s\n", name);
		free(name);
		debug_knot_response("    Type: %s\n",
		                      knot_rrtype_to_string(rrsets[i]->type));
		debug_knot_response("    Class: %s\n",
		                   knot_rrclass_to_string(rrsets[i]->rclass));
		debug_knot_response("    TTL: %d\n", rrsets[i]->ttl);
		debug_knot_response("    RDATA: ");

		knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(rrsets[i]->type);

		const knot_rdata_t *rdata = knot_rrset_rdata(rrsets[i]);
		while (rdata != NULL) {
			for (int j = 0; j < rdata->count; ++j) {
				switch (desc->wireformat[j]) {
				case KNOT_RDATA_WF_COMPRESSED_DNAME:
				case KNOT_RDATA_WF_LITERAL_DNAME:
				case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
					name = knot_dname_to_str(
						rdata->items[j].dname);
					debug_knot_response("%s \n",name);
					free(name);
					break;
				case KNOT_RDATA_WF_BINARYWITHLENGTH:
					debug_knot_response_hex(
					    (char *)rdata->items[j].raw_data,
					    rdata->items[j].raw_data[0]);
					break;
				default:
					debug_knot_response_hex(
					   (char *)&rdata->items[j].raw_data[1],
					   rdata->items[j].raw_data[0]);
					break;
				}
			}
			rdata = knot_rrset_rdata_next(rrsets[i], rdata);
		}
	}
}
#endif
/*----------------------------------------------------------------------------*/

void knot_response_dump(const knot_response_t *resp)
{
#ifdef KNOT_RESPONSE_DEBUG
	debug_knot_response("DNS response:\n-----------------------------\n");

	debug_knot_response("\nHeader:\n");
	debug_knot_response("  ID: %u", resp->header.id);
	debug_knot_response("  FLAGS: %s %s %s %s %s %s %s\n",
	       knot_wire_flags_get_qr(resp->header.flags1) ? "qr" : "",
	       knot_wire_flags_get_aa(resp->header.flags1) ? "aa" : "",
	       knot_wire_flags_get_tc(resp->header.flags1) ? "tc" : "",
	       knot_wire_flags_get_rd(resp->header.flags1) ? "rd" : "",
	       knot_wire_flags_get_ra(resp->header.flags2) ? "ra" : "",
	       knot_wire_flags_get_ad(resp->header.flags2) ? "ad" : "",
	       knot_wire_flags_get_cd(resp->header.flags2) ? "cd" : "");
	debug_knot_response("  QDCOUNT: %u\n", resp->header.qdcount);
	debug_knot_response("  ANCOUNT: %u\n", resp->header.ancount);
	debug_knot_response("  NSCOUNT: %u\n", resp->header.nscount);
	debug_knot_response("  ARCOUNT: %u\n", resp->header.arcount);

	debug_knot_response("\nQuestion:\n");
	char *qname = knot_dname_to_str(resp->question.qname);
	debug_knot_response("  QNAME: %s\n", qname);
	free(qname);
	debug_knot_response("  QTYPE: %u (%s)\n", resp->question.qtype,
	       knot_rrtype_to_string(resp->question.qtype));
	debug_knot_response("  QCLASS: %u (%s)\n", resp->question.qclass,
	       knot_rrclass_to_string(resp->question.qclass));

	debug_knot_response("\nAnswer RRSets:\n");
	knot_response_dump_rrsets(resp->answer, resp->an_rrsets);
	debug_knot_response("\nAuthority RRSets:\n");
	knot_response_dump_rrsets(resp->authority, resp->ns_rrsets);
	debug_knot_response("\nAdditional RRSets:\n");
	knot_response_dump_rrsets(resp->additional, resp->ar_rrsets);

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	debug_knot_response("\nEDNS - client:\n");
	debug_knot_response("  Version: %u\n", resp->edns_query.version);
	debug_knot_response("  Payload: %u\n", resp->edns_query.payload);
	debug_knot_response("  Extended RCODE: %u\n",
	                      resp->edns_query.ext_rcode);

	debug_knot_response("\nResponse size: %d\n", resp->size);
	debug_knot_response("\n-----------------------------\n");
#endif
}
