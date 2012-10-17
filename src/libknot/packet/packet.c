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

#include <assert.h>

#include "packet/packet.h"
#include "util/debug.h"
#include "common.h"
#include "util/descriptor.h"
#include "util/wire.h"
#include "tsig.h"

/*----------------------------------------------------------------------------*/

#define DEFAULT_RRCOUNT_QUERY(type) DEFAULT_##type##COUNT_QUERY
#define DEFAULT_RRCOUNT(type) DEFAULT_##type##COUNT

#define DEFAULT_RRSET_COUNT(type, packet) \
	((packet->prealloc_type == KNOT_PACKET_PREALLOC_NONE)  \
		? 0  \
		: (packet->prealloc_type == KNOT_PACKET_PREALLOC_QUERY)  \
			? DEFAULT_##type##_QUERY  \
			: DEFAULT_##type)



typedef enum {
	KNOT_PACKET_DUPL_IGNORE,
	KNOT_PACKET_DUPL_SKIP,
	KNOT_PACKET_DUPL_MERGE
} knot_packet_duplicate_handling_t;
/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets all the pointers in the packet structure to the respective
 *        parts of the pre-allocated space.
 */
static void knot_packet_init_pointers_response(knot_packet_t *pkt)
{
	dbg_packet_detail("Packet pointer: %p\n", pkt);
	
	char *pos = (char *)pkt + PREALLOC_PACKET;

	// put QNAME directly after the structure
	pkt->question.qname = (knot_dname_t *)pos;
	pos += PREALLOC_QNAME_DNAME;

	dbg_packet_detail("QNAME: %p\n", pkt->question.qname);

	pkt->question.qname->name = (uint8_t *)pos;
	pos += PREALLOC_QNAME_NAME;
	pkt->question.qname->labels = (uint8_t *)pos;
	pos += PREALLOC_QNAME_LABELS;

	pkt->owner_tmp = (uint8_t *)pos;
	dbg_packet_detail("Tmp owner: %p\n", pkt->owner_tmp);
	pos += PREALLOC_RR_OWNER;

	// then answer, authority and additional sections
	if (DEFAULT_ANCOUNT == 0) {
		pkt->answer = NULL;
	} else {
		pkt->answer = (const knot_rrset_t **)pos;
		pos += DEFAULT_ANCOUNT * sizeof(const knot_rrset_t *);
	}
	
	if (DEFAULT_NSCOUNT == 0) {
		pkt->authority = NULL;
	} else {
		pkt->authority = (const knot_rrset_t **)pos;
		pos += DEFAULT_NSCOUNT * sizeof(const knot_rrset_t *);
	}
	
	if (DEFAULT_ARCOUNT == 0) {
		pkt->additional = NULL;
	} else {
		pkt->additional = (const knot_rrset_t **)pos;
		pos += DEFAULT_ARCOUNT * sizeof(const knot_rrset_t *);
	}

	dbg_packet_detail("Answer section: %p\n", pkt->answer);
	dbg_packet_detail("Authority section: %p\n", pkt->authority);
	dbg_packet_detail("Additional section: %p\n", pkt->additional);

	pkt->max_an_rrsets = DEFAULT_ANCOUNT;
	pkt->max_ns_rrsets = DEFAULT_NSCOUNT;
	pkt->max_ar_rrsets = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	pkt->compression.dnames = (const knot_dname_t **)pos;
	pos += DEFAULT_DOMAINS_IN_RESPONSE * sizeof(const knot_dname_t *);
	pkt->compression.offsets = (size_t *)pos;
	pos += DEFAULT_DOMAINS_IN_RESPONSE * sizeof(size_t);
	pkt->compression.to_free = (int *)pos;
	pos += DEFAULT_DOMAINS_IN_RESPONSE * sizeof(int);

	dbg_packet_detail("Compression dnames: %p\n", pkt->compression.dnames);
	dbg_packet_detail("Compression offsets: %p\n", pkt->compression.offsets);
	dbg_packet_detail("Compression to_free: %p\n", pkt->compression.to_free);

	pkt->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;
	pkt->compression.default_count = DEFAULT_DOMAINS_IN_RESPONSE;

	// wildcard nodes and SNAMEs associated with them
	pkt->wildcard_nodes.nodes = (const knot_node_t **)pos;
	pos += DEFAULT_WILDCARD_NODES * sizeof(const knot_node_t *);
	pkt->wildcard_nodes.snames = (const knot_dname_t **)pos;
	pos += DEFAULT_WILDCARD_NODES * sizeof(knot_dname_t *);

	dbg_packet_detail("Wildcard nodes: %p\n", pkt->wildcard_nodes.nodes);
	dbg_packet_detail("Wildcard SNAMEs: %p\n", pkt->wildcard_nodes.snames);

	pkt->wildcard_nodes.default_count = DEFAULT_WILDCARD_NODES;
	pkt->wildcard_nodes.max = DEFAULT_WILDCARD_NODES;

	pkt->tmp_rrsets = (const knot_rrset_t **)pos;
	pos += DEFAULT_TMP_RRSETS * sizeof(const knot_rrset_t *);

	dbg_packet_detail("Tmp rrsets: %p\n", pkt->tmp_rrsets);

	pkt->tmp_rrsets_max = DEFAULT_TMP_RRSETS;

	assert((char *)pos == (char *)pkt + PREALLOC_RESPONSE);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets all the pointers in the packet structure to the respective
 *        parts of the pre-allocated space.
 */
static void knot_packet_init_pointers_query(knot_packet_t *pkt)
{
	dbg_packet_detail("Packet pointer: %p\n", pkt);
	
	char *pos = (char *)pkt + PREALLOC_PACKET;

	// put QNAME directly after the structure
	pkt->question.qname = (knot_dname_t *)pos;
	pos += PREALLOC_QNAME_DNAME;

	dbg_packet_detail("QNAME: %p (%zu after start of packet)\n",
	                  pkt->question.qname,
	                  (void *)pkt->question.qname - (void *)pkt);

	pkt->question.qname->name = (uint8_t *)pos;
	pos += PREALLOC_QNAME_NAME;
	pkt->question.qname->labels = (uint8_t *)pos;
	pos += PREALLOC_QNAME_LABELS;


	// then answer, authority and additional sections
	if (DEFAULT_ANCOUNT_QUERY == 0) {
		pkt->answer = NULL;
	} else {
		pkt->answer = (const knot_rrset_t **)pos;
		pos += DEFAULT_ANCOUNT_QUERY * sizeof(const knot_rrset_t *);
	}
	
	if (DEFAULT_NSCOUNT_QUERY == 0) {
		pkt->authority = NULL;
	} else {
		pkt->authority = (const knot_rrset_t **)pos;
		pos += DEFAULT_NSCOUNT_QUERY * sizeof(const knot_rrset_t *);
	}
	
	if (DEFAULT_ARCOUNT_QUERY == 0) {
		pkt->additional = NULL;
	} else {
		pkt->additional = (const knot_rrset_t **)pos;
		pos += DEFAULT_ARCOUNT_QUERY * sizeof(const knot_rrset_t *);
	}

	dbg_packet_detail("Answer section: %p\n", pkt->answer);
	dbg_packet_detail("Authority section: %p\n", pkt->authority);
	dbg_packet_detail("Additional section: %p\n", pkt->additional);

	pkt->max_an_rrsets = DEFAULT_ANCOUNT_QUERY;
	pkt->max_ns_rrsets = DEFAULT_NSCOUNT_QUERY;
	pkt->max_ar_rrsets = DEFAULT_ARCOUNT_QUERY;

	pkt->tmp_rrsets = (const knot_rrset_t **)pos;
	pos += DEFAULT_TMP_RRSETS_QUERY * sizeof(const knot_rrset_t *);

	dbg_packet_detail("Tmp rrsets: %p\n", pkt->tmp_rrsets);

	pkt->tmp_rrsets_max = DEFAULT_TMP_RRSETS_QUERY;

	dbg_packet_detail("Allocated total: %u\n", PREALLOC_QUERY);

	assert(pos == (char *)pkt + PREALLOC_QUERY);
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
static int knot_packet_parse_header(const uint8_t *wire, size_t *pos,
                                      size_t size, knot_header_t *header)
{
	assert(wire != NULL);
	assert(pos != NULL);
	assert(header != NULL);

	if (size - *pos < KNOT_WIRE_HEADER_SIZE) {
		dbg_packet("Not enough data to parse header.\n");
		return KNOT_EFEWDATA;
	}

	header->id = knot_wire_get_id(wire);
	// copy some of the flags: OPCODE and RD
	// do this by copying flags1 and setting QR to 1, AA to 0 and TC to 0
	header->flags1 = knot_wire_get_flags1(wire);
	// do not copy flags2 (all set by server)

	header->qdcount = knot_wire_get_qdcount(wire);
	header->ancount = knot_wire_get_ancount(wire);
	header->nscount = knot_wire_get_nscount(wire);
	header->arcount = knot_wire_get_arcount(wire);

	*pos += KNOT_WIRE_HEADER_SIZE;

	return KNOT_EOK;
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
static int knot_packet_parse_question(const uint8_t *wire, size_t *pos,
                                        size_t size,
                                        knot_question_t *question, int alloc)
{
	assert(pos != NULL);
	assert(wire != NULL);
	assert(question != NULL);

	if (size - *pos < KNOT_WIRE_QUESTION_MIN_SIZE) {
		dbg_packet("Not enough data to parse question.\n");
		return KNOT_EFEWDATA;  // malformed
	}

	dbg_packet("Parsing Question starting on position %zu.\n", *pos);

	// domain name must end with 0, so just search for 0
	int i = *pos;
	while (i < size && wire[i] != 0) {
		++i;
	}

	if (size - i - 1 < 4) {
		dbg_packet("Not enough data to parse question.\n");
		return KNOT_EFEWDATA;  // no 0 found or not enough data left
	}

	dbg_packet_verb("Parsing dname starting on position %zu and "
	                      "%zu bytes long.\n", *pos, i - *pos + 1);
	dbg_packet_verb("Alloc: %d\n", alloc);
	if (alloc) {
		question->qname = knot_dname_new_from_wire(
				wire + *pos, i - *pos + 1, NULL);
		if (question->qname == NULL) {
			return KNOT_ENOMEM;
		}
	} else {
		int res = knot_dname_from_wire(wire + *pos, i - *pos + 1,
	                                         NULL, question->qname);
		if (res != KNOT_EOK) {
			assert(res != KNOT_EINVAL);
			return res;
		}
	}

	*pos = i + 1;
	question->qtype = knot_wire_read_u16(wire + i + 1);
	question->qclass = knot_wire_read_u16(wire + i + 3);
	*pos += 4;

	return KNOT_EOK;
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
static int knot_packet_realloc_rrsets(const knot_rrset_t ***rrsets,
                                        short *max_count,
                                        short default_max_count, short step)
{
	dbg_packet_verb("Max count: %d, default max count: %d\n",
	       *max_count, default_max_count);
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

static knot_rdata_t *knot_packet_parse_rdata(const uint8_t *wire,
	size_t *pos, size_t total_size, size_t rdlength,
	const knot_rrtype_descriptor_t *desc)
{
	knot_rdata_t *rdata = knot_rdata_new();
	if (rdata == NULL) {
		return NULL;
	}

	int rc = knot_rdata_from_wire(rdata, wire, pos, total_size, rdlength,
	                                desc);

	if (rc != KNOT_EOK) {
		dbg_packet("rdata_from_wire() returned: %s\n",
		           knot_strerror(rc));
		knot_rdata_free(&rdata);
		return NULL;
	}

	return rdata;
}

/*----------------------------------------------------------------------------*/

static knot_rrset_t *knot_packet_parse_rr(const uint8_t *wire, size_t *pos,
                                              size_t size)
{
	dbg_packet("Parsing RR from position: %zu, total size: %zu\n",
	           *pos, size);

	knot_dname_t *owner = knot_dname_parse_from_wire(wire, pos, size,
	                                                     NULL);
	dbg_packet_detail("Created owner: %p, actual position: %zu\n", owner,
	                  *pos);
	if (owner == NULL) {
		return NULL;
	}

dbg_packet_exec_verb(
	char *name = knot_dname_to_str(owner);
	dbg_packet_verb("Parsed name: %s\n", name);
	free(name);
);

	/*! @todo Get rid of the numerical constant. */
	if (size - *pos < 10) {
		dbg_packet("Malformed RR: Not enough data to parse RR"
		           " header.\n");
		knot_dname_release(owner);
		return NULL;
	}

	dbg_packet_detail("Reading type from position %zu\n", *pos);

	uint16_t type = knot_wire_read_u16(wire + *pos);
	uint16_t rclass = knot_wire_read_u16(wire + *pos + 2);
	uint32_t ttl = knot_wire_read_u32(wire + *pos + 4);

	knot_rrset_t *rrset = knot_rrset_new(owner, type, rclass, ttl);

	/* Owner is either referenced in rrset or rrset creation failed. */
	knot_dname_release(owner);

	/* Check rrset allocation. */
	if (rrset == NULL) {
		return NULL;
	}

	uint16_t rdlength = knot_wire_read_u16(wire + *pos + 8);

	dbg_packet_detail("Read RR header: type %u, class %u, ttl %u, "
	                    "rdlength %u\n", rrset->type, rrset->rclass,
	                    rrset->ttl, rdlength);

	*pos += 10;

	if (size - *pos < rdlength) {
		dbg_packet("Malformed RR: Not enough data to parse RR"
		           " RDATA (size: %zu, position: %zu).\n", size, *pos);
		knot_rrset_deep_free(&rrset, 1, 1, 0);
		return NULL;
	}

	rrset->rrsigs = NULL;

	if (rdlength == 0) {
		return rrset;
	}

	// parse RDATA
	knot_rdata_t *rdata = knot_packet_parse_rdata(wire, pos, size,
	                         rdlength,
	                         knot_rrtype_descriptor_by_type(rrset->type));
	if (rdata == NULL) {
		dbg_packet("Malformed RR: Could not parse RDATA.\n");
		knot_rrset_deep_free(&rrset, 1, 1, 0);
		return NULL;
	}

	if (knot_rrset_add_rdata(rrset, rdata) != KNOT_EOK) {
		dbg_packet("Malformed RR: Could not add RDATA to RRSet.\n");
		knot_rdata_free(&rdata);
		knot_rrset_deep_free(&rrset, 1, 1, 0);
		return NULL;
	}

	return rrset;
}

/*----------------------------------------------------------------------------*/

static int knot_packet_add_rrset(knot_rrset_t *rrset,
                                 const knot_rrset_t ***rrsets,
                                 short *rrset_count,
                                 short *max_rrsets,
                                 short default_rrsets,
                                 const knot_packet_t *packet,
                                 knot_packet_duplicate_handling_t dupl)
{
	assert(rrset != NULL);
	assert(rrsets != NULL);
	assert(rrset_count != NULL);
	assert(max_rrsets != NULL);

dbg_packet_exec_verb(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_packet_verb("packet_add_rrset(), owner: %s, type: %s\n",
	                name, knot_rrtype_to_string(rrset->type));
	free(name);
);

	if (*rrset_count == *max_rrsets
	    && knot_packet_realloc_rrsets(rrsets, max_rrsets, default_rrsets,
	                                    STEP_ANCOUNT) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if (dupl == KNOT_PACKET_DUPL_SKIP &&
	    knot_packet_contains(packet, rrset, KNOT_RRSET_COMPARE_PTR)) {
		/*! \todo This should also return > 0, as it means that the
		          RRSet was not used actually. */
		return KNOT_EOK;
	}

	if (dupl == KNOT_PACKET_DUPL_MERGE) {
		// try to find the RRSet in this array of RRSets
		for (int i = 0; i < *rrset_count; ++i) {

dbg_packet_exec_detail(
			char *name = knot_dname_to_str((*rrsets)[i]->owner);
			dbg_packet_detail("Comparing to RRSet: owner: %s, "
			                  "type: %s\n", name,
			                  knot_rrtype_to_string(
			                       (*rrsets)[i]->type));
			free(name);
);

			if (knot_rrset_compare((*rrsets)[i], rrset,
			                         KNOT_RRSET_COMPARE_HEADER)) {
				/*! \todo Test this!!! */
				// no duplicate checking here, the packet should
				// look exactly as it came from wire
				int rc = knot_rrset_merge(
				    (void **)((*rrsets) + i), (void **)&rrset);
				if (rc != KNOT_EOK) {
					return rc;
				}
				return 1;
			}
		}
	}

	(*rrsets)[*rrset_count] = rrset;
	++(*rrset_count);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_packet_parse_rrs(const uint8_t *wire, size_t *pos,
                                 size_t size, uint16_t rr_count,
                                 uint16_t *parsed_rrs,
                                 const knot_rrset_t ***rrsets,
                                 short *rrset_count, short *max_rrsets,
                                 short default_rrsets,
                                 knot_packet_t *packet)
{
	assert(pos != NULL);
	assert(wire != NULL);
	assert(rrsets != NULL);
	assert(rrset_count != NULL);
	assert(max_rrsets != NULL);
	assert(packet != NULL);

	dbg_packet("Parsing RRSets starting on position: %zu\n", *pos);

	/*
	 * The RRs from one RRSet may be scattered in the current section.
	 * We must parse all RRs separately and try to add them to already
	 * parsed RRSets.
	 */
	int err = KNOT_EOK;
	knot_rrset_t *rrset = NULL;

	/* Start parsing from the first RR not parsed. */
	for (int i = *parsed_rrs; i < rr_count; ++i) {
		rrset = knot_packet_parse_rr(wire, pos, size);
		if (rrset == NULL) {
			dbg_packet("Failed to parse RR!\n");
			err = KNOT_EMALF;
			break;
		}

		++(*parsed_rrs);

		err = knot_packet_add_rrset(rrset, rrsets, rrset_count,
		                            max_rrsets, default_rrsets, packet,
		                            KNOT_PACKET_DUPL_MERGE);
		if (err < 0) {
			break;
		} else if (err > 0) {	// merged
			dbg_packet_detail("RRSet merged, freeing.\n");
			knot_rrset_deep_free(&rrset, 1, 0, 0);  // TODO: ok??
			continue;
		}

		err = knot_packet_add_tmp_rrset(packet, rrset);
		if (err != KNOT_EOK) {
			// remove the last RRSet from the list of RRSets
			// - just decrement the count
			--(*rrset_count);
			knot_rrset_deep_free(&rrset, 1, 1, 1);
			break;
		}

		if (knot_rrset_type(rrset) == KNOT_RRTYPE_TSIG) {
			// if there is some TSIG already, treat as malformed
			if (knot_packet_tsig(packet) != NULL) {
				err = KNOT_EMALF;
				break;
			}

			// First check the format of the TSIG RR
			if (!tsig_rdata_is_ok(rrset)) {
				err = KNOT_EMALF;
				break;
			}

			// store the TSIG into the packet
			knot_packet_set_tsig(packet, rrset);
		}
	}

	return (err < 0) ? err : KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Deallocates all space which was allocated additionally to the
 *        pre-allocated space of the response structure.
 *
 * \param resp Response structure that holds pointers to the allocated space.
 */
static void knot_packet_free_allocated_space(knot_packet_t *pkt)
{
	dbg_packet_verb("Freeing additional space in packet.\n");
	if (pkt->prealloc_type == KNOT_PACKET_PREALLOC_NONE) {
		dbg_packet_detail("Freeing QNAME.\n");
		knot_dname_release(pkt->question.qname);
	}

	if (pkt->max_an_rrsets > DEFAULT_RRSET_COUNT(ANCOUNT, pkt)) {
		free(pkt->answer);
	}
	if (pkt->max_ns_rrsets > DEFAULT_RRSET_COUNT(NSCOUNT, pkt)) {
		free(pkt->authority);
	}
	if (pkt->max_ar_rrsets > DEFAULT_RRSET_COUNT(ARCOUNT, pkt)) {
		free(pkt->additional);
	}

	if (pkt->compression.max > pkt->compression.default_count) {
		free(pkt->compression.dnames);
		free(pkt->compression.offsets);
		free(pkt->compression.to_free);
	}

	if (pkt->wildcard_nodes.max > pkt->wildcard_nodes.default_count) {
		free(pkt->wildcard_nodes.nodes);
		free(pkt->wildcard_nodes.snames);
	}

	if (pkt->tmp_rrsets_max > DEFAULT_RRSET_COUNT(TMP_RRSETS, pkt)) {
		free(pkt->tmp_rrsets);
	}
}

/*----------------------------------------------------------------------------*/

static int knot_packet_parse_rr_sections(knot_packet_t *packet,
                                           size_t *pos)
{
	assert(packet != NULL);
	assert(packet->wireformat != NULL);
	assert(packet->size > 0);
	assert(pos != NULL);
	assert(*pos > 0);

	int err;

	assert(packet->tsig_rr == NULL);

	dbg_packet_verb("Parsing Answer RRs...\n");
	if ((err = knot_packet_parse_rrs(packet->wireformat, pos,
	   packet->size, packet->header.ancount, &packet->parsed_an,
	   &packet->answer, &packet->an_rrsets, &packet->max_an_rrsets,
	   DEFAULT_RRSET_COUNT(ANCOUNT, packet), packet)) != KNOT_EOK) {
		return err;
	}

	if (packet->tsig_rr != NULL) {
		dbg_packet("TSIG in Answer section.\n");
		return KNOT_EMALF;
	}

	dbg_packet_verb("Parsing Authority RRs...\n");
	if ((err = knot_packet_parse_rrs(packet->wireformat, pos,
	   packet->size, packet->header.nscount, &packet->parsed_ns,
	   &packet->authority, &packet->ns_rrsets, &packet->max_ns_rrsets,
	   DEFAULT_RRSET_COUNT(NSCOUNT, packet), packet)) != KNOT_EOK) {
		return err;
	}

	if (packet->tsig_rr != NULL) {
		dbg_packet("TSIG in Authority section.\n");
		return KNOT_EMALF;
	}

	dbg_packet_verb("Parsing Additional RRs...\n");
	if ((err = knot_packet_parse_rrs(packet->wireformat, pos,
	   packet->size, packet->header.arcount, &packet->parsed_ar,
	   &packet->additional, &packet->ar_rrsets, &packet->max_ar_rrsets,
	   DEFAULT_RRSET_COUNT(ARCOUNT, packet), packet)) != KNOT_EOK) {
		return err;
	}

	// If TSIG is not the last record
	if (packet->tsig_rr != NULL
	    && packet->ar_rrsets[packet->additional - 1] != packet->tsig_rr) {
		dbg_packet("TSIG in Additonal section but not last.\n");
		return KNOT_EMALF;
	}

	dbg_packet_verb("Trying to find OPT RR in the packet.\n");

	for (int i = 0; i < packet->ar_rrsets; ++i) {
		assert(packet->additional[i] != NULL);
		if (knot_rrset_type(packet->additional[i]) == KNOT_RRTYPE_OPT) {
			dbg_packet_detail("Found OPT RR, filling.\n");
			err = knot_edns_new_from_rr(&packet->opt_rr,
			                              packet->additional[i]);
			if (err != KNOT_EOK) {
				return err;
			}
			break;
		}
	}

	packet->parsed = *pos;

	if (*pos < packet->size) {
		// If there is some trailing garbage, treat the packet as
		// malformed
		dbg_packet_verb("Packet: %zu bytes of trailing garbage "
		                "in packet.\n", packet->size - (*pos));
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_packet_t *knot_packet_new(knot_packet_prealloc_type_t prealloc)
{
	knot_packet_t *pkt;
	void (*init_pointers)(knot_packet_t *pkt) = NULL;
	size_t size = 0;

	switch (prealloc) {
	case KNOT_PACKET_PREALLOC_NONE:
		size = sizeof(knot_packet_t);
		break;
	case KNOT_PACKET_PREALLOC_QUERY:
		size = PREALLOC_QUERY;
		init_pointers = knot_packet_init_pointers_query;
		break;
	case KNOT_PACKET_PREALLOC_RESPONSE:
		size = PREALLOC_RESPONSE;
		init_pointers = knot_packet_init_pointers_response;
		break;
	}

	pkt = (knot_packet_t *)malloc(size);
	CHECK_ALLOC_LOG(pkt, NULL);
	memset(pkt, 0, size);
	if (init_pointers != NULL) {
		init_pointers(pkt);
	}

	pkt->prealloc_type = prealloc;

	// set EDNS version to not supported
	pkt->opt_rr.version = EDNS_NOT_SUPPORTED;

	return pkt;
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_from_wire(knot_packet_t *packet,
                                  const uint8_t *wireformat, size_t size,
                                  int question_only)
{
	if (packet == NULL || wireformat == NULL) {
		return KNOT_EINVAL;
	}

	int err;

	// save the wireformat in the packet
	// TODO: can we just save the pointer, or we have to copy the data??
	assert(packet->wireformat == NULL);
	packet->wireformat = (uint8_t*)wireformat;
	packet->size = size;
	packet->free_wireformat = 0;

	if (size < 2) {
		return KNOT_EMALF;
	}

	size_t pos = 0;

	dbg_packet_verb("Parsing wire format of packet (size %zu).\nHeader\n",
	                size);
	if ((err = knot_packet_parse_header(wireformat, &pos, size,
	                                      &packet->header)) != KNOT_EOK) {
		return err;
	}

	packet->parsed = pos;

	dbg_packet_verb("Question (prealloc type: %d)...\n",
	                packet->prealloc_type);

	if (packet->header.qdcount > 1) {
		dbg_packet("QDCOUNT larger than 1, FORMERR.\n");
		return KNOT_EMALF;
	}

	if (packet->header.qdcount == 1) {
		if ((err = knot_packet_parse_question(wireformat, &pos, size,
		             &packet->question, packet->prealloc_type 
		                                == KNOT_PACKET_PREALLOC_NONE)
		     ) != KNOT_EOK) {
			return err;
		}
		packet->parsed = pos;
	}

dbg_packet_exec_detail(
	knot_packet_dump(packet);
);

	if (question_only) {
		return KNOT_EOK;
	}

	/*! \todo Replace by call to parse_rest()? */
	err = knot_packet_parse_rest(packet);

dbg_packet_exec_detail(
	knot_packet_dump(packet);
);

	return err;
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_rest(knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	if (packet->header.ancount == packet->parsed_an
	    && packet->header.nscount == packet->parsed_ns
	    && packet->header.arcount == packet->parsed_ar
	    && packet->parsed == packet->size) {
		return KNOT_EOK;
	}

	// If there is less data then required, the next function will find out.
	// If there is more data than required, it also returns EMALF.
	
	size_t pos = packet->parsed;

	/*! \todo If we already parsed some part of the packet, it is not ok
	 *        to begin parsing from the Answer section.
	 */
	return knot_packet_parse_rr_sections(packet, &pos);
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_next_rr_answer(knot_packet_t *packet,
                                       knot_rrset_t **rr)
{
	if (packet == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	*rr = NULL;

	if (packet->parsed >= packet->size) {
		assert(packet->an_rrsets <= packet->header.ancount);
		if (packet->parsed_an != packet->header.ancount) {
			dbg_packet("Parsed less RRs than expected.\n");
			return KNOT_EMALF;
		} else {
			dbg_packet_detail("Whole packet parsed\n");
			return KNOT_EOK;
		}
	}

	if (packet->parsed_an == packet->header.ancount) {
		assert(packet->parsed < packet->size);
		//dbg_packet("Trailing garbage, ignoring...\n");
		// there may be other data in the packet 
		// (authority or additional).
		return KNOT_EOK;
	}

	size_t pos = packet->parsed;

	dbg_packet_verb("Parsing next Answer RR (pos: %zu)...\n", pos);
	*rr = knot_packet_parse_rr(packet->wireformat, &pos, packet->size);
	if (*rr == NULL) {
		dbg_packet_verb("Failed to parse RR!\n");
		return KNOT_EMALF;
	}
	
	dbg_packet_detail("Parsed. Pos: %zu.\n", pos);

	packet->parsed = pos;
	// increment the number of answer RRSets, though there are no saved
	// in the packet; it is OK, because packet->answer is NULL
	++packet->an_rrsets;
	++packet->parsed_an;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_next_rr_additional(knot_packet_t *packet,
                                         knot_rrset_t **rr)
{
	/*! \todo Implement. */
	if (packet == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	*rr = NULL;

	if (packet->parsed >= packet->size) {
		assert(packet->ar_rrsets <= packet->header.arcount);
		if (packet->parsed_ar != packet->header.arcount) {
			dbg_packet("Parsed less RRs than expected.\n");
			return KNOT_EMALF;
		} else {
			dbg_packet_detail("Whole packet parsed\n");
			return KNOT_EOK;
		}
	}

	if (packet->parsed_ar == packet->header.arcount) {
		assert(packet->parsed < packet->size);
		dbg_packet_verb("Trailing garbage, treating as malformed...\n");
		return KNOT_EMALF;
	}

	size_t pos = packet->parsed;

	dbg_packet_verb("Parsing next Additional RR (pos: %zu)...\n", pos);
	*rr = knot_packet_parse_rr(packet->wireformat, &pos, packet->size);
	if (*rr == NULL) {
		dbg_packet_verb("Failed to parse RR!\n");
		return KNOT_EMALF;
	}
	
	dbg_packet_detail("Parsed. Pos: %zu.\n", pos);

	packet->parsed = pos;
	// increment the number of answer RRSets, though there are no saved
	// in the packet; it is OK, because packet->answer is NULL
	++packet->ar_rrsets;
	++packet->parsed_ar;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

size_t knot_packet_size(const knot_packet_t *packet)
{
	return packet->size;
}

/*----------------------------------------------------------------------------*/

size_t knot_packet_question_size(const knot_packet_t *packet)
{
	return (KNOT_WIRE_HEADER_SIZE + 4
	        + knot_dname_size(packet->question.qname));
}

/*----------------------------------------------------------------------------*/

size_t knot_packet_parsed(const knot_packet_t *packet)
{
	return packet->parsed;
}

/*----------------------------------------------------------------------------*/

int knot_packet_set_max_size(knot_packet_t *packet, int max_size)
{
	if (packet == NULL || max_size <= 0) {
		return KNOT_EINVAL;
	}

	if (packet->max_size < max_size) {
		// reallocate space for the wire format (and copy anything
		// that might have been there before
		uint8_t *wire_new = (uint8_t *)malloc(max_size);
		if (wire_new == NULL) {
			return KNOT_ENOMEM;
		}

		uint8_t *wire_old = packet->wireformat;

		memcpy(wire_new, packet->wireformat, packet->max_size);
		packet->wireformat = wire_new;

		if (packet->max_size > 0 && packet->free_wireformat) {
			free(wire_old);
		}

		packet->free_wireformat = 1;
	}

	// set max size
	packet->max_size = max_size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_id(const knot_packet_t *packet)
{
	assert(packet != NULL);
	return packet->header.id;
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_id(knot_packet_t *packet, uint16_t id)
{
	if (packet == NULL) {
		return;
	}

	packet->header.id = id;
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_random_id(knot_packet_t *packet)
{
	if (packet == NULL) {
		return;
	}

	packet->header.id = knot_random_id();
}

/*----------------------------------------------------------------------------*/

uint8_t knot_packet_opcode(const knot_packet_t *packet)
{
	assert(packet != NULL);
	return knot_wire_flags_get_opcode(packet->header.flags1);
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_packet_qname(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return NULL;
	}

	return packet->question.qname;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_qtype(const knot_packet_t *packet)
{
	assert(packet != NULL);
	return packet->question.qtype;
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_qtype(knot_packet_t *packet, knot_rr_type_t qtype)
{
	assert(packet != NULL);
	packet->question.qtype = qtype;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_qclass(const knot_packet_t *packet)
{
	assert(packet != NULL);
	return packet->question.qclass;
}

/*----------------------------------------------------------------------------*/

int knot_packet_is_query(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return (knot_wire_flags_get_qr(packet->header.flags1) == 0);
}

/*----------------------------------------------------------------------------*/

const knot_packet_t *knot_packet_query(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return NULL;
	}

	return packet->query;
}

/*----------------------------------------------------------------------------*/

int knot_packet_rcode(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}
	
	return knot_wire_flags_get_rcode(packet->header.flags2);
}

/*----------------------------------------------------------------------------*/

int knot_packet_tc(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}
	
	return knot_wire_flags_get_tc(packet->header.flags1);
}

/*----------------------------------------------------------------------------*/

int knot_packet_qdcount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->header.qdcount;
}

/*----------------------------------------------------------------------------*/

int knot_packet_ancount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->header.ancount;
}

/*----------------------------------------------------------------------------*/

int knot_packet_nscount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->header.nscount;
}

/*----------------------------------------------------------------------------*/

int knot_packet_arcount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->header.arcount;
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_tsig_size(knot_packet_t *packet, size_t tsig_size)
{
	packet->tsig_size = tsig_size;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_tsig(const knot_packet_t *packet)
{
	return packet->tsig_rr;
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_tsig(knot_packet_t *packet, const knot_rrset_t *tsig_rr)
{
	packet->tsig_rr = (knot_rrset_t *)tsig_rr;
}

/*----------------------------------------------------------------------------*/

short knot_packet_answer_rrset_count(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->an_rrsets;
}

/*----------------------------------------------------------------------------*/

short knot_packet_authority_rrset_count(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->ns_rrsets;
}

/*----------------------------------------------------------------------------*/

short knot_packet_additional_rrset_count(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return packet->ar_rrsets;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_answer_rrset(
	const knot_packet_t *packet, short pos)
{
	if (packet == NULL || pos > packet->an_rrsets) {
		return NULL;
	}

	return packet->answer[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_authority_rrset(
	knot_packet_t *packet, short pos)
{
	if (packet == NULL || pos > packet->ns_rrsets) {
		return NULL;
	}

	return packet->authority[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_additional_rrset(
    knot_packet_t *packet, short pos)
{
	if (packet == NULL || pos > packet->ar_rrsets) {
		return NULL;
	}

	return packet->additional[pos];
}

/*----------------------------------------------------------------------------*/

int knot_packet_contains(const knot_packet_t *packet,
                           const knot_rrset_t *rrset,
                           knot_rrset_compare_type_t cmp)
{
	if (packet == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < packet->an_rrsets; ++i) {
		if (knot_rrset_compare(packet->answer[i], rrset, cmp)) {
			return 1;
		}
	}

	for (int i = 0; i < packet->ns_rrsets; ++i) {
		if (knot_rrset_compare(packet->authority[i], rrset, cmp)) {
			return 1;
		}
	}

	for (int i = 0; i < packet->ar_rrsets; ++i) {
		if (knot_rrset_compare(packet->additional[i], rrset, cmp)) {
			return 1;
		}
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int knot_packet_add_tmp_rrset(knot_packet_t *packet,
                                knot_rrset_t *tmp_rrset)
{
	if (packet == NULL || tmp_rrset == NULL) {
		return KNOT_EINVAL;
	}

	if (packet->tmp_rrsets_count == packet->tmp_rrsets_max
	    && knot_packet_realloc_rrsets(&packet->tmp_rrsets,
			&packet->tmp_rrsets_max,
			DEFAULT_RRSET_COUNT(TMP_RRSETS, packet),
			STEP_TMP_RRSETS) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	packet->tmp_rrsets[packet->tmp_rrsets_count++] = tmp_rrset;
	dbg_packet_detail("Current tmp RRSets count: %d, max count: %d\n",
	                  packet->tmp_rrsets_count, packet->tmp_rrsets_max);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Frees all temporary RRSets stored in the response structure.
 *
 * \param resp Response structure to free the temporary RRSets from.
 */
void knot_packet_free_tmp_rrsets(knot_packet_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	for (int i = 0; i < pkt->tmp_rrsets_count; ++i) {
dbg_packet_exec(
		char *name = knot_dname_to_str(
			(((knot_rrset_t **)(pkt->tmp_rrsets))[i])->owner);
		dbg_packet_verb("Freeing tmp RRSet on ptr: %p (ptr to ptr:"
		       " %p, type: %s, owner: %s)\n",
		       (((knot_rrset_t **)(pkt->tmp_rrsets))[i]),
		       &(((knot_rrset_t **)(pkt->tmp_rrsets))[i]),
		       knot_rrtype_to_string(
		            (((knot_rrset_t **)(pkt->tmp_rrsets))[i])->type),
		       name);
		free(name);
);
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		knot_rrset_deep_free(
			&(((knot_rrset_t **)(pkt->tmp_rrsets))[i]), 1, 1, 1);
	}
}

/*----------------------------------------------------------------------------*/

void knot_packet_header_to_wire(const knot_header_t *header,
                                  uint8_t **pos, size_t *size)
{
	if (header == NULL || pos == NULL || *pos == NULL || size == NULL) {
		return;
	}

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

int knot_packet_question_to_wire(knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	if (packet->size > KNOT_WIRE_HEADER_SIZE) {
		return KNOT_ERROR;
	}

	// TODO: get rid of the numeric constants
	size_t qsize = 4 + knot_dname_size(packet->question.qname);
	if (qsize > packet->max_size - KNOT_WIRE_HEADER_SIZE) {
		return KNOT_ESPACE;
	}

	// create the wireformat of Question
	uint8_t *pos = packet->wireformat + KNOT_WIRE_HEADER_SIZE;
	memcpy(pos, knot_dname_name(packet->question.qname),
	       knot_dname_size(packet->question.qname));

	pos += knot_dname_size(packet->question.qname);
	knot_wire_write_u16(pos, packet->question.qtype);
	pos += 2;
	knot_wire_write_u16(pos, packet->question.qclass);

	packet->size += knot_dname_size(packet->question.qname) + 4;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_packet_edns_to_wire(knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	packet->size += knot_edns_to_wire(&packet->opt_rr,
	                                  packet->wireformat + packet->size,
	                                  packet->max_size - packet->size);

	packet->header.arcount += 1;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_packet_to_wire(knot_packet_t *packet,
                          uint8_t **wire, size_t *wire_size)
{
	if (packet == NULL || wire == NULL || wire_size == NULL
	    || *wire != NULL) {
		return KNOT_EINVAL;
	}

	assert(packet->size <= packet->max_size);

	// if there are no additional RRSets, add EDNS OPT RR
	if (packet->header.arcount == 0
	    && packet->opt_rr.version != EDNS_NOT_SUPPORTED) {
	    knot_packet_edns_to_wire(packet);
	}

	// set QDCOUNT (in response it is already set, in query it is needed)
	knot_wire_set_qdcount(packet->wireformat, packet->header.qdcount);
	// set ANCOUNT to the packet
	knot_wire_set_ancount(packet->wireformat, packet->header.ancount);
	// set NSCOUNT to the packet
	knot_wire_set_nscount(packet->wireformat, packet->header.nscount);
	// set ARCOUNT to the packet
	knot_wire_set_arcount(packet->wireformat, packet->header.arcount);

	//assert(response->size == size);
	*wire = packet->wireformat;
	*wire_size = packet->size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const uint8_t *knot_packet_wireformat(const knot_packet_t *packet)
{
	return packet->wireformat;
}

/*----------------------------------------------------------------------------*/

void knot_packet_free(knot_packet_t **packet)
{
	if (packet == NULL || *packet == NULL) {
		return;
	}

	// free temporary domain names
	dbg_packet("Freeing tmp RRSets...\n");
	knot_packet_free_tmp_rrsets(*packet);

	dbg_packet("Freeing copied dnames for compression...\n");
	for (int i = 0; i < (*packet)->compression.count; ++i) {
		if ((*packet)->compression.to_free[i]) {
			knot_dname_release(
			      (knot_dname_t *)(*packet)->compression.dnames[i]);
		}
	}

	/*! \note The above code will free the domain names pointed to by
	 *        the list of wildcard nodes. It should not matter, however.
	 */

	// check if some additional space was allocated for the packet
	dbg_packet("Freeing additional allocated space...\n");
	knot_packet_free_allocated_space(*packet);

	// free the space for wireformat
	if ((*packet)->wireformat != NULL && (*packet)->free_wireformat) {
		free((*packet)->wireformat);
	}

	// free EDNS options
	knot_edns_free_options(&(*packet)->opt_rr);

	dbg_packet("Freeing packet structure\n");
	free(*packet);
	*packet = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef KNOT_PACKET_DEBUG
static void knot_packet_dump_rrsets(const knot_rrset_t **rrsets,
                                      int count)
{
	assert((rrsets != NULL && *rrsets != NULL) || count < 1);

	for (int i = 0; i < count; ++i) {
		knot_rrset_dump(rrsets[i], 0);
	}
}
#endif
/*----------------------------------------------------------------------------*/

void knot_packet_dump(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return;
	}

#ifdef KNOT_PACKET_DEBUG
	dbg_packet("DNS packet:\n-----------------------------\n");

	dbg_packet("\nHeader:\n");
	dbg_packet("  ID: %u\n", packet->header.id);
	dbg_packet("  FLAGS: %s %s %s %s %s %s %s\n",
	       knot_wire_flags_get_qr(packet->header.flags1) ? "qr" : "",
	       knot_wire_flags_get_aa(packet->header.flags1) ? "aa" : "",
	       knot_wire_flags_get_tc(packet->header.flags1) ? "tc" : "",
	       knot_wire_flags_get_rd(packet->header.flags1) ? "rd" : "",
	       knot_wire_flags_get_ra(packet->header.flags2) ? "ra" : "",
	       knot_wire_flags_get_ad(packet->header.flags2) ? "ad" : "",
	       knot_wire_flags_get_cd(packet->header.flags2) ? "cd" : "");
	dbg_packet("  QDCOUNT: %u\n", packet->header.qdcount);
	dbg_packet("  ANCOUNT: %u\n", packet->header.ancount);
	dbg_packet("  NSCOUNT: %u\n", packet->header.nscount);
	dbg_packet("  ARCOUNT: %u\n", packet->header.arcount);

	if (knot_packet_qdcount(packet) > 0) {
		dbg_packet("\nQuestion:\n");
		char *qname = knot_dname_to_str(packet->question.qname);
		dbg_packet("  QNAME: %s\n", qname);
		free(qname);
		dbg_packet("  QTYPE: %u (%s)\n", packet->question.qtype,
		       knot_rrtype_to_string(packet->question.qtype));
		dbg_packet("  QCLASS: %u (%s)\n", packet->question.qclass,
		       knot_rrclass_to_string(packet->question.qclass));
	}

	dbg_packet("\nAnswer RRSets:\n");
	knot_packet_dump_rrsets(packet->answer, packet->an_rrsets);
	dbg_packet("\nAuthority RRSets:\n");
	knot_packet_dump_rrsets(packet->authority, packet->ns_rrsets);
	dbg_packet("\nAdditional RRSets:\n");
	knot_packet_dump_rrsets(packet->additional, packet->ar_rrsets);

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	dbg_packet("\nEDNS:\n");
	dbg_packet("  Version: %u\n", packet->opt_rr.version);
	dbg_packet("  Payload: %u\n", packet->opt_rr.payload);
	dbg_packet("  Extended RCODE: %u\n",
	                      packet->opt_rr.ext_rcode);

	dbg_packet("\nPacket size: %zu\n", packet->size);
	dbg_packet("\n-----------------------------\n");
#endif
}

