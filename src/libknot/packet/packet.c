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
#include <stdlib.h>

#include "libknot/packet/packet.h"
#include "libknot/util/debug.h"
#include "libknot/common.h"
#include "libknot/dnssec/random.h"
#include "common/descriptor.h"
#include "libknot/util/wire.h"
#include "libknot/tsig.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/*!
 * \brief Processes DNS Question entry from the wire format.
 */
static int knot_packet_parse_question(knot_packet_t *pkt)
{
	assert(pkt != NULL);

	dbg_packet("Parsing Question starting on position %zu.\n", pkt->parsed);

	/* Process question. */
	int len = knot_dname_wire_check(pkt->wireformat + pkt->parsed,
	                                pkt->wireformat + pkt->size,
	                                NULL /* No compression allowed. */);
	if (len <= 0)
		return KNOT_EMALF;

	uint16_t question_size = len + 2 * sizeof(uint16_t);
	if (pkt->parsed + question_size > pkt->size) {
		return KNOT_EMALF;
	}

	pkt->parsed += question_size; /* Class + Type */
	pkt->qname_size = len;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocate space for RRSets.
 *
 * \param rrsets Space for RRSets.
 * \param max_count Size of the space available for the RRSets.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_packet_realloc_rrsets(const knot_rrset_t ***rrsets,
                                      short *max_count,
                                      mm_ctx_t *mm)
{
	short new_max_count = *max_count + RRSET_ALLOC_STEP;
	const knot_rrset_t **new_rrsets = mm->alloc(mm->ctx,
		new_max_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, KNOT_ENOMEM);
	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(knot_rrset_t *));

	mm->free(*rrsets);
	*rrsets = new_rrsets;
	*max_count = new_max_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_packet_parse_rdata(knot_rrset_t *rr, const uint8_t *wire,
                                   size_t *pos, size_t total_size,
                                   size_t rdlength)
{
	if (!rr || !wire || !pos) {
		return KNOT_EINVAL;
	}



	/*! \todo As I'm revising it, seems highly inefficient to me.
	 *        We just need to skim through the packet,
	 *        check if it is in valid format and store pointers to various
	 *        parts in rdata instead of copying memory blocks and
	 *        parsing domain names (with additional allocation) and then
	 *        use use the wireformat for lookup again. Compression could
	 *        be handled in-situ without additional memory allocs...
	 */

	int ret = knot_rrset_rdata_from_wire_one(rr, wire, pos, total_size,
	                                         rdlength);
	if (ret != KNOT_EOK) {
		dbg_packet("packet: parse_rdata: Failed to parse RDATA (%s).\n",
		           knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static knot_rrset_t *knot_packet_parse_rr(const uint8_t *wire, size_t *pos,
                                          size_t size)
{
	dbg_packet("Parsing RR from position: %zu, total size: %zu\n",
	           *pos, size);

	knot_dname_t *owner = knot_dname_parse(wire, pos, size);
	dbg_packet_detail("Created owner: %p, actual position: %zu\n", owner,
	                  *pos);
	if (owner == NULL) {
		return NULL;
	}
	knot_dname_to_lower(owner);

dbg_packet_exec_verb(
	char *name = knot_dname_to_str(owner);
	dbg_packet_verb("Parsed name: %s\n", name);
	free(name);
);

	if (size - *pos < KNOT_RR_HEADER_SIZE) {
		dbg_packet("Malformed RR: Not enough data to parse RR"
		           " header.\n");
		knot_dname_free(&owner);
		return NULL;
	}

	dbg_packet_detail("Reading type from position %zu\n", *pos);

	uint16_t type = knot_wire_read_u16(wire + *pos);
	uint16_t rclass = knot_wire_read_u16(wire + *pos + 2);
	uint32_t ttl = knot_wire_read_u32(wire + *pos + 4);

	knot_rrset_t *rrset = knot_rrset_new(owner, type, rclass, ttl);
	if (rrset == NULL) {
		knot_dname_free(&owner);
		return NULL;
	}

	uint16_t rdlength = knot_wire_read_u16(wire + *pos + 8);

	dbg_packet_detail("Read RR header: type %u, class %u, ttl %u, "
	                    "rdlength %u\n", rrset->type, rrset->rclass,
	                    rrset->ttl, rdlength);

	*pos += KNOT_RR_HEADER_SIZE;

	if (size - *pos < rdlength) {
		dbg_packet("Malformed RR: Not enough data to parse RR"
		           " RDATA (size: %zu, position: %zu).\n", size, *pos);
		knot_rrset_deep_free(&rrset, 1);
		return NULL;
	}

	rrset->rrsigs = NULL;

	// parse RDATA
	/*! \todo Merge with add_rdata_to_rr in zcompile, should be a rrset func
	 *        probably. */
	int ret = knot_packet_parse_rdata(rrset, wire, pos, size, rdlength);
	if (ret != KNOT_EOK) {
		dbg_packet("Malformed RR: Could not parse RDATA.\n");
		knot_rrset_deep_free(&rrset, 1);
		return NULL;
	}

	return rrset;
}

/*----------------------------------------------------------------------------*/

static int knot_packet_add_rrset(knot_rrset_t *rrset,
                                 const knot_rrset_t ***rrsets,
                                 short *rrset_count,
                                 short *max_rrsets,
                                 knot_packet_t *packet,
                                 knot_packet_flag_t flags)
{
	assert(rrset != NULL);
	assert(rrsets != NULL);
	assert(rrset_count != NULL);
	assert(max_rrsets != NULL);

dbg_packet_exec_verb(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_packet_verb("packet_add_rrset(), owner: %s, type: %u\n",
	                name, rrset->type);
	free(name);
);

	if (*rrset_count == *max_rrsets
	    && knot_packet_realloc_rrsets(rrsets, max_rrsets,
	                                  &packet->mm) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if ((flags & KNOT_PACKET_DUPL_SKIP) &&
	    knot_packet_contains(packet, rrset, KNOT_RRSET_COMPARE_PTR)) {
		return 2;
	}

	// Try to merge rdata to rrset if flag NO_MERGE isn't set.
    if ((flags & KNOT_PACKET_DUPL_NO_MERGE) == 0) {
		// try to find the RRSet in this array of RRSets
		for (int i = 0; i < *rrset_count; ++i) {
dbg_packet_exec_detail(
			char *name = knot_dname_to_str((*rrsets)[i]->owner);
			dbg_packet_detail("Comparing to RRSet: owner: %s, "
			                  "type: %u\n", name,
			                  (*rrsets)[i]->type);
			free(name);
);

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
                                 knot_packet_t *packet,
                                 knot_packet_flag_t flags)
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
		                            max_rrsets, packet, flags);
		if (err < 0) {
			break;
		} else if (err == 1) {	// merged, shallow data copy
			dbg_packet_detail("RRSet merged, freeing.\n");
			knot_rrset_deep_free(&rrset, 1);
			continue;
		} else if (err == 2) { // skipped
			knot_rrset_deep_free(&rrset, 1);
			continue;
		}

		err = knot_packet_add_tmp_rrset(packet, rrset);
		if (err != KNOT_EOK) {
			// remove the last RRSet from the list of RRSets
			// - just decrement the count
			--(*rrset_count);
			knot_rrset_deep_free(&rrset, 1);
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

	pkt->mm.free(pkt->qname);
	pkt->mm.free(pkt->answer);
	pkt->mm.free(pkt->authority);
	pkt->mm.free(pkt->additional);
	pkt->mm.free(pkt->wildcard_nodes.nodes);
	pkt->mm.free(pkt->wildcard_nodes.snames);
	pkt->mm.free(pkt->tmp_rrsets);
}

/*----------------------------------------------------------------------------*/

static int knot_packet_parse_rr_sections(knot_packet_t *packet, size_t *pos,
                                         knot_packet_flag_t flags)
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
	   packet->size, knot_wire_get_ancount(packet->wireformat), &packet->parsed_an,
	   &packet->answer, &packet->an_rrsets, &packet->max_an_rrsets,
	                                 packet, flags)) != KNOT_EOK) {
		return err;
	}

	if (packet->tsig_rr != NULL) {
		dbg_packet("TSIG in Answer section.\n");
		return KNOT_EMALF;
	}

	dbg_packet_verb("Parsing Authority RRs...\n");
	if ((err = knot_packet_parse_rrs(packet->wireformat, pos,
	   packet->size, knot_wire_get_nscount(packet->wireformat), &packet->parsed_ns,
	   &packet->authority, &packet->ns_rrsets, &packet->max_ns_rrsets,
	   packet, flags)) != KNOT_EOK) {
		return err;
	}

	if (packet->tsig_rr != NULL) {
		dbg_packet("TSIG in Authority section.\n");
		return KNOT_EMALF;
	}

	dbg_packet_verb("Parsing Additional RRs...\n");
	if ((err = knot_packet_parse_rrs(packet->wireformat, pos,
	   packet->size, knot_wire_get_arcount(packet->wireformat), &packet->parsed_ar,
	   &packet->additional, &packet->ar_rrsets, &packet->max_ar_rrsets,
	   packet, flags)) != KNOT_EOK) {
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

knot_packet_t *knot_packet_new()
{
	mm_ctx_t mm;
	mm_ctx_init(&mm);
	return knot_packet_new_mm(&mm);
}

knot_packet_t *knot_packet_new_mm(mm_ctx_t *mm)
{
	knot_packet_t *pkt = NULL;

	pkt = (knot_packet_t *)mm->alloc(mm->ctx, sizeof(knot_packet_t));
	CHECK_ALLOC_LOG(pkt, NULL);
	memset(pkt, 0, sizeof(knot_packet_t));
	memcpy(&pkt->mm, mm, sizeof(mm_ctx_t));

	// set EDNS version to not supported
	pkt->opt_rr.version = EDNS_NOT_SUPPORTED;

	return pkt;
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_from_wire(knot_packet_t *packet,
                                const uint8_t *wireformat, size_t size,
                                int question_only, knot_packet_flag_t flags)
{
	if (packet == NULL || wireformat == NULL || size < KNOT_WIRE_HEADER_SIZE)
		return KNOT_EINVAL;


	int err = KNOT_EOK;

	assert(packet->wireformat == NULL);
	packet->wireformat = (uint8_t*)wireformat;
	packet->size = size;
	packet->flags &= ~KNOT_PF_FREE_WIRE;
	packet->parsed = KNOT_WIRE_HEADER_SIZE;

	uint16_t qdcount = knot_wire_get_qdcount(packet->wireformat);
	if (qdcount == 1) {
		if ((err = knot_packet_parse_question(packet)) != KNOT_EOK)
			return err;
	} else if (qdcount > 1) {
		dbg_packet("QDCOUNT > 1, FORMERR.\n");
		return KNOT_EMALF;
	}

dbg_packet_exec_detail(
	knot_packet_dump(packet);
);

	if (question_only) {
		return KNOT_EOK;
	}

	err = knot_packet_parse_rest(packet, flags);

dbg_packet_exec_detail(
	knot_packet_dump(packet);
);

	return err;
}

/*----------------------------------------------------------------------------*/

int knot_packet_parse_rest(knot_packet_t *packet, knot_packet_flag_t flags)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	if (knot_wire_get_ancount(packet->wireformat) == packet->parsed_an
	    && knot_wire_get_nscount(packet->wireformat) == packet->parsed_ns
	    && knot_wire_get_arcount(packet->wireformat) == packet->parsed_ar
	    && packet->parsed == packet->size) {
		return KNOT_EOK;
	}

	// If there is less data then required, the next function will find out.
	// If there is more data than required, it also returns EMALF.

	size_t pos = packet->parsed;

	/*! \todo If we already parsed some part of the packet, it is not ok
	 *        to begin parsing from the Answer section.
	 */
	return knot_packet_parse_rr_sections(packet, &pos, flags);
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
		assert(packet->an_rrsets <= knot_wire_get_ancount(packet->wireformat));
		if (packet->parsed_an != knot_wire_get_ancount(packet->wireformat)) {
			dbg_packet("Parsed less RRs than expected.\n");
			return KNOT_EMALF;
		} else {
			dbg_packet_detail("Whole packet parsed\n");
			return KNOT_EOK;
		}
	}

	if (packet->parsed_an == knot_wire_get_ancount(packet->wireformat)) {
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
		assert(packet->ar_rrsets <= knot_wire_get_arcount(packet->wireformat));
		if (packet->parsed_ar != knot_wire_get_arcount(packet->wireformat)) {
			dbg_packet("Parsed less RRs than expected.\n");
			return KNOT_EMALF;
		} else {
			dbg_packet_detail("Whole packet parsed\n");
			return KNOT_EOK;
		}
	}

	if (packet->parsed_ar == knot_wire_get_arcount(packet->wireformat)) {
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

size_t knot_packet_max_size(const knot_packet_t *packet)
{
	return packet->max_size;
}

/*----------------------------------------------------------------------------*/

size_t knot_packet_question_size(const knot_packet_t *packet)
{
	if (packet->qname_size > 0) {
		return KNOT_WIRE_HEADER_SIZE + packet->qname_size + 2 * sizeof(uint16_t);
	} else {
		return KNOT_WIRE_HEADER_SIZE;
	}
}

/*----------------------------------------------------------------------------*/

size_t knot_packet_parsed(const knot_packet_t *packet)
{
	return packet->parsed;
}

/*----------------------------------------------------------------------------*/

int knot_packet_set_size(knot_packet_t *packet, int size)
{
	if (packet == NULL || size > packet->max_size)
		return KNOT_EINVAL;

	return packet->size = size;
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
		uint8_t *wire_new = packet->mm.alloc(packet->mm.ctx, max_size);
		if (wire_new == NULL) {
			return KNOT_ENOMEM;
		}

		if (packet->max_size > 0) {
			memcpy(wire_new, packet->wireformat, packet->max_size);
			if (packet->flags & KNOT_PF_FREE_WIRE)
				packet->mm.free(packet->wireformat);
		}

		packet->wireformat = wire_new;
		packet->max_size = max_size;
		packet->flags |= KNOT_PF_FREE_WIRE;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_id(const knot_packet_t *packet)
{
	assert(packet != NULL);
	return knot_wire_get_id(packet->wireformat);
}

/*----------------------------------------------------------------------------*/

void knot_packet_set_random_id(knot_packet_t *packet)
{
	if (packet == NULL) {
		return;
	}

	knot_wire_set_id(packet->wireformat, knot_random_uint16_t());
}

/*----------------------------------------------------------------------------*/

uint8_t knot_packet_opcode(const knot_packet_t *packet)
{
	assert(packet != NULL);
	uint8_t flags = knot_wire_get_flags1(packet->wireformat);
	return knot_wire_flags_get_opcode(flags);
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_packet_qname(const knot_packet_t *packet)
{
	if (packet == NULL || packet->qname_size == 0) {
		return NULL;
	}
	if (packet->qname == NULL) {
		/* Copy dname for lowercase conversion. */
		knot_dname_t **qname = &((knot_packet_t *)packet)->qname;
		*qname = packet->mm.alloc(packet->mm.ctx, packet->qname_size);
		if (*qname == NULL) {
			return NULL;
		}
		memcpy(*qname, packet->wireformat + KNOT_WIRE_HEADER_SIZE, packet->qname_size);
		knot_dname_to_lower(*qname);
	}

	return packet->qname;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_qtype(const knot_packet_t *packet)
{
	assert(packet != NULL);
	unsigned off = KNOT_WIRE_HEADER_SIZE + packet->qname_size;
	return knot_wire_read_u16(packet->wireformat + off);
}

/*----------------------------------------------------------------------------*/

uint16_t knot_packet_qclass(const knot_packet_t *packet)
{
	assert(packet != NULL);
	unsigned off = KNOT_WIRE_HEADER_SIZE + packet->qname_size + sizeof(uint16_t);
	return knot_wire_read_u16(packet->wireformat + off);
}

/*----------------------------------------------------------------------------*/

int knot_packet_is_query(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t flags = knot_wire_get_flags1(packet->wireformat);
	return (knot_wire_flags_get_qr(flags) == 0);
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

	uint8_t flags = knot_wire_get_flags2(packet->wireformat);
	return knot_wire_flags_get_rcode(flags);
}

/*----------------------------------------------------------------------------*/

int knot_packet_tc(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t flags = knot_wire_get_flags1(packet->wireformat);
	return knot_wire_flags_get_tc(flags);
}

/*----------------------------------------------------------------------------*/

int knot_packet_qdcount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return knot_wire_get_qdcount(packet->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_packet_ancount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return knot_wire_get_ancount(packet->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_packet_nscount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return knot_wire_get_nscount(packet->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_packet_arcount(const knot_packet_t *packet)
{
	if (packet == NULL) {
		return KNOT_EINVAL;
	}

	return knot_wire_get_arcount(packet->wireformat);
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
	if (packet == NULL || pos >= packet->an_rrsets) {
		return NULL;
	}

	return packet->answer[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_authority_rrset(
	const knot_packet_t *packet, short pos)
{
	if (packet == NULL || pos >= packet->ns_rrsets) {
		return NULL;
	}

	return packet->authority[pos];
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_packet_additional_rrset(
    const knot_packet_t *packet, short pos)
{
	if (packet == NULL || pos >= packet->ar_rrsets) {
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
		if (knot_rrset_equal(packet->answer[i], rrset, cmp)) {
			return 1;
		}
	}

	for (int i = 0; i < packet->ns_rrsets; ++i) {
		if (knot_rrset_equal(packet->authority[i], rrset, cmp)) {
			return 1;
		}
	}

	for (int i = 0; i < packet->ar_rrsets; ++i) {
		if (knot_rrset_equal(packet->additional[i], rrset, cmp)) {
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

	if (packet->tmp_rrsets_count == packet->tmp_rrsets_max) {
		int ret = knot_packet_realloc_rrsets(&packet->tmp_rrsets,
		                                     &packet->tmp_rrsets_max,
		                                     &packet->mm);
		if (ret != KNOT_EOK)
			return ret;
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
		       " %p, type: %u, owner: %s)\n",
		       (((knot_rrset_t **)(pkt->tmp_rrsets))[i]),
		       &(((knot_rrset_t **)(pkt->tmp_rrsets))[i]),
		       (((knot_rrset_t **)(pkt->tmp_rrsets))[i])->type,
		       name);
		free(name);
);
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		// TODO sort out freeing, this WILL leak.
		knot_rrset_deep_free(
			&(((knot_rrset_t **)(pkt->tmp_rrsets))[i]), 1);
	}
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

	knot_wire_add_arcount(packet->wireformat, 1);

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
	if (knot_wire_get_arcount(packet->wireformat) == 0
	    && packet->opt_rr.version != EDNS_NOT_SUPPORTED) {
	    knot_packet_edns_to_wire(packet);
	}

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

	// check if some additional space was allocated for the packet
	dbg_packet("Freeing additional allocated space...\n");
	knot_packet_free_allocated_space(*packet);

	// free the space for wireformat
	if ((*packet)->flags & KNOT_PF_FREE_WIRE)
		(*packet)->mm.free((*packet)->wireformat);

	// free EDNS options
	knot_edns_free_options(&(*packet)->opt_rr);

	dbg_packet("Freeing packet structure\n");
	(*packet)->mm.free(*packet);
	*packet = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef KNOT_PACKET_DEBUG
static void knot_packet_dump_rrsets(const knot_rrset_t **rrsets,
                                      int count)
{
	assert((rrsets != NULL && *rrsets != NULL) || count < 1);

	for (int i = 0; i < count; ++i) {
		knot_rrset_dump(rrsets[i]);
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
	dbg_packet("  ID: %u\n", knot_wire_get_id(packet->wireformat));
	dbg_packet("  FLAGS: %s %s %s %s %s %s %s\n",
	       knot_wire_get_qr(packet->wireformat) ? "qr" : "",
	       knot_wire_get_aa(packet->wireformat) ? "aa" : "",
	       knot_wire_get_tc(packet->wireformat) ? "tc" : "",
	       knot_wire_get_rd(packet->wireformat) ? "rd" : "",
	       knot_wire_get_ra(packet->wireformat) ? "ra" : "",
	       knot_wire_get_ad(packet->wireformat) ? "ad" : "",
	       knot_wire_get_cd(packet->wireformat) ? "cd" : "");
	dbg_packet("  RCODE: %u\n", knot_wire_get_rcode(packet->wireformat));
	dbg_packet("  OPCODE: %u\n", knot_wire_get_opcode(packet->wireformat));
	dbg_packet("  QDCOUNT: %u\n", knot_wire_get_qdcount(packet->wireformat));
	dbg_packet("  ANCOUNT: %u\n", knot_wire_get_ancount(packet->wireformat));
	dbg_packet("  NSCOUNT: %u\n", knot_wire_get_nscount(packet->wireformat));
	dbg_packet("  ARCOUNT: %u\n", knot_wire_get_arcount(packet->wireformat));

	if (knot_packet_qdcount(packet) > 0 && knot_packet_qname(packet)) {
		dbg_packet("\nQuestion:\n");
		char *qname = knot_dname_to_str(knot_packet_qname(packet));
		dbg_packet("  QNAME: %s\n", qname);
		free(qname);
		dbg_packet("  QTYPE: %u\n", knot_packet_qtype(packet));
		dbg_packet("  QCLASS: %u\n", knot_packet_qclass(packet));
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

static int knot_packet_free_section(const knot_rrset_t **s, short count) {
	/*! \todo The API is really incompatible here. */
	for (short i = 0; i < count; ++i)
		knot_rrset_deep_free((knot_rrset_t **)s + i, 1);
	return count;
}

int knot_packet_free_rrsets(knot_packet_t *packet)
{
	int ret = 0;
	ret += knot_packet_free_section(packet->answer, packet->an_rrsets);
	ret += knot_packet_free_section(packet->authority, packet->ns_rrsets);
	ret += knot_packet_free_section(packet->additional, packet->ar_rrsets);
	return ret;
}
