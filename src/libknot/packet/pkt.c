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
#include <stdlib.h>
#include <stdbool.h>

#include "libknot/packet/pkt.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/wire_ctx.h"

/*! \brief Packet RR array growth step. */
#define NEXT_RR_ALIGN 16
#define NEXT_RR_COUNT(count) (((count) / NEXT_RR_ALIGN + 1) * NEXT_RR_ALIGN)

/*! \brief Scan packet for RRSet existence. */
static bool pkt_contains(const knot_pkt_t *packet,
			 const knot_rrset_t *rrset)
{
	assert(packet);
	assert(rrset);

	for (int i = 0; i < packet->rrset_count; ++i) {
		const uint16_t type = packet->rr[i].type;
		const uint8_t *data = packet->rr[i].rrs.data;
		if (type == rrset->type && data == rrset->rrs.data) {
			return true;
		}
	}

	return false;
}

/*! \brief Free all RRSets and reset RRSet count. */
static void pkt_free_data(knot_pkt_t *pkt)
{
	assert(pkt);

	/* Free RRSets if applicable. */
	for (uint16_t i = 0; i < pkt->rrset_count; ++i) {
		if (pkt->rr_info[i].flags & KNOT_PF_FREE) {
			knot_rrset_clear(&pkt->rr[i], &pkt->mm);
		}
	}

	/* Reset RR count. */
	pkt->rrset_count = 0;

	/* Reset special types. */
	pkt->opt_rr = NULL;
	pkt->tsig_rr = NULL;

	/* Reset TSIG wire reference. */
	pkt->tsig_wire.pos = NULL;
	pkt->tsig_wire.len = 0;
}

/*! \brief Allocate new wireformat of given length. */
static int pkt_wire_alloc(knot_pkt_t *pkt, uint16_t len)
{
	assert(pkt);
	assert(len >= KNOT_WIRE_HEADER_SIZE);

	pkt->wire = pkt->mm.alloc(pkt->mm.ctx, len);
	if (pkt->wire == NULL) {
		return KNOT_ENOMEM;
	}

	pkt->flags |= KNOT_PF_FREE;
	pkt->max_size = len;
	knot_pkt_clear(pkt);
	return KNOT_EOK;
}

/*! \brief Set packet wireformat to an existing memory. */
static void pkt_wire_set(knot_pkt_t *pkt, void *wire, uint16_t len)
{
	assert(pkt);

	pkt->wire = wire;
	pkt->size = pkt->max_size = len;
	pkt->parsed = 0;
}

/*! \brief Calculate remaining size in the packet. */
static uint16_t pkt_remaining(knot_pkt_t *pkt)
{
	assert(pkt);

	return pkt->max_size - pkt->size - pkt->reserved;
}

/*! \brief Return RR count for given section (from wire xxCOUNT in header). */
static uint16_t pkt_rr_wirecount(knot_pkt_t *pkt, knot_section_t section_id)
{
	assert(pkt);
	switch (section_id) {
	case KNOT_ANSWER:     return knot_wire_get_ancount(pkt->wire);
	case KNOT_AUTHORITY:  return knot_wire_get_nscount(pkt->wire);
	case KNOT_ADDITIONAL: return knot_wire_get_arcount(pkt->wire);
	default: assert(0);   return 0;
	}
}

/*! \brief Update RR count for given section (wire xxCOUNT in header). */
static void pkt_rr_wirecount_add(knot_pkt_t *pkt, knot_section_t section_id,
                                 int16_t val)
{
	assert(pkt);
	switch (section_id) {
	case KNOT_ANSWER:     knot_wire_add_ancount(pkt->wire, val); break;
	case KNOT_AUTHORITY:  knot_wire_add_nscount(pkt->wire, val); break;
	case KNOT_ADDITIONAL: knot_wire_add_arcount(pkt->wire, val); break;
	}
}

/*! \brief Reserve enough space in the RR arrays. */
static int pkt_rr_array_alloc(knot_pkt_t *pkt, uint16_t count)
{
	/* Enough space. */
	if (pkt->rrset_allocd >= count) {
		return KNOT_EOK;
	}

	/* Allocate rr_info and rr fields to next size. */
	size_t next_size = NEXT_RR_COUNT(count);
	knot_rrinfo_t *rr_info = mm_alloc(&pkt->mm, sizeof(knot_rrinfo_t) * next_size);
	if (rr_info == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t *rr = mm_alloc(&pkt->mm, sizeof(knot_rrset_t) * next_size);
	if (rr == NULL) {
		mm_free(&pkt->mm, rr_info);
		return KNOT_ENOMEM;
	}

	/* Copy the old data. */
	memcpy(rr_info, pkt->rr_info, pkt->rrset_allocd * sizeof(knot_rrinfo_t));
	memcpy(rr, pkt->rr, pkt->rrset_allocd * sizeof(knot_rrset_t));

	/* Reassign and free old data. */
	mm_free(&pkt->mm, pkt->rr);
	mm_free(&pkt->mm, pkt->rr_info);
	pkt->rr = rr;
	pkt->rr_info = rr_info;
	pkt->rrset_allocd = next_size;

	return KNOT_EOK;
}

/*! \brief Clear the packet and switch wireformat pointers (possibly allocate new). */
static int pkt_init(knot_pkt_t *pkt, void *wire, uint16_t len, mm_ctx_t *mm)
{
	assert(pkt);

	memset(pkt, 0, sizeof(knot_pkt_t));

	/* No data to free, set memory context. */
	memcpy(&pkt->mm, mm, sizeof(mm_ctx_t));

	/* Initialize wire. */
	int ret = KNOT_EOK;
	if (wire == NULL) {
		ret = pkt_wire_alloc(pkt, len);
	} else {
		pkt_wire_set(pkt, wire, len);
	}

	return ret;
}

/*! \brief Reset packet parse state. */
static int pkt_reset_sections(knot_pkt_t *pkt)
{
	pkt->parsed  = 0;
	pkt->current = KNOT_ANSWER;
	memset(pkt->sections, 0, sizeof(pkt->sections));
	return knot_pkt_begin(pkt, KNOT_ANSWER);
}

/*! \brief Clear packet payload and free allocated data. */
static void pkt_clear_payload(knot_pkt_t *pkt)
{
	assert(pkt);

	/* Keep question. */
	pkt->parsed = 0;
	pkt->size = KNOT_WIRE_HEADER_SIZE + knot_pkt_question_size(pkt);
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);

	/* Free RRSets if applicable. */
	pkt_free_data(pkt);

	/* Reset sections. */
	pkt_reset_sections(pkt);
}

/*! \brief Allocate new packet using memory context. */
static knot_pkt_t *pkt_new_mm(void *wire, uint16_t len, mm_ctx_t *mm)
{
	assert(mm);

	knot_pkt_t *pkt = mm_alloc(mm, sizeof(knot_pkt_t));
	if (pkt == NULL) {
		return NULL;
	}

	if (pkt_init(pkt, wire, len, mm) != KNOT_EOK) {
		mm_free(mm, pkt);
		return NULL;
	}

	return pkt;
}

_public_
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, mm_ctx_t *mm)
{
	/* Default memory allocator if NULL. */
	mm_ctx_t _mm;
	if (mm == NULL) {
		mm_ctx_init(&_mm);
		mm = &_mm;
	}

	return pkt_new_mm(wire, len, mm);
}

static int append_tsig(knot_pkt_t *dst, const knot_pkt_t *src)
{
	/* Check if a wire TSIG is available. */
	if (src->tsig_wire.pos != NULL) {
		if (dst->max_size < src->size + src->tsig_wire.len) {
			return KNOT_ESPACE;
		}
		memcpy(dst->wire + dst->size, src->tsig_wire.pos,
		       src->tsig_wire.len);
		dst->size += src->tsig_wire.len;

		/* Increment arcount. */
		knot_wire_set_arcount(dst->wire,
		                      knot_wire_get_arcount(dst->wire) + 1);
	} else {
		return knot_tsig_append(dst->wire, &dst->size, dst->max_size,
		                        src->tsig_rr);
	}

	return KNOT_EOK;
}

_public_
int knot_pkt_copy(knot_pkt_t *dst, const knot_pkt_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	if (dst->max_size < src->size) {
		return KNOT_ESPACE;
	}
	memcpy(dst->wire, src->wire, src->size);
	dst->size = src->size;

	/* Append TSIG record. */
	if (src->tsig_rr) {
		int ret = append_tsig(dst, src);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Invalidate arrays. */
	dst->rr = NULL;
	dst->rr_info = NULL;
	dst->rrset_count = 0;
	dst->rrset_allocd = 0;

	/* @note This could be done more effectively if needed. */
	return knot_pkt_parse(dst, 0);
}

_public_
int knot_pkt_init_response(knot_pkt_t *pkt, const knot_pkt_t *query)
{
	if (pkt == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	/* Header + question size. */
	size_t base_size = KNOT_WIRE_HEADER_SIZE + knot_pkt_question_size(query);
	if (base_size > pkt->max_size) {
		return KNOT_ESPACE;
	}

	pkt->size = base_size;
	pkt->qname_size = query->qname_size;
	memcpy(pkt->wire, query->wire, base_size);

	/* Update size and flags. */
	knot_wire_set_qr(pkt->wire);
	knot_wire_clear_tc(pkt->wire);
	knot_wire_clear_ad(pkt->wire);
	knot_wire_clear_ra(pkt->wire);
	knot_wire_clear_aa(pkt->wire);

	/* Clear payload. */
	pkt_clear_payload(pkt);
	return KNOT_EOK;
}

_public_
void knot_pkt_clear(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	/* Clear payload. */
	pkt_clear_payload(pkt);

	/* Reset to header size. */
	pkt->size = KNOT_WIRE_HEADER_SIZE;
	memset(pkt->wire, 0, pkt->size);
}

_public_
void knot_pkt_free(knot_pkt_t **pkt)
{
	if (pkt == NULL || *pkt == NULL) {
		return;
	}

	/* Free temporary RRSets. */
	pkt_free_data(*pkt);

	/* Free RR/RR info arrays. */
	mm_free(&(*pkt)->mm, (*pkt)->rr);
	mm_free(&(*pkt)->mm, (*pkt)->rr_info);

	// free the space for wireformat
	if ((*pkt)->flags & KNOT_PF_FREE) {
		(*pkt)->mm.free((*pkt)->wire);
	}

	(*pkt)->mm.free(*pkt);
	*pkt = NULL;
}

_public_
int knot_pkt_reserve(knot_pkt_t *pkt, uint16_t size)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Reserve extra space (if possible). */
	if (pkt_remaining(pkt) >= size) {
		pkt->reserved += size;
		return KNOT_EOK;
	} else {
		return KNOT_ERANGE;
	}
}

_public_
int knot_pkt_reclaim(knot_pkt_t *pkt, uint16_t size)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	if (pkt->reserved >= size) {
		pkt->reserved -= size;
		return KNOT_EOK;
	} else {
		return KNOT_ERANGE;
	}

}

_public_
uint16_t knot_pkt_type(const knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return 0;
	}

	bool is_query = (knot_wire_get_qr(pkt->wire) == 0);
	uint16_t ret = KNOT_QUERY_INVALID;
	uint8_t opcode = knot_wire_get_opcode(pkt->wire);
	uint8_t query_type = knot_pkt_qtype(pkt);

	switch (opcode) {
	case KNOT_OPCODE_QUERY:
		switch (query_type) {
		case 0 /* RESERVED */: /* INVALID */ break;
		case KNOT_RRTYPE_AXFR: ret = KNOT_QUERY_AXFR; break;
		case KNOT_RRTYPE_IXFR: ret = KNOT_QUERY_IXFR; break;
		default:               ret = KNOT_QUERY_NORMAL; break;
		}
		break;
	case KNOT_OPCODE_NOTIFY: ret = KNOT_QUERY_NOTIFY; break;
	case KNOT_OPCODE_UPDATE: ret = KNOT_QUERY_UPDATE; break;
	default: break;
	}

	if (!is_query) {
		ret = ret|KNOT_RESPONSE;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
_public_
uint16_t knot_pkt_question_size(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	return pkt->qname_size + 2 * sizeof(uint16_t);
}

/*----------------------------------------------------------------------------*/
_public_
const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return NULL;
	}

	return pkt->wire + KNOT_WIRE_HEADER_SIZE;
}

/*----------------------------------------------------------------------------*/
_public_
uint16_t knot_pkt_qtype(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size;
	return wire_read_u16(pkt->wire + off);
}

/*----------------------------------------------------------------------------*/
_public_
uint16_t knot_pkt_qclass(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size + sizeof(uint16_t);
	return wire_read_u16(pkt->wire + off);
}

_public_
int knot_pkt_begin(knot_pkt_t *pkt, knot_section_t section_id)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Cannot step to lower section. */
	assert(section_id >= pkt->current);
	pkt->current = section_id;

	/* Remember watermark. */
	pkt->sections[section_id].pkt = pkt;
	pkt->sections[section_id].pos = pkt->rrset_count;

	return KNOT_EOK;
}

_public_
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	if (pkt == NULL || qname == NULL) {
		return KNOT_EINVAL;
	}

	assert(pkt->size == KNOT_WIRE_HEADER_SIZE);
	assert(pkt->rrset_count == 0);

	/* Copy name wireformat. */
	wire_ctx_t wire = wire_ctx_init(pkt->wire, pkt->max_size);
	wire_ctx_set_offset(&wire, KNOT_WIRE_HEADER_SIZE);

	int qname_len = knot_dname_to_wire(wire.position,
	                                   qname, wire_ctx_available(&wire));
	if (qname_len < 0) {
		return qname_len;
	}
	wire_ctx_skip(&wire, qname_len);

	/* Copy QTYPE & QCLASS */
	wire_ctx_write_u16(&wire, qtype);
	wire_ctx_write_u16(&wire, qclass);

	/* Check errors. */
	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	/* Update question count and sizes. */
	knot_wire_set_qdcount(pkt->wire, 1);
	pkt->size = wire_ctx_offset(&wire);
	pkt->qname_size = qname_len;

	/* Start writing ANSWER. */
	return knot_pkt_begin(pkt, KNOT_ANSWER);
}

_public_
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr,
                 uint16_t flags)
{
	if (pkt == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Reserve memory for RR descriptors. */
	int ret = pkt_rr_array_alloc(pkt, pkt->rrset_count + 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrinfo_t *rrinfo = &pkt->rr_info[pkt->rrset_count];
	memset(rrinfo, 0, sizeof(knot_rrinfo_t));
	rrinfo->pos = pkt->size;
	rrinfo->flags = flags;
	rrinfo->compress_ptr[0] = compr_hint;
	memcpy(pkt->rr + pkt->rrset_count, rr, sizeof(knot_rrset_t));

	/* Check for double insertion. */
	if ((flags & KNOT_PF_CHECKDUP) &&
	    pkt_contains(pkt, rr)) {
		return KNOT_EOK; /*! \todo return rather a number of added RRs */
	}

	uint8_t *pos = pkt->wire + pkt->size;
	size_t maxlen = pkt_remaining(pkt);

	/* Create compression context. */
	knot_compr_t compr;
	compr.wire = pkt->wire;
	compr.rrinfo = rrinfo;
	compr.suffix.pos = KNOT_WIRE_HEADER_SIZE;
	compr.suffix.labels = knot_dname_labels(compr.wire + compr.suffix.pos,
	                                        compr.wire);

	/* Write RRSet to wireformat. */
	ret = knot_rrset_to_wire(rr, pos, maxlen, &compr);
	if (ret < 0) {
		/* Truncate packet if required. */
		if (ret == KNOT_ESPACE && !(flags & KNOT_PF_NOTRUNC)) {
				knot_wire_set_tc(pkt->wire);
		}
		return ret;
	}

	size_t len = ret;
	uint16_t rr_added = rr->rrs.rr_count;

	/* Keep reference to special types. */
	if (rr->type == KNOT_RRTYPE_OPT) {
		pkt->opt_rr = &pkt->rr[pkt->rrset_count];
	}

	if (rr_added > 0) {
		pkt->rrset_count += 1;
		pkt->sections[pkt->current].count += 1;
		pkt->size += len;
		pkt_rr_wirecount_add(pkt, pkt->current, rr_added);
	}

	return KNOT_EOK;
}

_public_
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt,
                                          knot_section_t section_id)
{
	if (pkt == NULL) {
		return NULL;
	}

	return &pkt->sections[section_id];
}

_public_
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section, uint16_t i)
{
	if (section == NULL) {
		return NULL;
	}

	return section->pkt->rr + section->pos + i;
}

_public_
uint16_t knot_pkt_rr_offset(const knot_pktsection_t *section, uint16_t i)
{
	if (section == NULL || section->pkt == NULL) {
		return -1;
	}

	return section->pkt->rr_info[section->pos + i].pos;
}

_public_
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Reset parse state. */
	pkt_reset_sections(pkt);

	int ret = knot_pkt_parse_question(pkt);
	if (ret == KNOT_EOK) {
		ret = knot_pkt_parse_payload(pkt, flags);
	}

	return ret;
}

_public_
int knot_pkt_parse_question(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Check at least header size. */
	if (pkt->size < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_EMALF;
	}

	/* We have at least some DNS header. */
	pkt->parsed = KNOT_WIRE_HEADER_SIZE;

	/* Check QD count. */
	uint16_t qd = knot_wire_get_qdcount(pkt->wire);
	if (qd > 1) {
		return KNOT_EMALF;
	}

	/* No question. */
	if (qd == 0) {
		pkt->qname_size = 0;
		return KNOT_EOK;
	}

	/* Process question. */
	int len = knot_dname_wire_check(pkt->wire + pkt->parsed,
	                                pkt->wire + pkt->size,
	                                NULL /* No compression in QNAME. */);
	if (len <= 0) {
		return KNOT_EMALF;
	}

	/* Check QCLASS/QTYPE size. */
	uint16_t question_size = len + 2 * sizeof(uint16_t); /* QCLASS + QTYPE */
	if (pkt->parsed + question_size > pkt->size) {
		return KNOT_EMALF;
	}

	pkt->parsed += question_size;
	pkt->qname_size = len;

	return KNOT_EOK;
}

/* \note Private for check_rr_constraints(). */
#define CHECK_AR_CONSTRAINTS(pkt, rr, var, check_func) \
	if ((pkt)->current != KNOT_ADDITIONAL) { \
		return KNOT_EMALF; \
	} else if ((pkt)->var != NULL) { \
		return KNOT_EMALF; \
	} else if (!check_func(rr)) { \
		return KNOT_EMALF; \
	} else { \
		(pkt)->var = rr; \
	}

/*! \brief Check constraints (position, uniqueness, validity) for special types
 *         (TSIG, OPT).
 */
static int check_rr_constraints(knot_pkt_t *pkt, knot_rrset_t *rr, size_t rr_size,
                                unsigned flags)
{
	/* Check RR constraints. */
	switch(rr->type) {
	case KNOT_RRTYPE_TSIG:
		CHECK_AR_CONSTRAINTS(pkt, rr, tsig_rr, knot_tsig_rdata_is_ok);

		/* Strip TSIG RR from wireformat and decrease ARCOUNT. */
		if (!(flags & KNOT_PF_KEEPWIRE)) {
			pkt->parsed -= rr_size;
			pkt->size -= rr_size;
			pkt->tsig_wire.pos = pkt->wire + pkt->parsed;
			pkt->tsig_wire.len = rr_size;
			knot_wire_set_id(pkt->wire, knot_tsig_rdata_orig_id(rr));
			knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);
		}
		break;
	case KNOT_RRTYPE_OPT:
		CHECK_AR_CONSTRAINTS(pkt, rr, opt_rr, knot_edns_check_record);
		break;
	default:
		break;
	}

	return KNOT_EOK;
}

#undef CHECK_AR_RECORD

_public_
int knot_pkt_parse_rr(knot_pkt_t *pkt, unsigned flags)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	if (pkt->parsed >= pkt->size) {
		return KNOT_EFEWDATA;
	}

	/* Reserve memory for RR descriptors. */
	int ret = pkt_rr_array_alloc(pkt, pkt->rrset_count + 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Initialize RR info. */
	memset(&pkt->rr_info[pkt->rrset_count], 0, sizeof(knot_rrinfo_t));
	pkt->rr_info[pkt->rrset_count].pos = pkt->parsed;
	pkt->rr_info[pkt->rrset_count].flags = KNOT_PF_FREE;

	/* Parse wire format. */
	size_t rr_size = pkt->parsed;
	knot_rrset_t *rr = &pkt->rr[pkt->rrset_count];
	ret = knot_rrset_rr_from_wire(pkt->wire, &pkt->parsed, pkt->size,
	                              &pkt->mm, rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Calculate parsed RR size from before/after parsing. */
	rr_size = (pkt->parsed - rr_size);

	/* Update packet RRSet count. */
	++pkt->rrset_count;
	++pkt->sections[pkt->current].count;

	/* Check special RRs (OPT and TSIG). */
	return check_rr_constraints(pkt, rr, rr_size, flags);
}

_public_
int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	uint16_t rr_parsed = 0;
	uint16_t rr_count = pkt_rr_wirecount(pkt, pkt->current);

	/* Parse all RRs belonging to the section. */
	for (rr_parsed = 0; rr_parsed < rr_count; ++rr_parsed) {
		ret = knot_pkt_parse_rr(pkt, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

_public_
int knot_pkt_parse_payload(knot_pkt_t *pkt, unsigned flags)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	assert(pkt->wire != NULL);
	assert(pkt->size > 0);

	/* Reserve memory in advance to avoid resizing. */
	size_t rr_count = knot_wire_get_ancount(pkt->wire) +
	                  knot_wire_get_nscount(pkt->wire) +
	                  knot_wire_get_arcount(pkt->wire);

	if (rr_count > pkt->size / KNOT_WIRE_RR_MIN_SIZE) {
		return KNOT_EMALF;
	}

	int ret = pkt_rr_array_alloc(pkt, rr_count);
	if (ret != KNOT_EOK) {
		return ret;
	}

	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		ret = knot_pkt_begin(pkt, i);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = knot_pkt_parse_section(pkt, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* TSIG must be last record of AR if present. */
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	if (pkt->tsig_rr != NULL) {
		const knot_rrset_t *last_rr = knot_pkt_rr(ar, ar->count - 1);
		if (ar->count > 0 && pkt->tsig_rr->rrs.data != last_rr->rrs.data) {
			return KNOT_EMALF;
		}
	}

	/* Check for trailing garbage. */
	if (pkt->parsed < pkt->size) {
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

_public_
uint16_t knot_pkt_get_ext_rcode(const knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return 0;
	}

	uint8_t rcode = knot_wire_get_rcode(pkt->wire);

	if (pkt->opt_rr) {
		uint8_t opt_rcode = knot_edns_get_ext_rcode(pkt->opt_rr);
		return knot_edns_whole_rcode(opt_rcode, rcode);
	} else {
		return rcode;
	}
}
