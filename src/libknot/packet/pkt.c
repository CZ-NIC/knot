/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/attribute.h"
#include "libknot/packet/pkt.h"
#include "libknot/codes.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/wire.h"
#include "contrib/mempattern.h"
#include "contrib/wire_ctx.h"

/*! \brief Packet RR array growth step. */
#define NEXT_RR_ALIGN 16
#define NEXT_RR_COUNT(count) (((count) / NEXT_RR_ALIGN + 1) * NEXT_RR_ALIGN)

/*! \brief Scan packet for RRSet existence. */
static bool pkt_contains(const knot_pkt_t *packet, const knot_rrset_t *rrset)
{
	assert(packet);
	assert(rrset);

	for (int i = 0; i < packet->rrset_count; ++i) {
		const uint16_t type = packet->rr[i].type;
		const knot_rdata_t *data = packet->rr[i].rrs.data;
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
	pkt->rrset_count = 0;

	/* Free EDNS option positions. */
	mm_free(&pkt->mm, pkt->edns_opts);
	pkt->edns_opts = 0;
}

/*! \brief Allocate new wireformat of given length. */
static int pkt_wire_alloc(knot_pkt_t *pkt, uint16_t len)
{
	assert(pkt);

	if (len < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_ERANGE;
	}

	pkt->wire = mm_alloc(&pkt->mm, len);
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

static void compr_clear(knot_compr_t *compr)
{
	compr->rrinfo = NULL;
	compr->suffix.pos = 0;
	compr->suffix.labels = 0;
}

static void compr_init(knot_compr_t *compr, uint8_t *wire)
{
	compr_clear(compr);
	compr->wire = wire;
}

/*! \brief Clear the packet and switch wireformat pointers (possibly allocate new). */
static int pkt_init(knot_pkt_t *pkt, void *wire, uint16_t len, knot_mm_t *mm)
{
	assert(pkt);

	memset(pkt, 0, sizeof(knot_pkt_t));

	/* No data to free, set memory context. */
	memcpy(&pkt->mm, mm, sizeof(knot_mm_t));

	/* Initialize wire. */
	int ret = KNOT_EOK;
	if (wire == NULL) {
		ret = pkt_wire_alloc(pkt, len);
	} else {
		pkt_wire_set(pkt, wire, len);
	}

	/* Initialize compression context. */
	compr_init(&pkt->compr, pkt->wire);

	return ret;
}

/*! \brief Reset packet parse state. */
static void sections_reset(knot_pkt_t *pkt)
{
	pkt->current = KNOT_ANSWER;
	memset(pkt->sections, 0, sizeof(pkt->sections));
	(void)knot_pkt_begin(pkt, KNOT_ANSWER);
}

/*! \brief Allocate new packet using memory context. */
static knot_pkt_t *pkt_new_mm(void *wire, uint16_t len, knot_mm_t *mm)
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
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, knot_mm_t *mm)
{
	/* Default memory allocator if NULL. */
	knot_mm_t _mm;
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

static void payload_clear(knot_pkt_t *pkt)
{
	assert(pkt);

	/* Keep question. */
	pkt->parsed = 0;
	pkt->reserved = 0;

	/* Free RRSets if applicable. */
	pkt_free_data(pkt);

	/* Reset sections. */
	sections_reset(pkt);

	/* Reset special types. */
	pkt->opt_rr = NULL;
	pkt->tsig_rr = NULL;

	/* Reset TSIG wire reference. */
	pkt->tsig_wire.pos = NULL;
	pkt->tsig_wire.len = 0;
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
	memcpy(pkt->wire, query->wire, base_size);

	pkt->qname_size = query->qname_size;
	if (query->qname_size == 0) {
		/* Reset question count if malformed. */
		knot_wire_set_qdcount(pkt->wire, 0);
	}

	/* Update flags and section counters. */
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);

	knot_wire_set_qr(pkt->wire);
	knot_wire_clear_tc(pkt->wire);
	knot_wire_clear_ad(pkt->wire);
	knot_wire_clear_ra(pkt->wire);
	knot_wire_clear_aa(pkt->wire);
	knot_wire_clear_z(pkt->wire);

	/* Clear payload. */
	payload_clear(pkt);

	return KNOT_EOK;
}

_public_
void knot_pkt_clear(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	/* Reset to header size. */
	pkt->size = KNOT_WIRE_HEADER_SIZE;
	memset(pkt->wire, 0, pkt->size);

	/* Clear payload. */
	payload_clear(pkt);

	/* Clear compression context. */
	compr_clear(&pkt->compr);
}

_public_
void knot_pkt_free(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	/* Free temporary RRSets. */
	pkt_free_data(pkt);

	/* Free RR/RR info arrays. */
	mm_free(&pkt->mm, pkt->rr);
	mm_free(&pkt->mm, pkt->rr_info);

	/* Free the space for wireformat. */
	if (pkt->flags & KNOT_PF_FREE) {
		mm_free(&pkt->mm, pkt->wire);
	}

	mm_free(&pkt->mm, pkt);
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
int knot_pkt_begin(knot_pkt_t *pkt, knot_section_t section_id)
{
	if (pkt == NULL || section_id < pkt->current) {
		return KNOT_EINVAL;
	}

	/* Remember watermark but not on repeated calls. */
	pkt->sections[section_id].pkt = pkt;
	if (section_id > pkt->current) {
		pkt->sections[section_id].pos = pkt->rrset_count;
	}

	pkt->current = section_id;

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
int knot_pkt_put_rotate(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr,
                        uint16_t rotate, uint16_t flags)
{
	if (pkt == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Reserve memory for RR descriptors. */
	int ret = pkt_rr_array_alloc(pkt, pkt->rrset_count + 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check for double insertion. */
	if ((flags & KNOT_PF_CHECKDUP) && pkt_contains(pkt, rr)) {
		return KNOT_EOK;
	}

	knot_rrinfo_t *rrinfo = &pkt->rr_info[pkt->rrset_count];
	memset(rrinfo, 0, sizeof(knot_rrinfo_t));
	rrinfo->pos = pkt->size;
	rrinfo->flags = flags;
	rrinfo->compress_ptr[0] = compr_hint;
	memcpy(pkt->rr + pkt->rrset_count, rr, sizeof(knot_rrset_t));

	/* Disable compression if no QNAME is available. */
	knot_compr_t *compr = NULL;
	if (knot_pkt_qname(pkt) != NULL) {
		/* Initialize compression context if it did not happen yet. */
		pkt->compr.rrinfo = rrinfo;
		if (pkt->compr.suffix.pos == 0) {
			pkt->compr.suffix.pos = KNOT_WIRE_HEADER_SIZE;
			pkt->compr.suffix.labels =
				knot_dname_labels(pkt->compr.wire + pkt->compr.suffix.pos,
				                  pkt->compr.wire);
		}

		compr = &pkt->compr;
	}

	uint8_t *pos = pkt->wire + pkt->size;
	size_t maxlen = pkt_remaining(pkt);

	/* Write RRSet to wireformat. */
	ret = knot_rrset_to_wire_rotate(rr, pos, maxlen, rotate, compr);
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
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Reset parse state. */
	sections_reset(pkt);

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

/*! \brief Check constraints (position, uniqueness, validity) for special types
 *         (TSIG, OPT).
 */
static int check_rr_constraints(knot_pkt_t *pkt, knot_rrset_t *rr, size_t rr_size,
                                unsigned flags)
{
	switch (rr->type) {
	case KNOT_RRTYPE_TSIG:
		if (pkt->current != KNOT_ADDITIONAL || pkt->tsig_rr != NULL ||
		    !knot_tsig_rdata_is_ok(rr)) {
			return KNOT_EMALF;
		}

		/* Strip TSIG RR from wireformat and decrease ARCOUNT. */
		if (!(flags & KNOT_PF_KEEPWIRE)) {
			pkt->parsed -= rr_size;
			pkt->size -= rr_size;
			pkt->tsig_wire.pos = pkt->wire + pkt->parsed;
			pkt->tsig_wire.len = rr_size;
			knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);
		}

		pkt->tsig_rr = rr;
		break;
	case KNOT_RRTYPE_OPT:
		if (pkt->current != KNOT_ADDITIONAL || pkt->opt_rr != NULL ||
		    knot_edns_get_options(rr, &pkt->edns_opts, &pkt->mm) != KNOT_EOK) {
			return KNOT_EMALF;
		}

		pkt->opt_rr = rr;
		break;
	default:
		break;
	}

	return KNOT_EOK;
}

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
	                              &pkt->mm, rr, !(flags & KNOT_PF_NOCANON));
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

static int parse_section(knot_pkt_t *pkt, unsigned flags)
{
	assert(pkt);

	uint16_t rr_parsed = 0;
	uint16_t rr_count = pkt_rr_wirecount(pkt, pkt->current);

	/* Parse all RRs belonging to the section. */
	for (rr_parsed = 0; rr_parsed < rr_count; ++rr_parsed) {
		int ret = knot_pkt_parse_rr(pkt, flags);
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
		ret = parse_section(pkt, flags);
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
		return KNOT_ETRAIL;
	}

	return KNOT_EOK;
}

_public_
uint16_t knot_pkt_ext_rcode(const knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return 0;
	}

	/* Get header RCODE. */
	uint16_t rcode = knot_wire_get_rcode(pkt->wire);

	/* Update to extended RCODE if EDNS is available. */
	if (pkt->opt_rr != NULL) {
		uint8_t opt_rcode = knot_edns_get_ext_rcode(pkt->opt_rr);
		rcode = knot_edns_whole_rcode(opt_rcode, rcode);
	}

	/* Return if not NOTAUTH. */
	if (rcode != KNOT_RCODE_NOTAUTH) {
		return rcode;
	}

	/* Get TSIG RCODE. */
	uint16_t tsig_rcode = KNOT_RCODE_NOERROR;
	if (pkt->tsig_rr != NULL) {
		tsig_rcode = knot_tsig_rdata_error(pkt->tsig_rr);
	}

	/* Return proper RCODE. */
	if (tsig_rcode != KNOT_RCODE_NOERROR) {
		return tsig_rcode;
	} else {
		return rcode;
	}
}

_public_
const char *knot_pkt_ext_rcode_name(const knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return "";
	}

	uint16_t rcode = knot_pkt_ext_rcode(pkt);

	const knot_lookup_t *item = NULL;
	if (pkt->tsig_rr != NULL) {
		item = knot_lookup_by_id(knot_tsig_rcode_names, rcode);
	}
	if (item == NULL) {
		item = knot_lookup_by_id(knot_rcode_names, rcode);
	}

	return (item != NULL) ? item->name : "";
}
