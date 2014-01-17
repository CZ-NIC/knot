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
#include <stdbool.h>

#include "libknot/packet/pkt.h"
#include "libknot/util/debug.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "libknot/packet/wire.h"
#include "libknot/tsig.h"
#include "libknot/tsig-op.h"

/*! \brief Scan packet for RRSet existence. */
static bool pkt_contains(const knot_pkt_t *packet,
			 const knot_rrset_t *rrset,
			 knot_rrset_compare_type_t cmp)
{
	assert(packet);
	assert(rrset);

	for (int i = 0; i < packet->rrset_count; ++i) {
		if (knot_rrset_equal(packet->rr[i], rrset, cmp)) {
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
	knot_rrset_t *rr  = NULL;
	for (uint16_t i = 0; i < pkt->rrset_count; ++i) {
		if (pkt->rr_info[i].flags & KNOT_PF_FREE) {
			rr = (knot_rrset_t *)pkt->rr[i];
			knot_rrset_deep_free(&rr, 1);
		}
	}

	/* Reset RR count. */
	pkt->rrset_count = 0;
}

/*! \brief Allocate new wireformat of given length. */
static int pkt_wire_alloc(knot_pkt_t *pkt, uint16_t len)
{
	assert(pkt);

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
	}
}

/*! \brief Update RR count for given section (wire xxCOUNT in header). */
static void pkt_rr_wirecount_add(knot_pkt_t *pkt, knot_section_t section_id,
                                 int16_t val)
{
	assert(pkt);
	switch (section_id) {
	case KNOT_ANSWER:     return knot_wire_add_ancount(pkt->wire, val);
	case KNOT_AUTHORITY:  return knot_wire_add_nscount(pkt->wire, val);
	case KNOT_ADDITIONAL: return knot_wire_add_arcount(pkt->wire, val);
	}
}

/*! \brief Clear the packet and switch wireformat pointers (possibly allocate new). */
static int knot_pkt_reset(knot_pkt_t *pkt, void *wire, uint16_t len)
{
	assert(pkt);

	/* Free allocated data. */
	pkt_free_data(pkt);

	/* NULL everything up to 'sections' (not the large data fields). */
	int ret = KNOT_EOK;
	mm_ctx_t mm = pkt->mm;
	memset(pkt, 0, offsetof(knot_pkt_t, rr_info));
	pkt->mm = mm;

	/* Initialize OPT RR defaults. */
	pkt->opt_rr.version = EDNS_NOT_SUPPORTED;
	pkt->opt_rr.size = EDNS_MIN_SIZE;

	/* Initialize wire. */
	if (wire == NULL) {
		ret = pkt_wire_alloc(pkt, len);
	} else {
		pkt_wire_set(pkt, wire, len);
	}

	return ret;
}

/*! \brief Clear packet payload and free allocated data. */
static void pkt_clear_payload(knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	assert(pkt);

	/* Keep question. */
	pkt->parsed = 0;
	pkt->size = knot_pkt_question_size(pkt);
	knot_wire_set_ancount(pkt->wire, 0);
	knot_wire_set_nscount(pkt->wire, 0);
	knot_wire_set_arcount(pkt->wire, 0);

	/* Free RRSets if applicable. */
	pkt_free_data(pkt);

	/* Reset section. */
	pkt->current = KNOT_ANSWER;
	pkt->sections[pkt->current].rr = pkt->rr;
	pkt->sections[pkt->current].rrinfo = pkt->rr_info;
}

/*! \brief Allocate new packet using memory context. */
static knot_pkt_t *pkt_new_mm(void *wire, uint16_t len, mm_ctx_t *mm)
{
	assert(mm);

	knot_pkt_t *pkt = mm->alloc(mm->ctx, sizeof(knot_pkt_t));
	if (pkt == NULL) {
		return NULL;
	}

	/* No data to free, set memory context. */
	pkt->rrset_count = 0;
	memcpy(&pkt->mm, mm, sizeof(mm_ctx_t));
	if (knot_pkt_reset(pkt, wire, len) != KNOT_EOK) {
		mm->free(pkt);
		return NULL;
	}

	return pkt;
}

knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, mm_ctx_t *mm)
{
	/* Default memory allocator if NULL. */
	dbg_packet("%s(%p, %hu, %p)\n", __func__, wire, len, mm);
	mm_ctx_t _mm;
	if (mm == NULL) {
		mm_ctx_init(&_mm);
		mm = &_mm;
	}

	return pkt_new_mm(wire, len, mm);
}

int knot_pkt_init_response(knot_pkt_t *pkt, const knot_pkt_t *query)
{
	dbg_packet("%s(%p, %p)\n", __func__, pkt, query);
	if (pkt == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	/* Header + question size. */
	size_t question_size = knot_pkt_question_size(query);
	if (question_size > pkt->max_size) {
		dbg_packet("%s: pkt max size < HEADER size\n", __func__);
		return KNOT_ESPACE;
	}
	pkt->query = query;
	pkt->size = question_size;
	pkt->qname_size = query->qname_size;
	memcpy(pkt->wire, query->wire, question_size);

	/* Update size and flags. */
	knot_wire_set_qr(pkt->wire);
	knot_wire_clear_tc(pkt->wire);
	knot_wire_clear_ad(pkt->wire);
	knot_wire_clear_ra(pkt->wire);

	/* Clear payload. */
	pkt_clear_payload(pkt);
	return KNOT_EOK;
}

void knot_pkt_clear(knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL) {
		return;
	}

	/* Clear payload. */
	pkt_clear_payload(pkt);

	/* Reset to header size. */
	pkt->size = KNOT_WIRE_HEADER_SIZE;
	memset(pkt->wire, 0, pkt->size);
}

void knot_pkt_free(knot_pkt_t **pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL || *pkt == NULL) {
		return;
	}

	/* Free temporary RRSets. */
	pkt_free_data(*pkt);

	// free the space for wireformat
	if ((*pkt)->flags & KNOT_PF_FREE) {
		(*pkt)->mm.free((*pkt)->wire);
	}

	// free EDNS options
	knot_edns_free_options(&(*pkt)->opt_rr);

	dbg_packet("Freeing packet structure\n");
	(*pkt)->mm.free(*pkt);
	*pkt = NULL;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_pkt_type(const knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
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

uint16_t knot_pkt_question_size(const knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL) {
		return 0;
	}

	uint16_t ret = KNOT_WIRE_HEADER_SIZE;
	if (pkt->qname_size > 0) {
		ret += pkt->qname_size + 2 * sizeof(uint16_t);
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL || pkt->qname_size == 0) {
		return NULL;
	}

	return pkt->wire + KNOT_WIRE_HEADER_SIZE;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_pkt_qtype(const knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size;
	return knot_wire_read_u16(pkt->wire + off);
}

/*----------------------------------------------------------------------------*/

uint16_t knot_pkt_qclass(const knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size + sizeof(uint16_t);
	return knot_wire_read_u16(pkt->wire + off);
}

/*----------------------------------------------------------------------------*/

int knot_pkt_opt_set(knot_pkt_t *pkt, unsigned opt, const void *data, uint16_t len)
{
	dbg_packet("%s(%p, %u, %p, %hu)\n", __func__, pkt, opt, data, len);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	knot_opt_rr_t *rr = &pkt->opt_rr;

	switch (opt) {
	case KNOT_PKT_EDNS_PAYLOAD:
		knot_edns_set_payload(rr, *(uint16_t *)data);
		break;
	case KNOT_PKT_EDNS_RCODE:
		knot_edns_set_ext_rcode(rr, *(uint8_t *)data);
		break;;
	case KNOT_PKT_EDNS_VERSION:
		knot_edns_set_version(rr, *(uint8_t *)data);
		break;
	case KNOT_PKT_EDNS_NSID:
		return knot_edns_add_option(rr, EDNS_OPTION_NSID, len, data);
	default:
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
}

int knot_pkt_tsig_set(knot_pkt_t *pkt, const knot_tsig_key_t *tsig_key)
{
	dbg_packet("%s(%p, %p)\n", __func__, pkt, tsig_key);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	pkt->tsig_key = tsig_key;
	if (tsig_key) {
		pkt->reserved += tsig_wire_maxsize(tsig_key);
	}
	return KNOT_EOK;
}

int knot_pkt_begin(knot_pkt_t *pkt, knot_section_t section_id)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Cannot step to lower section. */
	dbg_packet("%s(%p, %u)\n", __func__, pkt, section_id);
	assert(section_id >= pkt->current);
	pkt->current = section_id;

	/* Remember watermark. */
	pkt->sections[section_id].rr = pkt->rr + pkt->rrset_count;
	pkt->sections[section_id].rrinfo = pkt->rr_info + pkt->rrset_count;
	return KNOT_EOK;
}

int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype)
{
	dbg_packet("%s(%p, %p, %hu, %hu)\n", __func__, pkt, qname, qclass, qtype);
	if (pkt == NULL || qname == NULL) {
		return KNOT_EINVAL;
	}

	assert(pkt->size == KNOT_WIRE_HEADER_SIZE);
	assert(pkt->rrset_count == 0);

	/* Copy name wireformat. */
	uint8_t *dst = pkt->wire + KNOT_WIRE_HEADER_SIZE;
	int qname_len = knot_dname_to_wire(dst, qname, pkt->max_size - pkt->size);
	assert(qname_len == knot_dname_size(qname));
	size_t question_len = 2 * sizeof(uint16_t) + qname_len;

	/* Check size limits. */
	if (qname_len < 0 || pkt->size + question_len > pkt->max_size)
		return KNOT_ESPACE;

	/* Copy QTYPE & QCLASS */
	dst += qname_len;
	knot_wire_write_u16(dst, qtype);
	dst += sizeof(uint16_t);
	knot_wire_write_u16(dst, qclass);

	/* Update question count and sizes. */
	knot_wire_set_qdcount(pkt->wire, 1);
	pkt->size += question_len;
	pkt->qname_size = qname_len;

	/* Start writing ANSWER. */
	return knot_pkt_begin(pkt, KNOT_ANSWER);
}

int knot_pkt_put_opt(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* \note #190, not going to be pretty until then */
	if (pkt->opt_rr.version == EDNS_NOT_SUPPORTED) {
		return KNOT_EOK;
	}

	int ret = knot_edns_to_wire(&pkt->opt_rr,
	                            pkt->wire + pkt->size,
	                            pkt->max_size - pkt->size);
	if (ret <= 0) {
		return ret;
	}

	pkt_rr_wirecount_add(pkt, pkt->current, 1);
	pkt->size += ret;
	pkt->reserved -= ret;

	dbg_packet("%s: OPT RR written, new packet size %zu\n", __func__, pkt->size);

	return KNOT_EOK;
}

int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr, uint16_t flags)
{
	dbg_packet("%s(%p, %u, %p, %u)\n", __func__, pkt, compr_hint, rr, flags);
	if (pkt == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrinfo_t *rrinfo = &pkt->rr_info[pkt->rrset_count];
	memset(rrinfo, 0, sizeof(knot_rrinfo_t));
	rrinfo->pos = pkt->size;
	rrinfo->flags = flags;
	rrinfo->compress_ptr[0] = compr_hint;
	pkt->rr[pkt->rrset_count] = rr;

	/* Check for double insertion. */
	if ((flags & KNOT_PF_CHECKDUP) &&
	    pkt_contains(pkt, rr, KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK; /*! \todo return rather a number of added RRs */
	}

	uint8_t *pos = pkt->wire + pkt->size;
	uint16_t rr_added = 0;
	size_t maxlen = pkt_remaining(pkt);
	size_t len = maxlen;

	/* Create compression context. */
	knot_compr_t compr;
	compr.wire = pkt->wire;
	compr.wire_pos = pkt->size;
	compr.rrinfo = rrinfo;
	compr.suffix.pos = KNOT_WIRE_HEADER_SIZE;
	compr.suffix.labels = knot_dname_labels(compr.wire + compr.suffix.pos,
	                                        compr.wire);

	/* Write RRSet to wireformat. */
	int ret = knot_rrset_to_wire(rr, pos, &len, maxlen, &rr_added, &compr);
	if (ret != KNOT_EOK) {
		dbg_packet("%s: rr_to_wire = %s\n,", __func__, knot_strerror(ret));

		/* Truncate packet if required. */
		if (ret == KNOT_ESPACE && !(flags & KNOT_PF_NOTRUNC)) {
				dbg_packet("%s: set TC=1\n", __func__);
				knot_wire_set_tc(pkt->wire);
		}
		return ret;
	}

	if (rr_added > 0) {
		pkt->rrset_count += 1;
		pkt->sections[pkt->current].count += 1;
		pkt->size += len;
		pkt_rr_wirecount_add(pkt, pkt->current, rr_added);
	}

	dbg_packet("%s: added %u RRs (@%zu, len=%zu), pktsize=%zu (%s)\n",
	           __func__, rr_added, pkt->size - len, len, pkt->size,
	           rr->rrsigs ? "signed" : "unsigned");

	return KNOT_EOK;
}

const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt, knot_section_t section_id)
{
	dbg_packet("%s(%p, %u)\n", __func__, pkt, section_id);
	if (pkt == NULL) {
		return NULL;
	}

	return &pkt->sections[section_id];
}

int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags)
{
	dbg_packet("%s(%p, %u)\n", __func__, pkt, flags);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knot_pkt_parse_question(pkt);
	if (ret == KNOT_EOK) {
		ret = knot_pkt_parse_payload(pkt, flags);
	}

	return ret;
}

int knot_pkt_parse_question(knot_pkt_t *pkt)
{
	dbg_packet("%s(%p)\n", __func__, pkt);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Check at least header size. */
	if (pkt->size < KNOT_WIRE_HEADER_SIZE) {
		dbg_packet("%s: smaller than DNS header, FORMERR\n", __func__);
		return KNOT_EMALF;
	}

	/* Check QD count. */
	uint16_t qd = knot_wire_get_qdcount(pkt->wire);
	if (qd > 1) {
		dbg_packet("%s: QD(%u) > 1, FORMERR\n", __func__, qd);
		return KNOT_EMALF;
	}

	pkt->parsed = KNOT_WIRE_HEADER_SIZE;

	/* No question. */
	if (qd == 0) {
		pkt->qname_size = 0;
		return KNOT_EOK;
	}

	/* Process question. */
	int len = knot_dname_wire_check(pkt->wire + pkt->parsed,
	                                pkt->wire + pkt->size,
	                                pkt->wire);
	if (len <= 0) {
		return KNOT_EMALF;
	}
	
	/* Check QCLASS/QTYPE size. */
	uint16_t question_size = len + 2 * sizeof(uint16_t); /* QCLASS + QTYPE */
	if (pkt->parsed + question_size > pkt->size) {
		dbg_packet("%s: missing QCLASS/QTYPE, FORMERR\n", __func__);
		return KNOT_EMALF;
	}

	pkt->parsed += question_size; 
	pkt->qname_size = len;

	return KNOT_EOK;
}

static int knot_pkt_merge_rr(knot_pkt_t *pkt, knot_rrset_t *rr, unsigned flags)
{
	dbg_packet("%s(%p, %p, %u)\n", __func__, pkt, rr, flags);
	assert(pkt);
	assert(rr);

	/* Don't want to merge, okay. */
	if (flags & KNOT_PACKET_DUPL_NO_MERGE) {
		return KNOT_ENOENT;
	}

	// try to find the RRSet in this array of RRSets
	for (int i = 0; i < pkt->rrset_count; ++i) {

		if (knot_rrset_equal(pkt->rr[i], rr, KNOT_RRSET_COMPARE_HEADER)) {
			int merged = 0;
			int deleted_rrs = 0;
			int rc = knot_rrset_merge_sort((knot_rrset_t *)pkt->rr[i],
			                               rr, &merged, &deleted_rrs);
			if (rc != KNOT_EOK) {
				dbg_packet("%s: failed to merge RR %p (%d)\n", __func__, rr, rc);
				return rc;
			}

			dbg_packet("%s: merged RR %p\n", __func__, rr);
			knot_rrset_deep_free(&rr, 1);
			return KNOT_EOK;
		}
	}


	return KNOT_ENOENT;
}

/*! \note Legacy code, mainly for transfers and updates.
 *        RRSets should use packet memory context for allocation and
 *        should be copied if they are supposed to be stored in zone permanently.
 */
static knot_rrset_t *knot_pkt_rr_from_wire(const uint8_t *wire, size_t *pos,
                                           size_t size)
{
	dbg_packet("%s(%p, %zu, %zu)\n", __func__, wire, *pos, size);
	assert(wire);
	assert(pos);

	knot_dname_t *owner = knot_dname_parse(wire, pos, size);
	if (owner == NULL) {
		return NULL;
	}
	knot_dname_to_lower(owner);

	if (size - *pos < KNOT_RR_HEADER_SIZE) {
		dbg_packet("%s: not enough data to parse RR HEADER\n", __func__);
		knot_dname_free(&owner);
		return NULL;
	}

	uint16_t type = knot_wire_read_u16(wire + *pos);
	uint16_t rclass = knot_wire_read_u16(wire + *pos + sizeof(uint16_t));
	uint32_t ttl = knot_wire_read_u32(wire + *pos + 2 * sizeof(uint16_t));
	uint16_t rdlength = knot_wire_read_u16(wire + *pos + 4 * sizeof(uint16_t));

	knot_rrset_t *rrset = knot_rrset_new(owner, type, rclass, ttl);
	if (rrset == NULL) {
		knot_dname_free(&owner);
		return NULL;
	}
	*pos += KNOT_RR_HEADER_SIZE;

	dbg_packet_verb("%s: read type %u, class %u, ttl %u, rdlength %u\n",
	                __func__, rrset->type, rrset->rclass, rrset->ttl, rdlength);

	if (size - *pos < rdlength) {
		dbg_packet("%s: not enough data to parse RDATA\n", __func__);
		knot_rrset_deep_free(&rrset, 1);
		return NULL;
	}

	// parse RDATA
	/*! \todo Merge with add_rdata_to_rr in zcompile, should be a rrset func
	 *        probably. */
	int ret = knot_rrset_rdata_from_wire_one(rrset, wire, pos, size, rdlength);
	if (ret != KNOT_EOK) {
		dbg_packet("%s: couldn't parse RDATA (%d)\n", __func__, ret);
		knot_rrset_deep_free(&rrset, 1);
		return NULL;
	}

	return rrset;
}

int knot_pkt_parse_rr(knot_pkt_t *pkt, unsigned flags)
{
	dbg_packet("%s(%p, %u)\n", __func__, pkt, flags);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	if (pkt->parsed >= pkt->size) {
		dbg_packet("%s: parsed %zu/%zu data\n", __func__, pkt->parsed, pkt->size);
		return KNOT_EFEWDATA;
	}

	/* Initialize RR info. */
	int ret = KNOT_EOK;
	memset(&pkt->rr_info[pkt->rrset_count], 0, sizeof(knot_rrinfo_t));
	pkt->rr_info[pkt->rrset_count].pos = pkt->parsed;
	pkt->rr_info[pkt->rrset_count].flags = KNOT_PF_FREE;

	/* Parse wire format. */
	size_t rr_size = pkt->parsed;
	knot_rrset_t *rr = NULL;
	rr = knot_pkt_rr_from_wire(pkt->wire, &pkt->parsed, pkt->max_size);
	if (rr == NULL) {
		dbg_packet("%s: failed to parse RR\n", __func__);
		return KNOT_EMALF;
	}
	
	/* Calculate parsed RR size from before/after parsing. */
	rr_size = (pkt->parsed - rr_size);

	/* Merge with existing RRSet if possible, otherwise add new RR set. */
	if (knot_pkt_merge_rr(pkt, rr, flags) == KNOT_EOK) {
		return KNOT_EOK;
	}

	/* Append to RR list. */
	pkt->rr[pkt->rrset_count] = rr;
	++pkt->rrset_count;

	/* Update section RRSet count. */
	++pkt->sections[pkt->current].count;

	/* Check RR constraints. */
	switch(knot_rrset_type(rr)) {
	case KNOT_RRTYPE_TSIG:
		// if there is some TSIG already, treat as malformed
		if (pkt->tsig_rr != NULL) {
			dbg_packet("%s: found 2nd TSIG\n", __func__);
			return KNOT_EMALF;
		} else if (!tsig_rdata_is_ok(rr)) {
			dbg_packet("%s: bad TSIG RDATA\n", __func__);
			return KNOT_EMALF;
		}

		/* Strip TSIG RR from wireformat and decrease ARCOUNT. */
		pkt->parsed -= rr_size;
		pkt->size -= rr_size;
		knot_wire_set_id(pkt->wire, tsig_rdata_orig_id(rr));
		knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);

		/* Remember TSIG RR. */
		pkt->tsig_rr = rr;
		break;
	case KNOT_RRTYPE_OPT:
		ret = knot_edns_new_from_rr(&pkt->opt_rr, rr);
		if (ret != KNOT_EOK) {
			dbg_packet("%s: couldn't parse OPT RR = %d\n",
				   __func__, ret);
		}
		break;
	default:
		break;
	}

	return ret;
}

int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags)
{
	dbg_packet("%s(%p, %u)\n", __func__, pkt, flags);
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
			dbg_packet("%s: couldn't parse RR %u/%u = %d\n",
			           __func__, rr_parsed, rr_count, ret);
			return ret;
		}
	}

	return KNOT_EOK;
}

int knot_pkt_parse_payload(knot_pkt_t *pkt, unsigned flags)
{
	dbg_packet("%s(%p, %u)\n", __func__, pkt, flags);
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	assert(pkt->wire != NULL);
	assert(pkt->size > 0);

	int ret = KNOT_ERROR;

	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		ret = knot_pkt_begin(pkt, i);
		if (ret != KNOT_EOK) {
			dbg_packet("%s: couldn't begin section %u = %d\n",
			           __func__, i, ret);
			return ret;
		}
		ret = knot_pkt_parse_section(pkt, flags);
		if (ret != KNOT_EOK) {
			dbg_packet("%s: couldn't parse section %u = %d\n",
			           __func__, i, ret);
			return ret;
		}
	}

	/* TSIG must be last record of AR if present. */
	const knot_pktsection_t *ar = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	if (pkt->tsig_rr != NULL) {
		if (ar->count > 0 && pkt->tsig_rr != ar->rr[ar->count - 1]) {
			dbg_packet("%s: TSIG not last RR in AR.\n", __func__);
			return KNOT_EMALF;
		}
	}

	/* Check for trailing garbage. */
	if (pkt->parsed < pkt->size) {
		dbg_packet("%s: %zu bytes of trailing garbage\n",
		           __func__, pkt->size - pkt->parsed);
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*** <<< #8 DEPRECATED */
/*----------------------------------------------------------------------------*/

int knot_pkt_add_opt(knot_pkt_t *resp, const knot_opt_rr_t *opt_rr, int add_nsid)
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

	if (add_nsid && opt_rr->option_count > 0) {
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
		resp->opt_rr.size = EDNS_MIN_SIZE;
	}

	resp->reserved += resp->opt_rr.size;

	return KNOT_EOK;
}

/*** >>> #8 DEPRECATED */
/*----------------------------------------------------------------------------*/
