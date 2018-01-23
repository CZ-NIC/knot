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
/*!
 * \file
 *
 * \brief Structure for holding DNS packet data and metadata.
 *
 * \addtogroup pkt
 * @{
 */

#pragma once

#include <assert.h>
#include <stdint.h>

#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/mm_ctx.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/opt.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/compr.h"
#include "libknot/wire.h"

/* Number of packet sections (ANSWER, AUTHORITY, ADDITIONAL). */
#define KNOT_PKT_SECTIONS 3

/*!
 * \brief Packet flags.
 */
enum {
	KNOT_PF_NULL      = 0 << 0, /*!< No flags. */
	KNOT_PF_FREE      = 1 << 1, /*!< Free with packet. */
	KNOT_PF_NOTRUNC   = 1 << 2, /*!< Don't truncate. */
	KNOT_PF_CHECKDUP  = 1 << 3, /*!< Check for duplicates. */
	KNOT_PF_KEEPWIRE  = 1 << 4, /*!< Keep wireformat untouched when parsing. */
	KNOT_PF_NOCANON   = 1 << 5, /*!< Don't canonicalize rrsets during parsing. */
};

/*!
 * \brief Packet section.
 * Points to RRSet and RRSet info arrays in the packet.
 * This structure is required for random access to packet sections.
 */
typedef struct {
	struct knot_pkt *pkt; /*!< Owner. */
	uint16_t pos;         /*!< Position in the rr/rrinfo fields in packet. */
	uint16_t count;       /*!< Number of RRSets in this section. */
} knot_pktsection_t;

/*!
 * \brief Structure representing a DNS packet.
 */
struct knot_pkt {

	uint8_t *wire;         /*!< Wire format of the packet. */
	size_t size;           /*!< Current wire size of the packet. */
	size_t max_size;       /*!< Maximum allowed size of the packet. */
	size_t parsed;         /*!< Parsed size. */
	uint16_t reserved;     /*!< Reserved space. */
	uint16_t qname_size;   /*!< QNAME size. */
	uint16_t rrset_count;  /*!< Packet RRSet count. */
	uint16_t flags;        /*!< Packet flags. */

	knot_rrset_t *opt_rr;   /*!< OPT RR included in the packet. */
	knot_rrset_t *tsig_rr;  /*!< TSIG RR stored in the packet. */

	/* TSIG RR position in the wire (if parsed from wire). */
	struct {
		uint8_t *pos;
		size_t len;
	} tsig_wire;

	/* Packet sections. */
	knot_section_t current;
	knot_pktsection_t sections[KNOT_PKT_SECTIONS];

	/* Packet RRSet (meta)data. */
	size_t rrset_allocd;
	knot_rrinfo_t *rr_info;
	knot_rrset_t *rr;

	knot_mm_t mm; /*!< Memory allocation context. */

	knot_compr_t compr; /*!< Compression context. */
};

/*!
 * \brief Create new packet over existing memory, or allocate new from memory context.
 *
 * \note Packet is allocated from given memory context.
 *
 * \param wire If NULL, memory of 'len' size shall be allocated.
 *        Otherwise pointer is used for the wire format of the packet.
 * \param len Wire format length.
 * \param mm Memory context (NULL for default).
 * \return New packet or NULL.
 */
knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, knot_mm_t *mm);

/*!
 * \brief Copy packet.
 *
 * \note Current implementation is not very efficient, as it re-parses the wire.
 *
 * \param dst Target packet.
 * \param src Source packet.
 *
 * \return new packet or NULL
 */
int knot_pkt_copy(knot_pkt_t *dst, const knot_pkt_t *src);

/*!
 * \brief Initialized response from query packet.
 *
 * \note Question is not checked, it is expected to be checked already.
 *
 * \param pkt Given packet.
 * \param query Query.
 * \return KNOT_EOK, KNOT_EINVAL, KNOT_ESPACE
 */
int knot_pkt_init_response(knot_pkt_t *pkt, const knot_pkt_t *query);

/*! \brief Reinitialize packet for another use. */
void knot_pkt_clear(knot_pkt_t *pkt);

/*! \brief Begone you foul creature of the underworld. */
void knot_pkt_free(knot_pkt_t **pkt);

/*!
 * \brief Reserve an arbitrary amount of space in the packet.
 *
 * \return KNOT_EOK
 * \return KNOT_ERANGE if size can't be reserved
 */
int knot_pkt_reserve(knot_pkt_t *pkt, uint16_t size);

/*!
 * \brief Reclaim reserved size.
 *
 * \return KNOT_EOK
 * \return KNOT_ERANGE if size can't be reclaimed
 */
int knot_pkt_reclaim(knot_pkt_t *pkt, uint16_t size);

/*
 * Packet QUESTION accessors.
 */
static inline uint16_t knot_pkt_question_size(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	return pkt->qname_size + 2 * sizeof(uint16_t);
}

static inline const knot_dname_t *knot_pkt_qname(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return NULL;
	}

	return pkt->wire + KNOT_WIRE_HEADER_SIZE;
}

static inline uint16_t knot_pkt_qtype(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size;
	return knot_wire_read_u16(pkt->wire + off);
}

static inline uint16_t knot_pkt_qclass(const knot_pkt_t *pkt)
{
	if (pkt == NULL || pkt->qname_size == 0) {
		return 0;
	}

	unsigned off = KNOT_WIRE_HEADER_SIZE + pkt->qname_size + sizeof(uint16_t);
	return knot_wire_read_u16(pkt->wire + off);
}

/*
 * Packet writing API.
 */

/*!
 * \brief Begin reading/writing packet section.
 *
 * \note You must proceed in the natural order (ANSWER, AUTHORITY, ADDITIONAL).
 *
 * \param pkt
 * \param section_id
 * \return KNOT_EOK or KNOT_EINVAL
 */
int knot_pkt_begin(knot_pkt_t *pkt, knot_section_t section_id);

/*!
 * \brief Put QUESTION in the packet.
 *
 * \note Since we support QD=1 only, QUESTION is a special type of packet section.
 * \note Must not be used after putting RRsets into the packet.
 *
 * \param pkt
 * \param qname
 * \param qclass
 * \param qtype
 * \return KNOT_EOK or various errors
 */
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname,
                          uint16_t qclass, uint16_t qtype);

/*!
 * \brief Put RRSet into packet.
 *
 * \note See compr.h for description on how compression hints work.
 * \note Available flags: PF_FREE, KNOT_PF_CHECKDUP, KNOT_PF_NOTRUNC
 *
 * \param pkt
 * \param compr_hint Compression hint, see enum knot_compr_hint or absolute
 *                   position.
 * \param rr Given RRSet.
 * \param flags RRSet flags (set PF_FREE if you want RRSet to be freed with the
 *              packet).
 * \return KNOT_EOK, KNOT_ESPACE, various errors
 */
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compr_hint, const knot_rrset_t *rr,
                 uint16_t flags);

/*! \brief Get description of the given packet section. */
static inline const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt,
                                                        knot_section_t section_id)
{
	assert(pkt);
	return &pkt->sections[section_id];
}

/*! \brief Get RRSet from the packet section. */
static inline const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *section,
                                              uint16_t i)
{
	assert(section);
	return section->pkt->rr + section->pos + i;
}

/*! \brief Get RRSet offset in the packet wire. */
static inline uint16_t knot_pkt_rr_offset(const knot_pktsection_t *section,
                                          uint16_t i)
{
	assert(section);
	return section->pkt->rr_info[section->pos + i].pos;
}

/*
 * Packet parsing API.
 */

/*!
 * \brief Parse both packet question and payload.
 *
 * Parses both QUESTION and all packet sections,
 * includes semantic checks over specific RRs (TSIG, OPT).
 *
 * \note For KNOT_PF_KEEPWIRE see note for \fn knot_pkt_parse_rr
 *
 * \param pkt Given packet.
 * \param flags Parsing flags (allowed KNOT_PF_KEEPWIRE)
 * \return KNOT_EOK, KNOT_EMALF and other errors
 */
int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags);

/*!
 * \brief Parse packet header and a QUESTION section.
 */
int knot_pkt_parse_question(knot_pkt_t *pkt);

/*!
 * \brief Parse single resource record.
 *
 * \note When KNOT_PF_KEEPWIRE is set, TSIG RR is not stripped from the wire
 *       and is processed as any other RR.
 *
 * \param pkt
 * \param flags
 * \return KNOT_EOK, KNOT_EFEWDATA if not enough data or various errors
 */
int knot_pkt_parse_rr(knot_pkt_t *pkt, unsigned flags);

/*!
 * \brief Parse current packet section.
 *
 * \note For KNOT_PF_KEEPWIRE see note for \fn knot_pkt_parse_rr
 *
 * \param pkt
 * \param flags
 * \return KNOT_EOK, KNOT_EFEWDATA if not enough data or various errors
 */
int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags);

/*!
 * \brief Parse whole packet payload.
 *
 * \note For KNOT_PF_KEEPWIRE see note for \fn knot_pkt_parse_rr
 *
 * \param pkt
 * \param flags
 * \return KNOT_EOK, KNOT_EFEWDATA if not enough data or various errors
 */
int knot_pkt_parse_payload(knot_pkt_t *pkt, unsigned flags);

/*!
 * \brief Get packet extended RCODE.
 *
 * Extended RCODE is created by considering TSIG RCODE, EDNS RCODE and
 * DNS Header RCODE. (See RFC 6895, Section 2.3).
 *
 * \param pkt Packet to get the response code from.
 *
 * \return Whole extended RCODE (0 if pkt == NULL).
 */
uint16_t knot_pkt_ext_rcode(const knot_pkt_t *pkt);

/*!
 * \brief Get packet extended RCODE name.
 *
 * The packet parameter is important as the name depends on TSIG.
 *
 * \param pkt Packet to get the response code from.
 *
 * \return RCODE name (or empty string if not known).
 */
const char *knot_pkt_ext_rcode_name(const knot_pkt_t *pkt);

/*!
 * \brief Checks if there is an OPT RR in the packet.
 */
static inline bool knot_pkt_has_edns(const knot_pkt_t *pkt)
{
	return pkt != NULL && pkt->opt_rr != NULL;
}

/*!
 * \brief Checks if TSIG is present.
 */
static inline bool knot_pkt_has_tsig(const knot_pkt_t *pkt)
{
	return pkt && pkt->tsig_rr;
}

/*!
 * \brief Checks if DO bit is set in the packet's OPT RR.
 */
static inline bool knot_pkt_has_dnssec(const knot_pkt_t *pkt)
{
	return knot_pkt_has_edns(pkt) && knot_edns_do(pkt->opt_rr);
}

/*!
 * \brief Checks if there is an NSID OPTION in the packet's OPT RR.
 */
static inline bool knot_pkt_has_nsid(const knot_pkt_t *pkt)
{
	return knot_pkt_has_edns(pkt)
	       && knot_edns_has_option(pkt->opt_rr, KNOT_EDNS_OPTION_NSID);
}

/*! @} */
