/*!
 * \file pkt.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for holding DNS packet data and metadata.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_PACKET_H_
#define _KNOT_PACKET_H_

#include <stdint.h>
#include <string.h>

#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/edns.h"
#include "libknot/zone/node.h"
#include "libknot/zone/zone.h"
#include "libknot/packet/wire.h"
#include "libknot/tsig.h"
#include "libknot/packet/compr.h"

/* Number of packet sections. */
#define KNOT_PKT_SECTIONS 3

/* Number of maximum RRs in packet. */
#define KNOT_PKT_MAX_RRS (KNOT_WIRE_MAX_PAYLOAD / KNOT_WIRE_RR_MIN_SIZE)

/*!
 * \brief Packet flags.
 */
enum {
	KNOT_PF_NULL      = 0 << 0, /*!< No flags. */
	KNOT_PF_WILDCARD  = 1 << 1, /*!< Query to wildcard name. */
	KNOT_PF_FREE      = 1 << 2, /*!< Free with packet. */
	KNOT_PF_NOTRUNC   = 1 << 3, /*!< Don't truncate. */
	KNOT_PF_CHECKDUP  = 1 << 4,  /*!< Check for duplicates. */
	KNOT_PACKET_DUPL_NO_MERGE = 1 << 5 /* Don't add duplicate rdata to rrset. */
};

/*!
 * \brief Packet section.
 */
typedef struct {
	const knot_rrset_t **rr;
	const knot_rrinfo_t *rrinfo;
	uint16_t count;
} knot_pktsection_t;

/*!
 * \brief Structure representing a DNS packet.
 */
typedef struct knot_pkt {

	uint8_t *wire;  /*!< Wire format of the packet. */

	size_t size;      /*!< Current wire size of the packet. */
	size_t max_size;  /*!< Maximum allowed size of the packet. */
	size_t parsed;

	uint16_t qname_size; /*!< QNAME size. */
	uint16_t tsig_size;	/*!< Space to reserve for the TSIG RR. */
	uint16_t rrset_count;
	uint16_t flags;

	knot_opt_rr_t opt_rr;   /*!< OPT RR included in the packet. */
	knot_rrset_t *tsig_rr;  /*!< TSIG RR stored in the packet. */

	/* #10 <<< SHOULD BE IN ANSWERING CONTEXT */
	/*! \todo Could be removed after NSEC proof port to packet processing,
	 *        and request processing module. */
	const knot_tsig_key_t *tsig_key;
	const struct knot_pkt *query; /*!< Associated query. */
	/* #10 >>> SHOULD BE IN ANSWERING CONTEXT */

	knot_section_t current;
	knot_pktsection_t sections[KNOT_PKT_SECTIONS];
	knot_rrinfo_t rr_info[KNOT_PKT_MAX_RRS];
	const knot_rrset_t *rr[KNOT_PKT_MAX_RRS];

	mm_ctx_t mm; /*!< Memory allocation context. */
} knot_pkt_t;

/*----------------------------------------------------------------------------*/

knot_pkt_t *knot_pkt_new(void *wire, uint16_t len, mm_ctx_t *mm);
int knot_pkt_reset(knot_pkt_t *pkt, void *wire, uint16_t len);
int knot_pkt_init_response(knot_pkt_t *pkt, const knot_pkt_t *query);
void knot_pkt_clear(knot_pkt_t *pkt);
void knot_pkt_clear_payload(knot_pkt_t *pkt);
void knot_pkt_free(knot_pkt_t **packet);

uint16_t knot_pkt_type(const knot_pkt_t *packet);
uint16_t knot_pkt_question_size(const knot_pkt_t *pkt);
knot_dname_t *knot_pkt_qname(const knot_pkt_t *packet);
uint16_t knot_pkt_qtype(const knot_pkt_t *packet);
uint16_t knot_pkt_qclass(const knot_pkt_t *packet);

int knot_pkt_begin(knot_pkt_t *pkt, knot_section_t section_id);
int knot_pkt_opt_set(knot_pkt_t *pkt, unsigned opt, const void *data, uint16_t len);
int knot_pkt_tsig_set(knot_pkt_t *pkt, const knot_tsig_key_t *tsig_key); /* #10 sign context */
int knot_pkt_put_question(knot_pkt_t *pkt, const knot_dname_t *qname, uint16_t qclass, uint16_t qtype);
int knot_pkt_put_dname(const knot_dname_t *dname, uint8_t *dst, uint16_t max, knot_compr_t *compr);
int knot_pkt_put_opt(knot_pkt_t *pkt);
int knot_pkt_put(knot_pkt_t *pkt, uint16_t compress, const knot_rrset_t *rr, uint32_t flags);

const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *pkt, knot_section_t section_id);
const knot_rrset_t *knot_pkt_get_last(const knot_pkt_t *pkt);

int knot_pkt_parse(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_question(knot_pkt_t *pkt);
int knot_pkt_parse_rr(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_section(knot_pkt_t *pkt, unsigned flags);
int knot_pkt_parse_payload(knot_pkt_t *pkt, unsigned flags);

/*!
 * \brief Checks if EDNS is supported (i.e. has EDNS VERSION != UNSUPPORTED).
 */
static inline bool knot_pkt_have_edns(const knot_pkt_t *pkt)
{
	return pkt && (knot_edns_get_version(&pkt->opt_rr) != EDNS_NOT_SUPPORTED);
}

/*!
 * \brief Checks if EDNS is supported (i.e. has EDNS VERSION != UNSUPPORTED).
 */
static inline bool knot_pkt_have_tsig(const knot_pkt_t *pkt)
{
	return pkt && pkt->tsig_rr;
}

/*!
 * \brief Checks if DNSSEC was requested (i.e. the DO bit was set).
 */
static inline bool knot_pkt_have_dnssec(const knot_pkt_t *pkt)
{
	return knot_pkt_have_edns(pkt) && knot_edns_do(&pkt->opt_rr);
}

/*!
 * \brief Checks if NSID was requested (i.e. the NSID option was
 *        present in the query OPT RR).
 */
static inline bool knot_pkt_have_nsid(const knot_pkt_t *pkt)
{
	return knot_pkt_have_edns(pkt)
	       && knot_edns_has_option(&pkt->opt_rr, EDNS_OPTION_NSID);
}

/*** <<< #10 DEPRECATED */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the OPT RR of the response.
 *
 * This function also allocates space for the wireformat of the response, if
 * the payload in the OPT RR is larger than the current maximum size of the
 * response and copies the current wireformat over to the new space.
 *
 * \note The contents of the OPT RR are copied.
 *
 * \note It is expected that resp.max_size is already set to correct value as
 *       it is impossible to distinguish TCP scenario in this function.
 *
 * \param resp Response to set the OPT RR to.
 * \param opt_rr OPT RR to set.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 *
 * \todo Needs test.
 */
int knot_pkt_add_opt(knot_pkt_t *resp,
                          const knot_opt_rr_t *opt_rr,
                          int add_nsid);

/*----------------------------------------------------------------------------*/
/*** >>> #10 DEPRECATED */


#endif /* _KNOT_PACKET_H_ */

/*! @} */
