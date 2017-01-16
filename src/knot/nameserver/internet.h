/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/packet/pkt.h"

struct query_data;
struct answer_data;

/*! \brief Internet query processing states. */
enum {
	BEGIN,   /* Begin name resolution. */
	NODATA,  /* Positive result with NO data. */
	HIT,     /* Positive result. */
	MISS,    /* Negative result. */
	DELEG,   /* Result is delegation. */
	FOLLOW,  /* Resolution not complete (CNAME/DNAME chain). */
	ERROR,   /* Resolution failed. */
	TRUNC    /* Finished, packet size limit encountered. */
};

/*!
 * \brief Answer query from an IN class zone.
 *
 * \retval KNOT_STATE_FAIL if it encountered an error.
 * \retval KNOT_STATE_DONE if finished.
 */
int internet_process_query(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Puts RRSet to packet, will store its RRSIG for later use.
 *
 * \param pkt         Packet to store RRSet into.
 * \param rr          RRSet to be stored.
 * \param rrsigs      RRSIGs to be stored.
 * \param compr_hint  Compression hint.
 * \param flags       Flags.
 * \param expand      Set to true if wildcards should be expanded.
 * \param qdata       Query data structure.
 *
 * \return KNOT_E*
 */
int ns_put_rr(knot_pkt_t *pkt, const knot_rrset_t *rr,
              const knot_rrset_t *rrsigs, uint16_t compr_hint,
              uint32_t flags, struct query_data *qdata);

/*! \brief Require given QUERY TYPE or return error code. */
#define NS_NEED_QTYPE(qdata, qtype_want, error_rcode) \
	if (knot_pkt_qtype((qdata)->query) != (qtype_want)) { \
		qdata->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require given QUERY NAME or return error code. */
#define NS_NEED_QNAME(qdata, qname_want, error_rcode) \
	if (!knot_dname_is_equal(knot_pkt_qname((qdata)->query), (qname_want))) { \
		qdata->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require existing zone or return failure. */
#define NS_NEED_ZONE(qdata, error_rcode) \
	if ((qdata)->zone == NULL) { \
		qdata->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require existing zone contents or return failure. */
#define NS_NEED_ZONE_CONTENTS(qdata, error_rcode) \
	if ((qdata)->zone->contents == NULL) { \
		qdata->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require authentication. */
#define NS_NEED_AUTH(qdata, zone_name, action) \
	if (!process_query_acl_check(conf(), (zone_name), (action), (qdata))) { \
		return KNOT_STATE_FAIL; \
	} else { \
		if (process_query_verify(qdata) != KNOT_EOK) { \
			return KNOT_STATE_FAIL; \
		} \
	}

/*! \brief Require maximum number of unsigned messages. */
#define NS_NEED_TSIG_SIGNED(tsig_ctx, max_unsigned) \
	if (tsig_unsigned_count(tsig_ctx) > max_unsigned) { \
		return KNOT_STATE_FAIL; \
	}
