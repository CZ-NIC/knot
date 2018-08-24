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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/include/module.h"
#include "knot/query/layer.h"
#include "knot/updates/acl.h"
#include "knot/zone/zone.h"

/* Query processing module implementation. */
const knot_layer_api_t *process_query_layer(void);

/*! \brief Query processing intermediate data. */
typedef struct knotd_qdata_extra {
	const zone_t *zone;  /*!< Zone from which is answered. */
	list_t wildcards;    /*!< Visited wildcards. */
	list_t rrsigs;       /*!< Section RRSIGs. */
	uint8_t *opt_rr_pos; /*!< Place of the OPT RR in wire. */

	/* Currently processed nodes. */
	const zone_node_t *node, *encloser, *previous;

	/* Original QNAME case. */
	uint8_t orig_qname[KNOT_DNAME_MAXLEN];

	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(knotd_qdata_t *); /*!< Extensions cleanup callback. */
} knotd_qdata_extra_t;

/*! \brief Visited wildcard node list. */
struct wildcard_hit {
	node_t n;
	const zone_node_t *node;   /* Visited node. */
	const zone_node_t *prev;   /* Previous node from the SNAME. */
	const knot_dname_t *sname; /* Name leading to this node. */
};

/*! \brief RRSIG info node list. */
struct rrsig_info {
	node_t n;
	knot_rrset_t synth_rrsig; /* Synthesized RRSIG. */
	knot_rrinfo_t *rrinfo;    /* RR info. */
};

/*!
 * \brief Check current query against ACL.
 *
 * \param conf       Configuration.
 * \param zone_name  Current zone name.
 * \param action     ACL action.
 * \param qdata      Query data.
 * \return true if accepted, false if denied.
 */
bool process_query_acl_check(conf_t *conf, const knot_dname_t *zone_name,
                             acl_action_t action, knotd_qdata_t *qdata);

/*!
 * \brief Verify current query transaction security and update query data.
 *
 * \param qdata
 * \retval KNOT_EOK
 * \retval KNOT_TSIG_EBADKEY
 * \retval KNOT_TSIG_EBADSIG
 * \retval KNOT_TSIG_EBADTIME
 * \retval (other generic errors)
 */
int process_query_verify(knotd_qdata_t *qdata);

/*!
 * \brief Sign current query using configured TSIG keys.
 *
 * \param pkt    Outgoing message.
 * \param qdata  Query data.
 *
 * \retval KNOT_E*
 */
int process_query_sign_response(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/*!
 * \brief Restore QNAME letter case.
 *
 * \param pkt    Incoming message.
 * \param qdata  Query data.
 */
static inline void process_query_qname_case_restore(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	// If original QNAME is empty, query is either unparsed or for root domain.
	if (qdata->extra->orig_qname[0] != '\0') {
		memcpy(pkt->wire + KNOT_WIRE_HEADER_SIZE,
		       qdata->extra->orig_qname, qdata->query->qname_size);
	}
}

/*!
 * \brief Convert QNAME to lowercase format for processing.
 *
 * \param pkt    Incoming message.
 */
static inline void process_query_qname_case_lower(knot_pkt_t *pkt)
{
	knot_dname_to_lower(knot_pkt_qname(pkt));
}

/*!
 * \brief Puts RRSet to packet, will store its RRSIG for later use.
 *
 * \param pkt         Packet to store RRSet into.
 * \param qdata       Query data structure.
 * \param rr          RRSet to be stored.
 * \param rrsigs      RRSIGs to be stored.
 * \param compr_hint  Compression hint.
 * \param flags       Flags.
 *
 * \return KNOT_E*
 */
int process_query_put_rr(knot_pkt_t *pkt, knotd_qdata_t *qdata,
                         const knot_rrset_t *rr, const knot_rrset_t *rrsigs,
                         uint16_t compr_hint, uint32_t flags);
