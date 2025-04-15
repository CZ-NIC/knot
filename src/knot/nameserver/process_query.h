/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	zone_t *zone;        /*!< Zone from which is answered. */
	zone_contents_t *contents; /*!< Zone contents from which is answered. */
	list_t wildcards;    /*!< Visited wildcards. */
	list_t rrsigs;       /*!< Section RRSIGs. */
	uint8_t *opt_rr_pos; /*!< Place of the OPT RR in wire. */

	/* Currently processed nodes. */
	const zone_node_t *node, *encloser, *previous;

	uint8_t cname_chain; /*!< Length of the CNAME chain so far. */

	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(knotd_qdata_t *); /*!< Extensions cleanup callback. */
	void (*ext_finished)(knotd_qdata_t *, knot_pkt_t *, int); /*!< Optional postprocessing callback. */
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
 * \param action     ACL action.
 * \param qdata      Query data.
 * \return true if accepted, false if denied.
 */
bool process_query_acl_check(conf_t *conf, acl_action_t action,
                             knotd_qdata_t *qdata);

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

/*!
 * \brief Processes all global module protocol callbacks at given stage.
 *
 * \param params   Query processing parameters.
 * \param stage    Processing stage (KNOTD_STAGE_PROTO_BEGIN or KNOTD_STAGE_PROTO_END).
 *
 * \return Resulting state.
 */
knotd_proto_state_t process_query_proto(knotd_qdata_params_t *params,
                                        const knotd_stage_t stage);
