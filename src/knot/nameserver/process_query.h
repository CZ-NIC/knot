/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Query processor.
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/updates/acl.h"
#include "contrib/sockaddr.h"

/* Query processing module implementation. */
const knot_layer_api_t *process_query_layer(void);

/* Query processing specific flags. */
enum process_query_flag {
	NS_QUERY_NO_AXFR    = 1 << 0, /* Don't process AXFR */
	NS_QUERY_NO_IXFR    = 1 << 1, /* Don't process IXFR */
	NS_QUERY_LIMIT_ANY  = 1 << 2, /* Limit ANY QTYPE (respond with TC=1) */
	NS_QUERY_LIMIT_RATE = 1 << 3, /* Apply rate limits. */
	NS_QUERY_LIMIT_SIZE = 1 << 4  /* Apply UDP size limit. */
};

/* Module load parameters. */
struct process_query_param {
	uint16_t   proc_flags;
	server_t   *server;
	int        socket;
	const struct sockaddr_storage *remote;
	unsigned   thread_id;
};

/*! \brief Query processing intermediate data. */
struct query_data {
	uint16_t rcode;       /*!< Resulting RCODE (Whole extended RCODE). */
	uint16_t rcode_tsig;  /*!< Resulting TSIG RCODE. */
	uint16_t packet_type; /*!< Resolved packet type. */
	knot_pkt_t *query;    /*!< Query to be solved. */
	const zone_t *zone;   /*!< Zone from which is answered. */
	list_t wildcards;     /*!< Visited wildcards. */
	list_t rrsigs;        /*!< Section RRSIGs. */

	/* Current processed name and nodes. */
	const zone_node_t *node, *encloser, *previous;
	const knot_dname_t *name;

	/* Original QNAME case. */
	uint8_t orig_qname[KNOT_DNAME_MAXLEN];

	/* EDNS */
	knot_rrset_t opt_rr;
	uint8_t *opt_rr_pos;  /*!< Place of the OPT RR in wire. */

	/* Extensions. */
	void *ext;
	void (*ext_cleanup)(struct query_data*); /*!< Extensions cleanup callback. */
	knot_sign_context_t sign;            /*!< Signing context. */

	/* Everything below should be kept on reset. */
	struct process_query_param *param; /*!< Module parameters. */
	knot_mm_t *mm;                     /*!< Memory context. */
};

/*! \brief Visited wildcard node list. */
struct wildcard_hit {
	node_t n;
	const zone_node_t *node;   /* Visited node. */
	const knot_dname_t *sname; /* Name leading to this node. */
};

/*! \brief RRSIG info node list. */
struct rrsig_info {
	node_t n;
	knot_rrset_t synth_rrsig;  /* Synthesized RRSIG. */
	knot_rrinfo_t *rrinfo;      /* RR info. */
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
                             acl_action_t action, struct query_data *qdata);

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
int process_query_verify(struct query_data *qdata);

/*!
 * \brief Sign current query using configured TSIG keys.
 *
 * \param pkt    Outgoing message.
 * \param qdata  Query data.
 *
 * \retval KNOT_E*
 */
int process_query_sign_response(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Restore QNAME letter case.
 *
 * \param qdata  Query data.
 * \param pkt    Incoming message.
 */
void process_query_qname_case_restore(struct query_data *qdata, knot_pkt_t *pkt);

/*!
 * \brief Convert QNAME to lowercase format for processing.
 *
 * \param pkt    Incoming message.
 */
int process_query_qname_case_lower(knot_pkt_t *pkt);

/*! @} */
