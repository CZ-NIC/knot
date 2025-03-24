/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"

/*! \brief Don't follow CNAME/DNAME chain beyond this depth. */
#define CNAME_CHAIN_MAX 5

/*!
 * \brief Answer query from an IN class zone.
 */
knot_layer_state_t internet_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata);

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
	if ((qdata)->extra->zone == NULL) { \
		qdata->rcode = (error_rcode); \
		if ((error_rcode) == KNOT_RCODE_REFUSED) { \
			qdata->rcode_ede = KNOT_EDNS_EDE_NOTAUTH; \
		} \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require existing zone contents or return failure. */
#define NS_NEED_ZONE_CONTENTS(qdata) \
	if ((qdata)->extra->contents == NULL) { \
		qdata->rcode = KNOT_RCODE_SERVFAIL; \
		qdata->rcode_ede = KNOT_EDNS_EDE_INV_DATA; \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require authentication. */
#define NS_NEED_AUTH(qdata, action) \
	if (!process_query_acl_check(conf(), (action), (qdata)) || \
	    process_query_verify(qdata) != KNOT_EOK) { \
		qdata->params->flags &= ~KNOTD_QUERY_FLAG_AUTHORIZED; \
		return KNOT_STATE_FAIL; \
	} else { \
		qdata->params->flags |= KNOTD_QUERY_FLAG_AUTHORIZED; \
	}
