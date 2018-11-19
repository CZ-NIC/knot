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

#include "libknot/packet/pkt.h"
#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"

/*!
 * \brief Answer query from an IN class zone.
 *
 * \retval KNOT_STATE_FAIL if it encountered an error.
 * \retval KNOT_STATE_DONE if finished.
 */
int internet_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata);

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
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require existing zone contents or return failure. */
#define NS_NEED_ZONE_CONTENTS(qdata, error_rcode) \
	if ((qdata)->extra->zone->contents == NULL) { \
		qdata->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require authentication. */
#define NS_NEED_AUTH(qdata, action) \
	if (!process_query_acl_check(conf(), (action), (qdata)) || \
	    process_query_verify(qdata) != KNOT_EOK) { \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require maximum number of unsigned messages. */
#define NS_NEED_TSIG_SIGNED(tsig_ctx, max_unsigned) \
	if (tsig_unsigned_count(tsig_ctx) > max_unsigned) { \
		return KNOT_STATE_FAIL; \
	}

/*! \brief Require the zone not to be frozen. */
#define NS_NEED_NOT_FROZEN(qdata, error_rcode) \
	if ((qdata)->extra->zone->events.ufrozen) { \
		(qdata)->rcode = (error_rcode); \
		return KNOT_STATE_FAIL; \
	}
