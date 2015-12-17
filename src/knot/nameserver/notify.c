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

#include <assert.h>

#include "knot/nameserver/notify.h"

#include "libknot/dname.h"
#include "libknot/descriptor.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/consts.h"
#include "knot/zone/zonedb.h"
#include "knot/zone/timers.h"
#include "libknot/packet/wire.h"
#include "knot/updates/acl.h"
#include "knot/common/evsched.h"
#include "knot/common/log.h"
#include "knot/server/server.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "dnssec/random.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/nameserver/process_answer.h"
#include "libknot/rrtype/soa.h"
#include "contrib/sockaddr.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

/* NOTIFY-specific logging (internal, expects 'qdata' variable set). */
#define NOTIFY_QLOG(severity, msg, ...) \
	QUERY_LOG(severity, qdata, "NOTIFY, incoming", msg, ##__VA_ARGS__)

static int notify_check_query(struct query_data *qdata)
{
	/* RFC1996 requires SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone, transaction security. */
	zone_t *zone = (zone_t *)qdata->zone;
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(qdata, zone->name, ACL_ACTION_NOTIFY);

	return KNOT_STATE_DONE;
}

int notify_process_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Validate notification query. */
	int state = notify_check_query(qdata);
	if (state == KNOT_STATE_FAIL) {
		switch (qdata->rcode) {
		case KNOT_RCODE_NOTAUTH: /* Not authoritative or ACL check failed. */
			NOTIFY_QLOG(LOG_NOTICE, "unauthorized request");
			break;
		case KNOT_RCODE_FORMERR: /* Silently ignore bad queries. */
		default:
			break;
		}
		return state;
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, knot_tsig_wire_maxsize(&qdata->sign.tsig_key));

	/* SOA RR in answer may be included, recover serial. */
	const knot_pktsection_t *answer = knot_pkt_section(qdata->query, KNOT_ANSWER);
	if (answer->count > 0) {
		const knot_rrset_t *soa = knot_pkt_rr(answer, 0);
		if (soa->type == KNOT_RRTYPE_SOA) {
			uint32_t serial = knot_soa_serial(&soa->rrs);
			NOTIFY_QLOG(LOG_INFO, "received serial %u", serial);
		} else { /* Complain, but accept N/A record. */
			NOTIFY_QLOG(LOG_NOTICE, "received, bad record in answer section");
		}
	} else {
		NOTIFY_QLOG(LOG_INFO, "received, doesn't have SOA");
	}

	/* Incoming NOTIFY expires REFRESH timer and renews EXPIRE timer. */
	zone_t *zone = (zone_t *)qdata->zone;
	zone_set_preferred_master(zone, qdata->param->remote);
	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);

	return KNOT_STATE_DONE;
}

#undef NOTIFY_QLOG

/* NOTIFY-specific logging (internal, expects 'adata' variable set). */
#define NOTIFY_RLOG(severity, msg, ...) \
	ANSWER_LOG(severity, adata, "NOTIFY, outgoing", msg, ##__VA_ARGS__)

int notify_process_answer(knot_pkt_t *pkt, struct answer_data *adata)
{
	if (pkt == NULL || adata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check RCODE. */
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			NOTIFY_RLOG(LOG_WARNING, "server responded with %s", lut->name);
		}
		return KNOT_STATE_FAIL;
	}

	NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);

	return KNOT_STATE_DONE; /* No processing. */
}

#undef NOTIFY_RLOG
