/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "knot/nameserver/notify.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/log.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/zone/serial.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"

#define NOTIFY_IN_LOG(priority, qdata, fmt...) \
	ns_log(priority, knot_pkt_qname(qdata->query), LOG_OPERATION_NOTIFY, \
	       LOG_DIRECTION_IN, qdata->params->remote, fmt)

static int notify_check_query(knotd_qdata_t *qdata)
{
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(qdata, ACL_ACTION_NOTIFY);
	/* RFC1996 requires SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	return KNOT_STATE_DONE;
}

int notify_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Validate notification query. */
	int state = notify_check_query(qdata);
	if (state == KNOT_STATE_FAIL) {
		switch (qdata->rcode) {
		case KNOT_RCODE_NOTAUTH: /* Not authorized, already logged. */
			break;
		default:                 /* Other errors. */
			NOTIFY_IN_LOG(LOG_DEBUG, qdata, "invalid query");
			break;
		}
		return state;
	}

	/* Reserve space for TSIG. */
	int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* SOA RR in answer may be included, recover serial. */
	zone_t *zone = (zone_t *)qdata->extra->zone;
	const knot_pktsection_t *answer = knot_pkt_section(qdata->query, KNOT_ANSWER);
	if (answer->count > 0) {
		const knot_rrset_t *soa = knot_pkt_rr(answer, 0);
		if (soa->type == KNOT_RRTYPE_SOA) {
			uint32_t zone_serial, serial = knot_soa_serial(soa->rrs.rdata);
			(void)slave_zone_serial(zone, conf(), &zone_serial);
			NOTIFY_IN_LOG(LOG_INFO, qdata, "serial %u", serial);
			if (serial_equal(serial, zone_serial)) {
				// NOTIFY serial == zone serial => ignore, keep timers
				return KNOT_STATE_DONE;
			}
		} else { /* Complain, but accept N/A record. */
			NOTIFY_IN_LOG(LOG_NOTICE, qdata, "bad record in answer section");
		}
	} else {
		NOTIFY_IN_LOG(LOG_INFO, qdata, "serial none");
	}

	/* Incoming NOTIFY expires REFRESH timer and renews EXPIRE timer. */
	zone_set_preferred_master(zone, qdata->params->remote);
	zone_events_schedule_now(zone, ZONE_EVENT_REFRESH);

	return KNOT_STATE_DONE;
}
