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
#include "common/descriptor.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/consts.h"
#include "knot/zone/zonedb.h"
#include "libknot/common.h"
#include "libknot/packet/wire.h"
#include "knot/updates/acl.h"
#include "common/evsched.h"
#include "knot/other/debug.h"
#include "knot/server/server.h"
#include "knot/nameserver/internet.h"
#include "common/debug.h"
#include "knot/nameserver/process_query.h"
#include "libknot/dnssec/random.h"
#include "libknot/rdata/soa.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int notify_create_request(const zone_t *zone, knot_pkt_t *pkt)
{
	if (zone == NULL || pkt == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *contents = zone->contents;
	if (contents == NULL) {
		return KNOT_EINVAL; /* Not valid for stub zones. */
	}

	knot_wire_set_aa(pkt->wire);
	knot_wire_set_opcode(pkt->wire, KNOT_OPCODE_NOTIFY);

	knot_dname_t *apex = contents->apex->owner;
	return knot_pkt_put_question(pkt, apex, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
}

int notify_process_response(knot_pkt_t *notify, int msgid)
{
	if (!notify) {
		return KNOT_EINVAL;
	}

	/* Match ID against awaited. */
	if (knot_wire_get_id(notify->wire) != msgid) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/* NOTIFY-specific logging (internal, expects 'qdata' variable set). */
#define NOTIFY_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "NOTIFY", msg)

int internet_notify(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/* Check valid zone, transaction security. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(qdata->zone->notify_in, qdata);

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* SOA RR in answer may be included, recover serial. */
	unsigned serial = 0;
	const knot_pktsection_t *answer = knot_pkt_section(qdata->query, KNOT_ANSWER);
	if (answer->count > 0) {
		const knot_rrset_t *soa = &answer->rr[0];
		if (soa->type == KNOT_RRTYPE_SOA) {
			serial = knot_soa_serial(&soa->rrs);
			dbg_ns("%s: received serial %u\n", __func__, serial);
		} else { /* Ignore */
			dbg_ns("%s: NOTIFY answer != SOA_RR\n", __func__);
		}
	}

	int next_state = NS_PROC_FAIL;

	/* Incoming NOTIFY expires REFRESH timer and renews EXPIRE timer. */
	int ret =  zones_schedule_refresh((zone_t *)qdata->zone, ZONE_EVENT_NOW);

	/* Format resulting log message. */
	if (ret != KNOT_EOK) {
		next_state = NS_PROC_NOOP; /* RFC1996: Ignore. */
		NOTIFY_LOG(LOG_ERR, "%s", knot_strerror(ret));
	} else {
		next_state = NS_PROC_DONE;
		NOTIFY_LOG(LOG_INFO, "received serial %u.", serial);
	}

	return next_state;
}
