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

#include <config.h>
#include <assert.h>

#include "knot/server/notify.h"

#include "libknot/dname.h"
#include "common/descriptor.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/consts.h"
#include "libknot/zone/zonedb.h"
#include "libknot/common.h"
#include "libknot/packet/wire.h"
#include "knot/server/zones.h"
#include "common/acl.h"
#include "common/evsched.h"
#include "knot/other/debug.h"
#include "knot/server/server.h"
#include "libknot/rdata.h"
#include "libknot/nameserver/internet.h"
#include "libknot/util/debug.h"
#include "libknot/nameserver/ns_proc_query.h"


/* Messages. */
#define NOTIFY_MSG "NOTIFY of '%s' from %s: "
#define NOTIFY_XMSG "received serial %u."

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int notify_request(const knot_rrset_t *rrset,
                          uint8_t *buffer, size_t *size)
{
	knot_pkt_t *pkt = knot_pkt_new(buffer, *size, NULL);
	CHECK_ALLOC_LOG(pkt, KNOT_ENOMEM);

	knot_pkt_clear(pkt);
	knot_wire_set_id(pkt->wire, knot_random_id());
	knot_wire_set_aa(pkt->wire);
	knot_wire_set_opcode(pkt->wire, KNOT_OPCODE_NOTIFY);

	int ret = knot_pkt_put_question(pkt, rrset->owner, rrset->rclass, rrset->type);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&pkt);
		return KNOT_ERROR;
	}

	/* Write back size, #10 crappy API. */
	*size = pkt->size;

	knot_pkt_free(&pkt);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int notify_create_request(const knot_zone_contents_t *zone, uint8_t *buffer,
                          size_t *size)
{
	const knot_rrset_t *soa_rrset = knot_node_rrset(
		            knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		return KNOT_ERROR;
	}

	return notify_request(soa_rrset, buffer, size);
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

static int notify_reschedule(knot_nameserver_t *ns,
			     const knot_zone_t *zone,
			     sockaddr_t *from)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, ns, zone, from);
	if (ns == NULL || zone == NULL || zone->data == NULL) {
		return KNOT_EINVAL;
	}

	/* Check ACL for notify-in. */
	zonedata_t *zone_data = (zonedata_t *)knot_zone_data(zone);
	if (from) {
		if (acl_find(zone_data->notify_in, from) == NULL) {
			return KNOT_EDENIED;
		}
	} else {
		dbg_ns("%s: no zone data/address, can't do ACL check\n", __func__);
	}

	/* Cancel REFRESH/RETRY timer. */
	server_t *server = ns->data;
	event_t *refresh_ev = zone_data->xfr_in.timer;
	if (refresh_ev && server) {
		dbg_ns("%s: expiring REFRESH timer\n", __func__);
		evsched_cancel(server->sched, refresh_ev);
		evsched_schedule(server->sched, refresh_ev, 0);
	} else {
		dbg_ns("%s: no REFRESH timer to expire\n", __func__);
	}

	return KNOT_EOK;
}

int internet_notify(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);
	/*! \note NOTIFY/RFC1996 isn't clear on error RCODEs.
	 *        Most servers use NOTAUTH from RFC2136. */
	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* SOA RR in answer may be included, recover serial. */
	unsigned serial = 0;
	const knot_pktsection_t *answer = knot_pkt_section(qdata->pkt, KNOT_ANSWER);
	if (answer->count > 0) {
		const knot_rrset_t *soa = answer->rr[0];
		if (knot_rrset_type(soa) == KNOT_RRTYPE_SOA) {
			serial = knot_rdata_soa_serial(soa);
			dbg_ns("%s: received serial %u\n", __func__, serial);
		} else { /* Ignore */
			dbg_ns("%s: NOTIFY answer != SOA_RR\n", __func__);
		}
	}

	int next_state = NS_PROC_FAIL;
	int ret = notify_reschedule(ns, qdata->zone, NULL /*! \todo API */);

	/* Format resulting log message. */
	char *qname_str = knot_dname_to_str(knot_pkt_qname(pkt));
	char *addr_str = strdup("(noaddr)"); /* xfr_remote_str(from, NULL); */ /*! \todo API */
	if (ret != KNOT_EOK) {
		next_state = NS_PROC_NOOP; /* RFC1996: Ignore. */
		log_server_warning(NOTIFY_MSG "%s\n", qname_str, addr_str, knot_strerror(ret));
	} else {
		next_state = NS_PROC_FINISH;
		log_server_info(NOTIFY_MSG NOTIFY_XMSG "\n", qname_str, addr_str, serial);
	}
	free(qname_str);
	free(addr_str);

	return next_state;
}
