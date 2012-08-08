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

#include "knot/server/notify.h"

#include "libknot/dname.h"
#include "libknot/packet/packet.h"
#include "libknot/rrset.h"
#include "libknot/packet/response.h"
#include "libknot/packet/query.h"
#include "libknot/consts.h"
#include "knot/other/error.h"
#include "libknot/zone/zonedb.h"
#include "libknot/common.h"
#include "libknot/util/error.h"
#include "libknot/util/wire.h"
#include "knot/server/zones.h"
#include "common/acl.h"
#include "common/evsched.h"
#include "knot/other/debug.h"
#include "knot/server/server.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int notify_request(const knot_rrset_t *rrset,
                          uint8_t *buffer, size_t *size)
{
	knot_packet_t *pkt = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(pkt, KNOTD_ENOMEM);

	/*! \todo Get rid of the numeric constant. */
	int rc = knot_packet_set_max_size(pkt, 512);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	rc = knot_query_init(pkt);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	knot_question_t question;

	// this is ugly!!
	question.qname = rrset->owner;
	question.qtype = rrset->type;
	question.qclass = rrset->rclass;

	rc = knot_query_set_question(pkt, &question);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	/* Set random query ID. */
	knot_packet_set_random_id(pkt);
	knot_wire_set_id(pkt->wireformat, pkt->header.id);

	/*! \todo add the SOA RR to the Answer section as a hint */
	/*! \todo this should not use response API!! */
//	rc = knot_response_add_rrset_answer(pkt, rrset, 0, 0, 0);
//	if (rc != KNOT_EOK) {
//		knot_packet_free(&pkt);
//		return rc;
//	}

	/*! \todo this should not use response API!! */
	knot_response_set_aa(pkt);

	knot_query_set_opcode(pkt, KNOT_OPCODE_NOTIFY);

	/*! \todo OPT RR ?? */

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = knot_packet_to_wire(pkt, &wire, &wire_size);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	if (wire_size > *size) {
		knot_packet_free(&pkt);
		return KNOTD_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	knot_packet_dump(pkt);

	knot_packet_free(&pkt);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_create_response(knot_packet_t *request, uint8_t *buffer,
                           size_t *size)
{
	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(response, KNOTD_ENOMEM);

	/* Set maximum packet size. */
	int rc = knot_packet_set_max_size(response, *size);
	if (rc == KNOT_EOK) {
		rc = knot_response_init_from_query(response, request);
	}
	
	/* Aggregated result check. */
	if (rc != KNOT_EOK) {
		dbg_notify("%s: failed to init response packet: %s",
			   "notify_create_response", knot_strerror(rc));
		knot_packet_free(&response);
		return KNOTD_EINVAL;
	}

	// TODO: copy the SOA in Answer section
	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = knot_packet_to_wire(response, &wire, &wire_size);
	if (rc != KNOT_EOK) {
		knot_packet_free(&response);
		return rc;
	}

	if (wire_size > *size) {
		knot_packet_free(&response);
		return KNOTD_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	knot_packet_dump(response);
	knot_packet_free(&response);

	return KNOTD_EOK;
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
		return KNOTD_ERROR;
	}

	return notify_request(soa_rrset, buffer, size);
}

/*----------------------------------------------------------------------------*/

static int notify_check_and_schedule(knot_nameserver_t *nameserver,
                                     const knot_zone_t *zone,
                                     sockaddr_t *from)
{
	if (zone == NULL || from == NULL || knot_zone_data(zone) == NULL) {
		return KNOTD_EINVAL;
	}
	
	/* Check ACL for notify-in. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (from) {
		if (acl_match(zd->notify_in, from, 0) == ACL_DENY) {
			/* rfc1996: Ignore request and report incident. */
			char straddr[SOCKADDR_STRLEN];
			sockaddr_tostr(from, straddr, sizeof(straddr));
			log_zone_notice("Unauthorized NOTIFY query "
			                "from '%s@%d' to zone '%s'.\n",
			                straddr, sockaddr_portnum(from),
			                zd->conf->name);
			return KNOT_ERROR;
		} else {
			dbg_notify("notify: authorized NOTIFY query.\n");
		}
	}

	/*! \todo Packet may contain updated RRs. */

	/* Cancel REFRESH/RETRY timer. */
	evsched_t *sched = ((server_t *)knot_ns_get_data(nameserver))->sched;
	event_t *refresh_ev = zd->xfr_in.timer;
	if (refresh_ev) {
		dbg_notify("notify: expiring REFRESH timer\n");
		evsched_cancel(sched, refresh_ev);

		/* Set REFRESH timer for now. */
		evsched_schedule(sched, refresh_ev, 0);
	}
	
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_request(knot_nameserver_t *ns,
                           knot_packet_t *notify,
                           sockaddr_t *from,
                           uint8_t *buffer, size_t *size)
{
	/*! \todo Most of this function is identical to xfrin_transfer_needed()
	 *        - it will be fine to merge the code somehow.
	 */

	if (notify == NULL || ns == NULL || buffer == NULL
	    || size == NULL || from == NULL) {
		dbg_notify("notify: invalid parameters for %s()\n",
		           "notify_process_request");
		return KNOTD_EINVAL;
	}

	int ret = KNOTD_EOK;

	dbg_notify("notify: parsing rest of the packet\n");
	if (notify->parsed < notify->size) {
		if (knot_packet_parse_rest(notify) != KNOT_EOK) {
			dbg_notify("notify: failed to parse NOTIFY query\n");
			knot_ns_error_response_from_query(ns, notify,
			                                  KNOT_RCODE_FORMERR,
			                                  buffer, size);
			return KNOTD_EOK;
		}
	}

	// check if it makes sense - if the QTYPE is SOA
	if (knot_packet_qtype(notify) != KNOT_RRTYPE_SOA) {
		// send back FORMERR
		knot_ns_error_response_from_query(ns, notify,
		                                  KNOT_RCODE_FORMERR, buffer,
		                                  size);
		return KNOTD_EOK;
	}

	// create NOTIFY response
	dbg_notify("notify: creating response\n");
	ret = notify_create_response(notify, buffer, size);
	if (ret != KNOTD_EOK) {
		dbg_notify("notify: failed to create NOTIFY response\n");
		knot_ns_error_response_from_query(ns, notify,
		                                  KNOT_RCODE_SERVFAIL, buffer,
		                                  size);
		return KNOTD_EOK;
	}

	// find the zone
	rcu_read_lock();
	const knot_dname_t *qname = knot_packet_qname(notify);
	const knot_zone_t *z = knot_zonedb_find_zone_for_name(
			ns->zone_db, qname);
	if (z == NULL) {
		rcu_read_unlock();
		dbg_notify("notify: failed to find zone by name\n");
		knot_ns_error_response_from_query(ns, notify,
		                                  KNOT_RCODE_FORMERR, buffer,
		                                  size);
		return KNOTD_EOK;
	}

	notify_check_and_schedule(ns, z, from);
	rcu_read_unlock();
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_response(knot_nameserver_t *nameserver,
                            knot_packet_t *notify,
                            sockaddr_t *from,
                            uint8_t *buffer, size_t *size)
{
	if (nameserver == NULL || notify == NULL || from == NULL 
	    || buffer == NULL || size == NULL) {
		return KNOTD_EINVAL;
	}

	/* Assert no response size. */
	*size = 0;

	/* Find matching zone. */
	rcu_read_lock();
	const knot_dname_t *zone_name = knot_packet_qname(notify);
	knot_zone_t *zone = knot_zonedb_find_zone(nameserver->zone_db,
	                                              zone_name);
	if (!zone) {
		rcu_read_unlock();
		return KNOTD_ENOENT;
	}
	if (!knot_zone_data(zone)) {
		rcu_read_unlock();
		return KNOTD_ENOENT;
	}

	/* Match ID against awaited. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	pthread_mutex_lock(&zd->lock);
	uint16_t pkt_id = knot_packet_id(notify);
	notify_ev_t *ev = 0, *match = 0;
	WALK_LIST(ev, zd->notify_pending) {
		if ((int)pkt_id == ev->msgid) {
			match = ev;
			break;
		}
	}

	/* Found waiting NOTIFY query? */
	if (!match) {
		rcu_read_unlock();
		pthread_mutex_unlock(&zd->lock);
		return KNOTD_ERROR;
	}

	/* NOTIFY is now finished. */
	zones_cancel_notify(zd, match);

	/* Zone was removed/reloaded. */
	pthread_mutex_unlock(&zd->lock);
	
	rcu_read_unlock();

	return KNOTD_EOK;
}

